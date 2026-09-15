package wire

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"time"
)

const (
	DomainDeviceReportPayload   = "loom-device-report-payload-v2"
	DomainDeviceReportSignature = "loom-device-report-signature-v2"
)

type DeviceReportBodyV2 struct {
	Schema         int            `json:"schema"`
	ClusterID      string         `json:"cluster_id"`
	DeviceID       string         `json:"device_id"`
	ReportID       string         `json:"report_id"`
	ReportSequence int64          `json:"report_sequence"`
	GeneratedAt    string         `json:"generated_at"`
	AcceptedFloors ClientFloorsV2 `json:"accepted_floors"`
	Kind           string         `json:"kind"`
	PayloadSchema  int64          `json:"payload_schema"`
	PayloadHash    string         `json:"payload_hash"`
}

type DeviceReportSignatureV1 struct {
	Algorithm        string `json:"algorithm"`
	IdentitySPKIHash string `json:"identity_spki_hash"`
	Signature        string `json:"signature"`
}

type DeviceReportEnvelopeV2 struct {
	Schema    int                     `json:"schema"`
	Body      DeviceReportBodyV2      `json:"body"`
	Payload   json.RawMessage         `json:"payload"`
	Signature DeviceReportSignatureV1 `json:"signature"`
}

type DeviceReportSchemaRegistry map[string]int64

func DeviceReportPayloadHash(payload json.RawMessage) (string, error) {
	canonical, err := CanonicalizeStrict(payload)
	if err != nil || !bytes.Equal(canonical, payload) || len(payload) < 2 || payload[0] != '{' {
		return "", errors.New("[device_report] payload 必须是 exact canonical JSON object")
	}
	return HashCanonical(DomainDeviceReportPayload, payload)
}

func ValidateDeviceReportBody(body *DeviceReportBodyV2, schemas DeviceReportSchemaRegistry) error {
	if body == nil || body.Schema != 2 || !validIdentifier(body.ClusterID, 128) ||
		!validIdentifier(body.DeviceID, 128) || !validIdentifier(body.ReportID, 128) ||
		body.ReportSequence < 1 || !validIdentifier(body.Kind, 128) || body.PayloadSchema < 1 {
		return errors.New("[device_report] report body identity/sequence/schema 无效")
	}
	expectedSchema, found := schemas[body.Kind]
	if !found || expectedSchema != body.PayloadSchema {
		return errors.New("[device_report] report kind/schema 未获 reader contract 授权")
	}
	if _, err := ParseTimeZ(body.GeneratedAt); err != nil {
		return err
	}
	if err := validateClientFloors(body.AcceptedFloors); err != nil || body.AcceptedFloors.ClusterID != body.ClusterID {
		return errors.New("[device_report] report floors 无效或 cluster 不一致")
	}
	if _, err := ParseHash(body.PayloadHash); err != nil {
		return err
	}
	return nil
}

func DeviceReportMessage(body *DeviceReportBodyV2, schemas DeviceReportSchemaRegistry) ([]byte, error) {
	if err := ValidateDeviceReportBody(body, schemas); err != nil {
		return nil, err
	}
	canonical, err := MarshalCanonical(body)
	if err != nil {
		return nil, err
	}
	return Frame(DomainDeviceReportSignature, canonical)
}

func SignDeviceReport(body DeviceReportBodyV2, payload json.RawMessage, privateKey *ecdsa.PrivateKey,
	schemas DeviceReportSchemaRegistry) (DeviceReportEnvelopeV2, error) {
	if privateKey == nil || privateKey.Curve != elliptic.P256() {
		return DeviceReportEnvelopeV2{}, errors.New("[device_report] identity private key 必须是 P-256")
	}
	return SignDeviceReportWithSigner(body, payload, privateKey, schemas)
}

// SignDeviceReportWithSigner 与 Enrollment PoP 共用平台 signer 边界；共享 wire
// 只接收 public key 与签名回调，不要求 Windows 宿主导出 identity private key。
func SignDeviceReportWithSigner(body DeviceReportBodyV2, payload json.RawMessage, signer crypto.Signer,
	schemas DeviceReportSchemaRegistry) (DeviceReportEnvelopeV2, error) {
	publicKey, ok := signerPublicP256(signer)
	if !ok {
		return DeviceReportEnvelopeV2{}, errors.New("[device_report] identity signer 必须是 P-256")
	}
	payloadHash, err := DeviceReportPayloadHash(payload)
	if err != nil {
		return DeviceReportEnvelopeV2{}, err
	}
	if body.PayloadHash != payloadHash {
		return DeviceReportEnvelopeV2{}, errors.New("[device_report] report body 未绑定 exact payload")
	}
	message, err := DeviceReportMessage(&body, schemas)
	if err != nil {
		return DeviceReportEnvelopeV2{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return DeviceReportEnvelopeV2{}, err
	}
	identityHash, _ := HashBytes(DomainEnrollmentIdentitySPKI, spki)
	signature, err := signP256LowSWithSigner(message, signer, publicKey)
	if err != nil {
		return DeviceReportEnvelopeV2{}, err
	}
	return DeviceReportEnvelopeV2{Schema: 2, Body: body, Payload: append(json.RawMessage(nil), payload...),
		Signature: DeviceReportSignatureV1{Algorithm: "ecdsa-p256-sha256", IdentitySPKIHash: identityHash, Signature: signature}}, nil
}

func signP256LowSWithSigner(message []byte, signer crypto.Signer, publicKey *ecdsa.PublicKey) (string, error) {
	digest := sha256.Sum256(message)
	raw, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	var signature struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(raw, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil ||
		signature.R.Sign() <= 0 || signature.S.Sign() <= 0 {
		return "", errors.New("[device_report] 平台 signer 返回的 ECDSA DER 无效")
	}
	canonical, err := asn1.Marshal(signature)
	if err != nil || !bytes.Equal(canonical, raw) {
		return "", errors.New("[device_report] 平台 signer 返回的 ECDSA DER 非规范")
	}
	s := new(big.Int).Set(signature.S)
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(publicKey.Params().N), 1)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(publicKey.Params().N, s)
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{R: signature.R, S: s})
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(der)
	if err := verifyP256LowS(message, publicKey, encoded); err != nil {
		return "", err
	}
	return encoded, nil
}

func VerifyDeviceReport(envelope *DeviceReportEnvelopeV2, identityPublicKey *ecdsa.PublicKey,
	expectedDeviceID, expectedIdentitySPKIHash string, trustedTime time.Time, maximumAge, maximumClockSkew time.Duration,
	schemas DeviceReportSchemaRegistry) error {
	if envelope == nil || envelope.Schema != 2 || identityPublicKey == nil || identityPublicKey.Curve != elliptic.P256() ||
		trustedTime.IsZero() || maximumAge < 0 || maximumClockSkew < 0 || maximumClockSkew > 5*time.Minute {
		return errors.New("[device_report] verification context 无效")
	}
	if err := ValidateDeviceReportBody(&envelope.Body, schemas); err != nil {
		return err
	}
	payloadHash, err := DeviceReportPayloadHash(envelope.Payload)
	if err != nil || payloadHash != envelope.Body.PayloadHash {
		return errors.New("[device_report] payload hash 不匹配")
	}
	if envelope.Body.DeviceID != expectedDeviceID || envelope.Signature.Algorithm != "ecdsa-p256-sha256" ||
		envelope.Signature.IdentitySPKIHash != expectedIdentitySPKIHash {
		return errors.New("[device_report] Device/signature identity binding 无效")
	}
	spki, err := x509.MarshalPKIXPublicKey(identityPublicKey)
	if err != nil {
		return err
	}
	identityHash, _ := HashBytes(DomainEnrollmentIdentitySPKI, spki)
	if identityHash != expectedIdentitySPKIHash {
		return errors.New("[device_report] report identity key 与 certificate SPKI 不一致")
	}
	generatedAt, _ := ParseTimeZ(envelope.Body.GeneratedAt)
	instant := trustedTime.UTC()
	if generatedAt.After(instant.Add(maximumClockSkew)) || generatedAt.Before(instant.Add(-maximumAge-maximumClockSkew)) {
		return errors.New("[device_report] report 超出 freshness/clock-skew window")
	}
	message, err := DeviceReportMessage(&envelope.Body, schemas)
	if err != nil {
		return err
	}
	return verifyP256LowS(message, identityPublicKey, envelope.Signature.Signature)
}

func signP256LowS(message []byte, privateKey *ecdsa.PrivateKey) (string, error) {
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return "", err
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(privateKey.Params().N), 1)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(privateKey.Params().N, s)
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(der), nil
}

func verifyP256LowS(message []byte, publicKey *ecdsa.PublicKey, encoded string) error {
	if publicKey == nil || publicKey.Curve != elliptic.P256() || !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return errors.New("[device_report] identity public key 不是 P-256")
	}
	raw, err := decodeCanonicalBase64URL(encoded)
	if err != nil {
		return errors.New("[device_report] signature 编码无效")
	}
	var signature struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(raw, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil ||
		signature.R.Sign() <= 0 || signature.S.Sign() <= 0 {
		return errors.New("[device_report] ECDSA signature DER 无效")
	}
	canonical, err := asn1.Marshal(signature)
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(publicKey.Params().N), 1)
	if err != nil || !bytes.Equal(canonical, raw) || signature.S.Cmp(halfOrder) > 0 {
		return errors.New("[device_report] ECDSA signature 必须是 canonical DER low-S")
	}
	digest := sha256.Sum256(message)
	if !ecdsa.Verify(publicKey, digest[:], signature.R, signature.S) {
		return errors.New("[device_report] Device identity signature 无效")
	}
	return nil
}
