package loomcore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"loom/internal/wire"
)

const (
	androidDeviceReportKind          = "health"
	androidDeviceReportPayloadSchema = int64(1)
	maximumAndroidDeviceReportBytes  = 4 << 20
)

type androidDeviceReportDraftV1 struct {
	Schema         int                     `json:"schema"`
	Body           wire.DeviceReportBodyV2 `json:"body"`
	Payload        json.RawMessage         `json:"payload"`
	SigningMessage string                  `json:"signing_message"`
}

// PrepareAndroidV2DeviceReportDraft 从 protected LKG 取得 exact floors，并返回
// Android Keystore 必须签名的 framed message。Go 核心不接触 identity private key（D131）。
func PrepareAndroidV2DeviceReportDraft(stateJSON, identitySPKIDER []byte, reportID string,
	reportSequence int64, generatedAt string, payloadJSON []byte,
) ([]byte, error) {
	state, identityHash, _, err := androidDeviceReportContext(stateJSON, identitySPKIDER)
	if err != nil {
		return nil, err
	}
	if len(payloadJSON) == 0 || len(payloadJSON) > maximumAndroidDeviceReportBytes {
		return nil, errors.New("[D131 Android report] payload 为空或超限")
	}
	payload := json.RawMessage(append([]byte(nil), payloadJSON...))
	payloadHash, err := wire.DeviceReportPayloadHash(payload)
	if err != nil {
		return nil, err
	}
	if reportID == "" {
		reportID = androidDeviceReportID(reportSequence, payloadHash)
	}
	body := wire.DeviceReportBodyV2{
		Schema: 2, ClusterID: state.Envelope.Payload.ClusterID,
		DeviceID: state.Envelope.Payload.DeviceID, ReportID: reportID,
		ReportSequence: reportSequence, GeneratedAt: generatedAt,
		AcceptedFloors: state.Floors, Kind: androidDeviceReportKind,
		PayloadSchema: androidDeviceReportPayloadSchema, PayloadHash: payloadHash,
	}
	message, err := wire.DeviceReportMessage(&body, androidDeviceReportSchemas())
	if err != nil {
		return nil, err
	}
	if identityHash == "" {
		return nil, errors.New("[D131 Android report] identity binding 缺失")
	}
	return wire.MarshalCanonical(androidDeviceReportDraftV1{
		Schema: 1, Body: body, Payload: payload,
		SigningMessage: base64.RawURLEncoding.EncodeToString(message),
	})
}

// AssembleAndroidV2DeviceReport 重新计算 draft 的 payload hash、签名消息、当前 floors
// 与 Keystore identity binding，且只输出通过共享 verifier 的 canonical envelope（D131）。
func AssembleAndroidV2DeviceReport(stateJSON, identitySPKIDER, draftJSON, signatureDER []byte,
	trustedTime string,
) ([]byte, error) {
	state, identityHash, identity, err := androidDeviceReportContext(stateJSON, identitySPKIDER)
	if err != nil {
		return nil, err
	}
	instant, err := wire.ParseTimeZ(trustedTime)
	if err != nil {
		return nil, errors.New("[D131 Android report] trusted time 无效")
	}
	var draft androidDeviceReportDraftV1
	if err := decodeExactAndroidV2(draftJSON, maximumAndroidDeviceReportBytes, &draft, "Device report draft"); err != nil {
		return nil, err
	}
	message, err := verifyAndroidDeviceReportDraft(&draft, &state, identityHash)
	if err != nil {
		return nil, err
	}
	encodedMessage, err := base64.RawURLEncoding.DecodeString(draft.SigningMessage)
	if err != nil || base64.RawURLEncoding.EncodeToString(encodedMessage) != draft.SigningMessage ||
		!bytes.Equal(encodedMessage, message) {
		return nil, errors.New("[D131 Android report] draft signing message 不一致")
	}
	signature := base64.RawURLEncoding.EncodeToString(signatureDER)
	envelope := wire.DeviceReportEnvelopeV2{
		Schema: 2, Body: draft.Body, Payload: append(json.RawMessage(nil), draft.Payload...),
		Signature: wire.DeviceReportSignatureV1{
			Algorithm: "ecdsa-p256-sha256", IdentitySPKIHash: identityHash, Signature: signature,
		},
	}
	if err := wire.VerifyDeviceReport(&envelope, identity, state.Envelope.Payload.DeviceID,
		identityHash, instant, 24*time.Hour, 5*time.Minute, androidDeviceReportSchemas()); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(envelope)
}

// ValidateAndroidV2DeviceReport 验证 journal 中的 pending exact envelope 仍绑定当前
// identity、floors 和 reader contract。失败时不能以相同 sequence 另签新正文（D131）。
func ValidateAndroidV2DeviceReport(stateJSON, identitySPKIDER, envelopeJSON []byte,
	trustedTime string,
) error {
	state, identityHash, identity, err := androidDeviceReportContext(stateJSON, identitySPKIDER)
	if err != nil {
		return err
	}
	instant, err := wire.ParseTimeZ(trustedTime)
	if err != nil {
		return errors.New("[D131 Android report] trusted time 无效")
	}
	var envelope wire.DeviceReportEnvelopeV2
	if err := decodeExactAndroidV2(envelopeJSON, maximumAndroidDeviceReportBytes, &envelope,
		"pending Device report"); err != nil {
		return err
	}
	if !wire.EqualCanonical(envelope.Body.AcceptedFloors, state.Floors) {
		return errors.New("[D131 Android report] pending report floors 与当前 LKG 不一致")
	}
	return wire.VerifyDeviceReport(&envelope, identity, state.Envelope.Payload.DeviceID,
		identityHash, instant, 24*time.Hour, 5*time.Minute, androidDeviceReportSchemas())
}

func verifyAndroidDeviceReportDraft(draft *androidDeviceReportDraftV1, state *androidV2DeviceState,
	identityHash string,
) ([]byte, error) {
	if draft == nil || state == nil || draft.Schema != 1 ||
		draft.Body.ClusterID != state.Envelope.Payload.ClusterID ||
		draft.Body.DeviceID != state.Envelope.Payload.DeviceID ||
		!wire.EqualCanonical(draft.Body.AcceptedFloors, state.Floors) {
		return nil, errors.New("[D131 Android report] draft 与当前 Device/floors 不一致")
	}
	payloadHash, err := wire.DeviceReportPayloadHash(draft.Payload)
	if err != nil || payloadHash != draft.Body.PayloadHash || identityHash == "" {
		return nil, errors.New("[D131 Android report] draft payload/identity binding 无效")
	}
	return wire.DeviceReportMessage(&draft.Body, androidDeviceReportSchemas())
}

func androidDeviceReportContext(stateJSON, identitySPKIDER []byte) (androidV2DeviceState,
	string, *ecdsa.PublicKey, error,
) {
	state, err := decodeAndroidV2DeviceState(stateJSON)
	if err != nil {
		return androidV2DeviceState{}, "", nil, err
	}
	if state.Enrollment == nil || state.Envelope.Payload.State != "active" ||
		state.Envelope.Payload.Active == nil {
		return androidV2DeviceState{}, "", nil,
			errors.New("[D131 Android report] active Device/Enrollment 不完整")
	}
	parsed, err := x509.ParsePKIXPublicKey(identitySPKIDER)
	identity, ok := parsed.(*ecdsa.PublicKey)
	identityHash, hashErr := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, identitySPKIDER)
	if err != nil || !ok || identity.Curve != elliptic.P256() || hashErr != nil ||
		identityHash != state.Enrollment.IdentityKeyHash ||
		identityHash != state.Envelope.Payload.Active.IdentitySPKIHash {
		return androidV2DeviceState{}, "", nil,
			errors.New("[D131 Android report] Keystore identity 与 protected Device 不一致")
	}
	return state, identityHash, identity, nil
}

func androidDeviceReportSchemas() wire.DeviceReportSchemaRegistry {
	return wire.DeviceReportSchemaRegistry{androidDeviceReportKind: androidDeviceReportPayloadSchema}
}

func androidDeviceReportID(sequence int64, payloadHash string) string {
	digest := payloadHash
	if len(digest) > len("sha256:") && digest[:len("sha256:")] == "sha256:" {
		digest = digest[len("sha256:"):]
	}
	if len(digest) > 16 {
		digest = digest[:16]
	}
	return fmt.Sprintf("android-%020d-%s", sequence, digest)
}
