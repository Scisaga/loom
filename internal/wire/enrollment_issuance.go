package wire

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"sort"
)

const (
	DomainEnrollmentProvisionalIssuanceBody      = "loom-enrollment-provisional-issuance-body-v1"
	DomainEnrollmentProvisionalIssuanceEnvelope  = "loom-enrollment-provisional-issuance-envelope-v1"
	DomainEnrollmentProvisionalIssuanceSignature = "loom-enrollment-provisional-issuance-signature-v1"
	DomainEnrollmentIssuanceRegistryLeaf         = "loom-enrollment-issuance-registry-leaf-v1"
)

// EnrollmentProvisionalIssuanceBodyV1 只引用私有 result artifact 的稳定摘要；
// certificate、view 与 secret artifact 正文不得进入公开日志。
type EnrollmentProvisionalIssuanceBodyV1 struct {
	Schema                            int                     `json:"schema"`
	ClusterID                         string                  `json:"cluster_id"`
	InviteID                          string                  `json:"invite_id"`
	RequestID                         string                  `json:"request_id"`
	ClaimOperationHash                string                  `json:"claim_operation_hash"`
	ReservationHeadHash               string                  `json:"reservation_head_hash"`
	ReservationHeadQCHash             string                  `json:"reservation_head_qc_hash"`
	DeviceCertificateHash             string                  `json:"device_certificate_hash"`
	InitialDeviceViewHash             string                  `json:"initial_device_view_hash"`
	SecretArtifactRefsRoot            string                  `json:"secret_artifact_refs_root"`
	ResultArtifactHash                string                  `json:"result_artifact_hash"`
	DeviceCertificateProfileStateHash string                  `json:"device_certificate_profile_state_hash"`
	IssuanceLogCoordinate             IssuanceLogCoordinateV1 `json:"issuance_log_coordinate"`
}

type DeviceCAIssuanceSignatureV1 struct {
	Algorithm          string `json:"algorithm"`
	IssuerID           string `json:"issuer_id"`
	IssuerGeneration   int64  `json:"issuer_generation"`
	IssuerFencingEpoch int64  `json:"issuer_fencing_epoch"`
	Signature          string `json:"signature"`
}

type EnrollmentProvisionalIssuanceV1 struct {
	Body        EnrollmentProvisionalIssuanceBodyV1 `json:"body"`
	CASignature DeviceCAIssuanceSignatureV1         `json:"ca_signature"`
}

type EnrollmentIssuanceRegistryLeafV1 struct {
	Schema                  int    `json:"schema"`
	ClaimOperationHash      string `json:"claim_operation_hash"`
	ProvisionalIssuanceHash string `json:"provisional_issuance_hash"`
}

func ValidateEnrollmentProvisionalIssuanceBody(body *EnrollmentProvisionalIssuanceBodyV1) error {
	if body == nil || body.Schema != 1 || !validIdentifier(body.ClusterID, 128) ||
		!validIdentifier(body.InviteID, 128) || !validIdentifier(body.RequestID, 128) ||
		body.IssuanceLogCoordinate.RecoveryEpoch < 0 || body.IssuanceLogCoordinate.RaftIndex < 1 {
		return errors.New("[Enrollment] provisional issuance body identity/coordinate 无效")
	}
	for _, hash := range []string{body.ClaimOperationHash, body.ReservationHeadHash,
		body.ReservationHeadQCHash, body.DeviceCertificateHash, body.InitialDeviceViewHash,
		body.SecretArtifactRefsRoot, body.ResultArtifactHash, body.DeviceCertificateProfileStateHash} {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	return nil
}

func EnrollmentProvisionalIssuanceBodyHash(body *EnrollmentProvisionalIssuanceBodyV1) (string, error) {
	if err := ValidateEnrollmentProvisionalIssuanceBody(body); err != nil {
		return "", err
	}
	return HashObject(DomainEnrollmentProvisionalIssuanceBody, body)
}

// SignEnrollmentProvisionalIssuance 只允许 exact current active profile 的 online
// Ed25519 issuer key 签名；profile generation/fencing epoch 同时进入签名 envelope。
func SignEnrollmentProvisionalIssuance(body EnrollmentProvisionalIssuanceBodyV1,
	profile *DeviceCertificateProfileStateV1, privateKey crypto.Signer) (EnrollmentProvisionalIssuanceV1, error) {
	if err := validateEnrollmentIssuanceProfile(&body, profile); err != nil {
		return EnrollmentProvisionalIssuanceV1{}, err
	}
	if privateKey == nil {
		return EnrollmentProvisionalIssuanceV1{}, errors.New("[D102 Device CA] provisional issuance signer 缺失")
	}
	issuerDER, _ := decodeCanonicalBase64URL(profile.ProfileIntent.IssuerCertificateDER)
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil || issuer.PublicKeyAlgorithm != x509.Ed25519 ||
		!bytes.Equal(issuer.RawSubjectPublicKeyInfo, mustMarshalPKIX(privateKey.Public())) {
		return EnrollmentProvisionalIssuanceV1{}, errors.New("[Device CA] provisional issuance key 与 exact profile issuer 不匹配")
	}
	canonical, err := MarshalCanonical(body)
	if err != nil {
		return EnrollmentProvisionalIssuanceV1{}, err
	}
	message, _ := Frame(DomainEnrollmentProvisionalIssuanceSignature, canonical)
	// Non-exportable KMS/HSM handles implement Signer; never request raw CA key bytes.
	signature, err := privateKey.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return EnrollmentProvisionalIssuanceV1{}, err
	}
	publicKey, ok := issuer.PublicKey.(ed25519.PublicKey)
	if !ok || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, message, signature) {
		return EnrollmentProvisionalIssuanceV1{}, errors.New("[D102 Device CA] signer 未返回 exact Ed25519 signature")
	}
	intent := profile.ProfileIntent
	return EnrollmentProvisionalIssuanceV1{Body: body, CASignature: DeviceCAIssuanceSignatureV1{
		Algorithm: "ed25519", IssuerID: intent.IssuerID, IssuerGeneration: intent.IssuerGeneration,
		IssuerFencingEpoch: intent.IssuerFencingEpoch,
		Signature:          base64.RawURLEncoding.EncodeToString(signature),
	}}, nil
}

func VerifyEnrollmentProvisionalIssuance(issuance *EnrollmentProvisionalIssuanceV1,
	profile *DeviceCertificateProfileStateV1) error {
	if issuance == nil {
		return errors.New("[Enrollment] provisional issuance 不能为空")
	}
	if err := validateEnrollmentIssuanceProfile(&issuance.Body, profile); err != nil {
		return err
	}
	intent := profile.ProfileIntent
	signature := issuance.CASignature
	if signature.Algorithm != "ed25519" || signature.IssuerID != intent.IssuerID ||
		signature.IssuerGeneration != intent.IssuerGeneration ||
		signature.IssuerFencingEpoch != intent.IssuerFencingEpoch {
		return errors.New("[Device CA] provisional issuance signature purpose/fence 无效")
	}
	rawSignature, err := decodeRawURL(signature.Signature, ed25519.SignatureSize)
	if err != nil {
		return errors.New("[Device CA] provisional issuance signature 编码无效")
	}
	issuerDER, _ := decodeCanonicalBase64URL(intent.IssuerCertificateDER)
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return errors.New("[Device CA] provisional issuance issuer certificate 无效")
	}
	publicKey, ok := issuer.PublicKey.(ed25519.PublicKey)
	canonical, _ := MarshalCanonical(issuance.Body)
	message, _ := Frame(DomainEnrollmentProvisionalIssuanceSignature, canonical)
	if !ok || !ed25519.Verify(publicKey, message, rawSignature) {
		return errors.New("[Device CA] provisional issuance signature 无效")
	}
	return nil
}

func EnrollmentProvisionalIssuanceHash(issuance *EnrollmentProvisionalIssuanceV1) (string, error) {
	if issuance == nil || ValidateEnrollmentProvisionalIssuanceBody(&issuance.Body) != nil {
		return "", errors.New("[Enrollment] provisional issuance envelope 无效")
	}
	return HashObject(DomainEnrollmentProvisionalIssuanceEnvelope, issuance)
}

func validateEnrollmentIssuanceProfile(body *EnrollmentProvisionalIssuanceBodyV1,
	profile *DeviceCertificateProfileStateV1) error {
	if err := ValidateEnrollmentProvisionalIssuanceBody(body); err != nil {
		return err
	}
	if err := ValidateDeviceCertificateProfileState(profile); err != nil {
		return err
	}
	profileHash, _ := DeviceCertificateProfileStateHash(profile)
	if profile.Status != "active" || profile.ClusterID != body.ClusterID ||
		body.DeviceCertificateProfileStateHash != profileHash {
		return errors.New("[Device CA] provisional issuance 未绑定 exact active/fenced profile")
	}
	return nil
}

func mustMarshalPKIX(public any) []byte {
	der, _ := x509.MarshalPKIXPublicKey(public)
	return der
}

func ValidateEnrollmentIssuanceRegistryLeaf(leaf *EnrollmentIssuanceRegistryLeafV1) error {
	if leaf == nil || leaf.Schema != 1 {
		return errors.New("[Enrollment] issuance registry leaf schema 无效")
	}
	if _, err := ParseHash(leaf.ClaimOperationHash); err != nil {
		return err
	}
	if _, err := ParseHash(leaf.ProvisionalIssuanceHash); err != nil {
		return err
	}
	return nil
}

func EnrollmentIssuanceRegistryLeafHash(leaf *EnrollmentIssuanceRegistryLeafV1) (string, error) {
	if err := ValidateEnrollmentIssuanceRegistryLeaf(leaf); err != nil {
		return "", err
	}
	return HashObject(DomainEnrollmentIssuanceRegistryLeaf, leaf)
}

// EnrollmentIssuanceRegistryRoot 按 claim-operation hash raw bytes 排序；同一 claim
// 只允许一个 first-result leaf，避免输入顺序或字符串排序造成跨实现分歧。
func EnrollmentIssuanceRegistryRoot(leaves []EnrollmentIssuanceRegistryLeafV1) (string, error) {
	ordered := append([]EnrollmentIssuanceRegistryLeafV1(nil), leaves...)
	for index := range ordered {
		if err := ValidateEnrollmentIssuanceRegistryLeaf(&ordered[index]); err != nil {
			return "", err
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		left, _ := ParseHash(ordered[i].ClaimOperationHash)
		right, _ := ParseHash(ordered[j].ClaimOperationHash)
		return bytes.Compare(left, right) < 0
	})
	canonical := make([][]byte, len(ordered))
	for index := range ordered {
		if index > 0 && ordered[index-1].ClaimOperationHash == ordered[index].ClaimOperationHash {
			return "", errors.New("[Enrollment] issuance registry 含重复 claim first-result")
		}
		canonical[index], _ = MarshalCanonical(ordered[index])
	}
	return canonicalMerkleRootHash(canonical), nil
}
