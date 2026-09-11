package enrollmentv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"loom/internal/wire"
)

// ClaimPrivateEvidenceV1 保存 admission 后继续事务所需、但不得进入公开
// operation log 的稳定公开材料。它不含 token、CSR、challenge 或 PoP bytes（D129、D130）。
type ClaimPrivateEvidenceV1 struct {
	Schema             int                                  `json:"schema"`
	Opening            wire.DeviceEnrollmentIntentOpeningV1 `json:"opening"`
	WrappingPublicKey  string                               `json:"wrapping_public_key"`
	WrappingKeyProfile string                               `json:"wrapping_key_profile"`
}

func (attempt VerifiedClaimAttemptV2) PrivateClaimEvidence() ClaimPrivateEvidenceV1 {
	return ClaimPrivateEvidenceV1{Schema: 1, Opening: clonePrivateValue(attempt.material.Opening),
		WrappingPublicKey:  attempt.submission.ClaimCore.WrappingPublicKey,
		WrappingKeyProfile: attempt.submission.ClaimCore.WrappingKeyProfile}
}

func validateClaimPrivateEvidence(evidence *ClaimPrivateEvidenceV1, operation *ClaimOperationV2) error {
	if evidence == nil || operation == nil || evidence.Schema != 1 {
		return errors.New("[D130 Enrollment] private claim evidence header 无效")
	}
	openingHash, err := wire.IntentOpeningHash(&evidence.Opening)
	if err != nil {
		return err
	}
	_, commitmentHash, err := wire.IntentCommitment(&evidence.Opening)
	if err != nil || openingHash != operation.DeviceEnrollmentIntentOpeningHash ||
		commitmentHash != operation.DeviceEnrollmentIntentCommitmentHash ||
		evidence.Opening.ClusterID != operation.ClusterID || evidence.Opening.InviteID != operation.InviteID ||
		!containsString(evidence.Opening.DeviceEnrollmentIntent.WrappingKeyProfiles, evidence.WrappingKeyProfile) {
		return errors.New("[D130 Enrollment] private opening/wrapping profile 未绑定 committed claim")
	}
	encoded := evidence.WrappingPublicKey
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(der) == 0 || base64.RawURLEncoding.EncodeToString(der) != encoded {
		return errors.New("[D129 Enrollment] wrapping SPKI 必须是规范无 padding base64url")
	}
	public, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return errors.New("[D129 Enrollment] wrapping SPKI 无效")
	}
	switch evidence.WrappingKeyProfile {
	case "p256-keystore-ecdh-v1", "p256-root-only-pkcs8-ecdh-v1":
		key, ok := public.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() {
			return errors.New("[D129 Enrollment] wrapping key 不是 P-256")
		}
	case "rsa2048-keystore-decrypt-v1":
		key, ok := public.(*rsa.PublicKey)
		if !ok || key.N.BitLen() != 2048 || key.E != 65537 {
			return errors.New("[D129 Enrollment] wrapping key 不是 RSA-2048/e=65537")
		}
	default:
		return errors.New("[D129 Enrollment] wrapping key profile 未获授权")
	}
	hash, err := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, der)
	if err != nil || hash != operation.WrappingKeyHash {
		return errors.New("[D129 Enrollment] wrapping key preimage 未绑定 admitted claim")
	}
	return nil
}
