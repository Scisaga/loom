package wire

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
)

const (
	DomainSealingPolicy                     = "loom-sealing-policy-v1"
	DomainSealedSecretRecipientSet          = "loom-sealed-secret-recipient-set-v1"
	DomainSealedSecretContext               = "loom-sealed-secret-context-v1"
	DomainSealedSecretEnvelope              = "loom-sealed-secret-envelope-v1"
	DomainSealedSecretEphemeralSPKI         = "loom-sealed-secret-ephemeral-spki-v1"
	DomainAuthorityProofKeyID               = "loom-authority-proof-key-id-v1"
	DomainSecretPossessionProofSignature    = "loom-secret-possession-proof-signature-v1"
	DomainSecretPossessionProof             = "loom-secret-possession-proof-v1"
	DomainArtifactAvailabilityPolicy        = "loom-artifact-availability-policy-v1"
	DomainArtifactAvailabilityReceiptSign   = "loom-artifact-availability-receipt-signature-v1"
	DomainArtifactAvailabilityReceipt       = "loom-artifact-availability-receipt-v1"
	DomainSecretArtifactRef                 = "loom-secret-artifact-ref-v2"
	DomainSealedSecretPayloadAAD            = "loom-sealed-secret-payload-aad-v1"
	DomainSealedSecretHKDFSalt              = "loom-sealed-secret-hkdf-salt-v1"
	DomainSealedSecretKEKInfo               = "loom-sealed-secret-kek-info-v1"
	DomainSealedSecretWrapAAD               = "loom-sealed-secret-wrap-aad-v1"
	secretArtifactMaximumImmutableRefBytes  = 2048
	secretArtifactMaximumProviderFieldBytes = 256
)

var secretPurposeOrder = []string{
	"invite_token",
	"device_credential",
	"data_plane_credential",
	"tls_private_key",
	"ca_private_key",
	"dns_provider_credential",
	"acme_account_key",
	"acme_order_state",
	"control_peer_identity",
	"recovery_private_key",
}

type SecretArtifactDeviceOwnerV1 struct {
	DeviceID string `json:"device_id"`
}

type SecretArtifactRecoveryOwnerV1 struct {
	PolicyID         string `json:"policy_id"`
	PolicyGeneration int64  `json:"policy_generation"`
	KeyID            string `json:"key_id"`
}

type SecretArtifactOwnerV1 struct {
	Kind           string                         `json:"kind"`
	Device         *SecretArtifactDeviceOwnerV1   `json:"device,omitempty"`
	RecoveryPolicy *SecretArtifactRecoveryOwnerV1 `json:"recovery_policy,omitempty"`
}

type AuthorityProofKeyV1 struct {
	Algorithm        string `json:"algorithm"`
	PublicKeySPKIDER string `json:"public_key_spki_der"`
	KeyID            string `json:"key_id"`
}

type AuthorityProofSignatureV1 struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

type P256ECDHSealingPolicyV1 struct {
	Curve          string `json:"curve"`
	SharedSecret   string `json:"shared_secret"`
	KDF            string `json:"kdf"`
	SaltProfile    string `json:"salt_profile"`
	InfoProfile    string `json:"info_profile"`
	WrapAEAD       string `json:"wrap_aead"`
	WrapNonceBytes int64  `json:"wrap_nonce_bytes"`
}

type RSAOAEPSealingPolicyV1 struct {
	ModulusBits    int64  `json:"modulus_bits"`
	PublicExponent int64  `json:"public_exponent"`
	Digest         string `json:"digest"`
	MGF1Digest     string `json:"mgf1_digest"`
	Label          string `json:"label"`
}

type SealingPolicyV1 struct {
	Schema              int                      `json:"schema"`
	PolicyID            string                   `json:"policy_id"`
	Generation          int64                    `json:"generation"`
	RecipientKeyProfile string                   `json:"recipient_key_profile"`
	PlaintextFormat     string                   `json:"plaintext_format"`
	ContentAEAD         string                   `json:"content_aead"`
	CEKBytes            int64                    `json:"cek_bytes"`
	ContentNonceBytes   int64                    `json:"content_nonce_bytes"`
	TagBytes            int64                    `json:"tag_bytes"`
	KeyWrapKind         string                   `json:"key_wrap_kind"`
	P256ECDH            *P256ECDHSealingPolicyV1 `json:"p256_ecdh,omitempty"`
	RSAOAEP             *RSAOAEPSealingPolicyV1  `json:"rsa_oaep,omitempty"`
}

type SealedBlobRecipientKeyRefV1 struct {
	RecipientID            string              `json:"recipient_id"`
	RecipientKeyGeneration int64               `json:"recipient_key_generation"`
	RecipientKeyID         string              `json:"recipient_key_id"`
	RecipientKeyProfile    string              `json:"recipient_key_profile"`
	RecipientPublicKey     AuthorityProofKeyV1 `json:"recipient_public_key"`
}

type SealedBlobRefV1 struct {
	CiphertextDigest     string                        `json:"ciphertext_digest"`
	SealingPolicy        SealingPolicyV1               `json:"sealing_policy"`
	SealingPolicyHash    string                        `json:"sealing_policy_hash"`
	RecipientKeyVersions []SealedBlobRecipientKeyRefV1 `json:"recipient_key_versions"`
}

type KMSOrHardwareKeyRefV1 struct {
	Provider     string `json:"provider"`
	ObjectID     string `json:"object_id"`
	ExactVersion string `json:"exact_version"`
	PolicyHash   string `json:"policy_hash"`
}

type SecretArtifactRefV2 struct {
	Schema                   int                    `json:"schema"`
	ClusterID                string                 `json:"cluster_id"`
	ProposalID               string                 `json:"proposal_id"`
	SecretID                 string                 `json:"secret_id"`
	Purpose                  string                 `json:"purpose"`
	Owner                    SecretArtifactOwnerV1  `json:"owner"`
	Generation               int64                  `json:"generation"`
	PublicKey                *AuthorityProofKeyV1   `json:"public_key,omitempty"`
	ImmutableRef             string                 `json:"immutable_ref"`
	BackendKind              string                 `json:"backend_kind"`
	SealedBlob               *SealedBlobRefV1       `json:"sealed_blob,omitempty"`
	KMSOrHardwareKey         *KMSOrHardwareKeyRefV1 `json:"kms_or_hardware_key,omitempty"`
	PossessionProofHash      *string                `json:"possession_proof_hash,omitempty"`
	AvailabilityPolicyHash   string                 `json:"availability_policy_hash"`
	AvailabilityReceiptsRoot string                 `json:"availability_receipts_root"`
}

type SealedSecretContextV1 struct {
	Schema            int                   `json:"schema"`
	ClusterID         string                `json:"cluster_id"`
	ProposalID        string                `json:"proposal_id"`
	SecretID          string                `json:"secret_id"`
	Purpose           string                `json:"purpose"`
	Owner             SecretArtifactOwnerV1 `json:"owner"`
	Generation        int64                 `json:"generation"`
	SealingPolicyHash string                `json:"sealing_policy_hash"`
	RecipientSetHash  string                `json:"recipient_set_hash"`
}

type SealedSecretPlaintextV1 struct {
	Schema      int                   `json:"schema"`
	Context     SealedSecretContextV1 `json:"context"`
	SecretBytes string                `json:"secret_bytes"`
}

type SealedSecretP256RecipientEnvelopeV1 struct {
	EphemeralSPKIDER  string `json:"ephemeral_spki_der"`
	EphemeralSPKIHash string `json:"ephemeral_spki_hash"`
	WrapNonce         string `json:"wrap_nonce"`
	WrappedCEKAndTag  string `json:"wrapped_cek_and_tag"`
}

type SealedSecretRSARecipientEnvelopeV1 struct {
	WrappedCEK string `json:"wrapped_cek"`
}

type SealedSecretRecipientEnvelopeV1 struct {
	RecipientKey SealedBlobRecipientKeyRefV1          `json:"recipient_key"`
	KeyWrapKind  string                               `json:"key_wrap_kind"`
	P256ECDH     *SealedSecretP256RecipientEnvelopeV1 `json:"p256_ecdh,omitempty"`
	RSAOAEP      *SealedSecretRSARecipientEnvelopeV1  `json:"rsa_oaep,omitempty"`
}

type SealedSecretEnvelopeV1 struct {
	Schema             int                               `json:"schema"`
	Context            SealedSecretContextV1             `json:"context"`
	ContentNonce       string                            `json:"content_nonce"`
	CiphertextAndTag   string                            `json:"ciphertext_and_tag"`
	RecipientEnvelopes []SealedSecretRecipientEnvelopeV1 `json:"recipient_envelopes"`
}

type SecretPossessionProofBodyV1 struct {
	Schema       int                   `json:"schema"`
	ClusterID    string                `json:"cluster_id"`
	ProposalID   string                `json:"proposal_id"`
	SecretID     string                `json:"secret_id"`
	Generation   int64                 `json:"generation"`
	Purpose      string                `json:"purpose"`
	Owner        SecretArtifactOwnerV1 `json:"owner"`
	ImmutableRef string                `json:"immutable_ref"`
	PublicKey    AuthorityProofKeyV1   `json:"public_key"`
}

type SecretPossessionProofV1 struct {
	Body           SecretPossessionProofBodyV1 `json:"body"`
	ProofSignature AuthorityProofSignatureV1   `json:"proof_signature"`
}

type ArtifactAvailabilityReporterRefV1 struct {
	ReporterID      string              `json:"reporter_id"`
	ReporterKey     AuthorityProofKeyV1 `json:"reporter_key"`
	FaultDomain     string              `json:"fault_domain"`
	AllowedPurposes []string            `json:"allowed_purposes"`
}

type ArtifactAvailabilityPolicyV1 struct {
	Schema                   int                                 `json:"schema"`
	ClusterID                string                              `json:"cluster_id"`
	PolicyID                 string                              `json:"policy_id"`
	Generation               int64                               `json:"generation"`
	RequiredReceiptCount     int64                               `json:"required_receipt_count"`
	RequiredFaultDomainCount int64                               `json:"required_fault_domain_count"`
	MaxReceiptAgeSeconds     int64                               `json:"max_receipt_age_seconds"`
	Reporters                []ArtifactAvailabilityReporterRefV1 `json:"reporters"`
}

type ArtifactAvailabilityReceiptBodyV1 struct {
	Schema                  int                          `json:"schema"`
	ClusterID               string                       `json:"cluster_id"`
	ProposalID              string                       `json:"proposal_id"`
	SecretID                string                       `json:"secret_id"`
	Generation              int64                        `json:"generation"`
	Purpose                 string                       `json:"purpose"`
	ImmutableRef            string                       `json:"immutable_ref"`
	ArtifactOrVersionDigest string                       `json:"artifact_or_version_digest"`
	ReporterID              string                       `json:"reporter_id"`
	RecipientKeyRef         *SealedBlobRecipientKeyRefV1 `json:"recipient_key_ref,omitempty"`
	ObservedAt              string                       `json:"observed_at"`
}

type ArtifactAvailabilityReceiptV1 struct {
	Body              ArtifactAvailabilityReceiptBodyV1 `json:"body"`
	ReporterSignature AuthorityProofSignatureV1         `json:"reporter_signature"`
}

type ArtifactAvailabilityReceiptLeafV1 struct {
	Schema      int    `json:"schema"`
	ReporterID  string `json:"reporter_id"`
	ReceiptHash string `json:"receipt_hash"`
}

// ValidateSecretArtifactOwner 钉住 owner tagged union，避免同一 secret 被两种
// authority 解释（D124）。
func ValidateSecretArtifactOwner(owner *SecretArtifactOwnerV1) error {
	if owner == nil {
		return errors.New("[D124 secret artifact] owner 缺失")
	}
	switch owner.Kind {
	case "device":
		if owner.Device == nil || owner.RecoveryPolicy != nil || !validIdentifier(owner.Device.DeviceID, 128) {
			return errors.New("[D124 secret artifact] device owner union 无效")
		}
	case "recovery_policy":
		if owner.Device != nil || owner.RecoveryPolicy == nil || !validIdentifier(owner.RecoveryPolicy.PolicyID, 128) ||
			owner.RecoveryPolicy.PolicyGeneration < 1 || !validIdentifier(owner.RecoveryPolicy.KeyID, 256) {
			return errors.New("[D124 secret artifact] recovery owner union 无效")
		}
	default:
		return errors.New("[D124 secret artifact] owner kind 未获协议授权")
	}
	return nil
}

func AuthorityProofKeyID(spkiDER []byte) (string, error) {
	if len(spkiDER) == 0 {
		return "", errors.New("[D124 secret artifact] authority SPKI 为空")
	}
	return HashBytes(DomainAuthorityProofKeyID, spkiDER)
}

// ParseAuthorityProofKey 既检查算法参数，也要求 DER 能逐字节 round-trip；宽松
// BER 或 provider 自选参数不能进入签名身份（D124）。
func ParseAuthorityProofKey(key *AuthorityProofKeyV1) (any, error) {
	if key == nil || !oneOf(key.Algorithm, "ed25519", "ecdsa-p256-sha256", "rsa2048-pkcs1v15-sha256") {
		return nil, errors.New("[D124 secret artifact] authority proof key algorithm 无效")
	}
	der, err := decodeCanonicalBase64URL(key.PublicKeySPKIDER)
	if err != nil {
		return nil, errors.New("[D124 secret artifact] authority proof SPKI 编码无效")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("[D124 secret artifact] authority proof SPKI DER 无效")
	}
	reencoded, err := x509.MarshalPKIXPublicKey(parsed)
	if err != nil || !bytes.Equal(reencoded, der) {
		return nil, errors.New("[D124 secret artifact] authority proof SPKI 非 strict DER")
	}
	switch public := parsed.(type) {
	case ed25519.PublicKey:
		if key.Algorithm != "ed25519" || len(public) != ed25519.PublicKeySize {
			return nil, errors.New("[D124 secret artifact] Ed25519 SPKI/profile 不匹配")
		}
	case *ecdsa.PublicKey:
		if key.Algorithm != "ecdsa-p256-sha256" || public.Curve != elliptic.P256() {
			return nil, errors.New("[D124 secret artifact] P-256 SPKI/profile 不匹配")
		}
	case *rsa.PublicKey:
		if key.Algorithm != "rsa2048-pkcs1v15-sha256" || public.N.BitLen() != 2048 || public.E != 65537 {
			return nil, errors.New("[D124 secret artifact] RSA-2048 SPKI/profile 不匹配")
		}
	default:
		return nil, errors.New("[D124 secret artifact] authority proof SPKI 类型无效")
	}
	wantID, _ := AuthorityProofKeyID(der)
	if key.KeyID != wantID {
		return nil, errors.New("[D124 secret artifact] authority proof key_id 不匹配")
	}
	return parsed, nil
}

func ValidateSealingPolicy(policy *SealingPolicyV1) error {
	if policy == nil || policy.Schema != 1 || policy.Generation != 1 ||
		policy.PlaintextFormat != "jcs-sealed-secret-plaintext-v1" || policy.ContentAEAD != "aes-256-gcm" ||
		policy.CEKBytes != 32 || policy.ContentNonceBytes != 12 || policy.TagBytes != 16 {
		return errors.New("[D124 sealed secret] sealing policy 共同字段无效")
	}
	switch policy.KeyWrapKind {
	case "p256_ecdh":
		p := policy.P256ECDH
		if policy.RSAOAEP != nil || p == nil || policy.PolicyID != "sealed-p256-v1" ||
			policy.RecipientKeyProfile != "p256-keystore-ecdh-v1" || p.Curve != "p256" ||
			p.SharedSecret != "x-coordinate-be32" || p.KDF != "hkdf-sha256" ||
			p.SaltProfile != "context-sha256-v1" || p.InfoProfile != "recipient-context-frame-v1" ||
			p.WrapAEAD != "aes-256-gcm" || p.WrapNonceBytes != 12 {
			return errors.New("[D124 sealed secret] P-256 sealing policy 不是固定 profile")
		}
	case "rsa_oaep":
		p := policy.RSAOAEP
		if policy.P256ECDH != nil || p == nil || policy.PolicyID != "sealed-rsa2048-v1" ||
			policy.RecipientKeyProfile != "rsa2048-keystore-decrypt-v1" || p.ModulusBits != 2048 ||
			p.PublicExponent != 65537 || p.Digest != "sha256" || p.MGF1Digest != "sha1" || p.Label != "empty" {
			return errors.New("[D124 sealed secret] RSA sealing policy 不是固定 profile")
		}
	default:
		return errors.New("[D124 sealed secret] key wrap kind 未获协议授权")
	}
	return nil
}

func SealingPolicyHash(policy *SealingPolicyV1) (string, error) {
	if err := ValidateSealingPolicy(policy); err != nil {
		return "", err
	}
	return HashObject(DomainSealingPolicy, policy)
}

func validateRecipientKeyRef(ref *SealedBlobRecipientKeyRefV1, profile string) error {
	if ref == nil || !validIdentifier(ref.RecipientID, 128) || ref.RecipientKeyGeneration < 1 ||
		!validIdentifier(ref.RecipientKeyID, 256) || ref.RecipientKeyProfile != profile ||
		ref.RecipientKeyID != ref.RecipientPublicKey.KeyID {
		return errors.New("[D124 sealed secret] recipient key ref 字段无效")
	}
	public, err := ParseAuthorityProofKey(&ref.RecipientPublicKey)
	if err != nil {
		return err
	}
	if profile == "p256-keystore-ecdh-v1" {
		if _, ok := public.(*ecdsa.PublicKey); !ok {
			return errors.New("[D124 sealed secret] P-256 recipient profile/SPKI 不匹配")
		}
	} else if profile == "rsa2048-keystore-decrypt-v1" {
		if _, ok := public.(*rsa.PublicKey); !ok {
			return errors.New("[D124 sealed secret] RSA recipient profile/SPKI 不匹配")
		}
	}
	return nil
}

func ValidateSealedBlobRef(ref *SealedBlobRefV1) error {
	if ref == nil || len(ref.RecipientKeyVersions) == 0 {
		return errors.New("[D124 sealed secret] sealed blob/recipients 缺失")
	}
	if _, err := ParseHash(ref.CiphertextDigest); err != nil {
		return err
	}
	policyHash, err := SealingPolicyHash(&ref.SealingPolicy)
	if err != nil || policyHash != ref.SealingPolicyHash {
		return errors.New("[D124 sealed secret] sealing policy hash 不匹配")
	}
	for i := range ref.RecipientKeyVersions {
		current := &ref.RecipientKeyVersions[i]
		if err := validateRecipientKeyRef(current, ref.SealingPolicy.RecipientKeyProfile); err != nil {
			return err
		}
		if i > 0 && compareRecipientRefs(&ref.RecipientKeyVersions[i-1], current) >= 0 {
			return errors.New("[D124 sealed secret] recipient refs 必须严格排序且不重复")
		}
	}
	return nil
}

func compareRecipientRefs(left, right *SealedBlobRecipientKeyRefV1) int {
	if value := strings.Compare(left.RecipientID, right.RecipientID); value != 0 {
		return value
	}
	if left.RecipientKeyGeneration < right.RecipientKeyGeneration {
		return -1
	}
	if left.RecipientKeyGeneration > right.RecipientKeyGeneration {
		return 1
	}
	return strings.Compare(left.RecipientKeyID, right.RecipientKeyID)
}

func validateSecretRefHeader(ref *SecretArtifactRefV2) error {
	if ref == nil || ref.Schema != 2 || !validIdentifier(ref.ClusterID, 128) ||
		!validIdentifier(ref.ProposalID, 128) || !validIdentifier(ref.SecretID, 128) ||
		!contains(secretPurposeOrder, ref.Purpose) || ref.Generation < 1 ||
		!validIdentifier(ref.ImmutableRef, secretArtifactMaximumImmutableRefBytes) {
		return errors.New("[D124 secret artifact] ref header 无效")
	}
	if err := ValidateSecretArtifactOwner(&ref.Owner); err != nil {
		return err
	}
	if (ref.Purpose == "recovery_private_key") != (ref.Owner.Kind == "recovery_policy") {
		return errors.New("[D124 secret artifact] purpose/owner kind 不匹配")
	}
	if _, err := ParseHash(ref.AvailabilityPolicyHash); err != nil {
		return err
	}
	if _, err := ParseHash(ref.AvailabilityReceiptsRoot); err != nil {
		return err
	}
	return nil
}

func ValidateSecretArtifactRef(ref *SecretArtifactRefV2) error {
	if err := validateSecretRefHeader(ref); err != nil {
		return err
	}
	switch ref.BackendKind {
	case "sealed_blob":
		if ref.SealedBlob == nil || ref.KMSOrHardwareKey != nil {
			return errors.New("[D124 secret artifact] sealed backend union 无效")
		}
		if err := ValidateSealedBlobRef(ref.SealedBlob); err != nil {
			return err
		}
	case "kms_or_hardware_key":
		backend := ref.KMSOrHardwareKey
		if ref.SealedBlob != nil || backend == nil ||
			!validIdentifier(backend.Provider, secretArtifactMaximumProviderFieldBytes) ||
			!validIdentifier(backend.ObjectID, secretArtifactMaximumImmutableRefBytes) ||
			!validIdentifier(backend.ExactVersion, secretArtifactMaximumProviderFieldBytes) ||
			strings.EqualFold(backend.ExactVersion, "latest") {
			return errors.New("[D124 secret artifact] KMS/HSM exact version union 无效")
		}
		if _, err := ParseHash(backend.PolicyHash); err != nil {
			return err
		}
	default:
		return errors.New("[D124 secret artifact] backend kind 未获协议授权")
	}
	publicRequired := oneOf(ref.Purpose, "tls_private_key", "ca_private_key", "acme_account_key", "control_peer_identity", "recovery_private_key")
	if publicRequired && (ref.PublicKey == nil || ref.PossessionProofHash == nil) {
		return errors.New("[D124 secret artifact] private-key purpose 缺 SPKI/PoP")
	}
	if (ref.PublicKey == nil) != (ref.PossessionProofHash == nil) {
		return errors.New("[D124 secret artifact] SPKI 与 possession proof 必须同时存在或缺失")
	}
	if ref.PublicKey != nil {
		if _, err := ParseAuthorityProofKey(ref.PublicKey); err != nil {
			return err
		}
		if _, err := ParseHash(*ref.PossessionProofHash); err != nil {
			return err
		}
	}
	if ref.Purpose == "invite_token" || ref.Purpose == "acme_order_state" {
		if ref.BackendKind != "sealed_blob" || ref.PublicKey != nil {
			return errors.New("[D124 secret artifact] bearer secret backend/PoP 无效")
		}
	}
	if oneOf(ref.Purpose, "ca_private_key", "acme_account_key") && ref.BackendKind != "kms_or_hardware_key" {
		return errors.New("[D124 secret artifact] CA/ACME key 必须使用 exact KMS/HSM version")
	}
	return nil
}

func SecretArtifactRefHash(ref *SecretArtifactRefV2) (string, error) {
	if err := ValidateSecretArtifactRef(ref); err != nil {
		return "", err
	}
	return HashObject(DomainSecretArtifactRef, ref)
}

func SecretPossessionProofHash(proof *SecretPossessionProofV1) (string, error) {
	if err := ValidateSecretPossessionProof(proof); err != nil {
		return "", err
	}
	return HashObject(DomainSecretPossessionProof, proof)
}

func ValidateSecretPossessionProof(proof *SecretPossessionProofV1) error {
	if proof == nil || proof.Body.Schema != 1 || !validIdentifier(proof.Body.ClusterID, 128) ||
		!validIdentifier(proof.Body.ProposalID, 128) || !validIdentifier(proof.Body.SecretID, 128) ||
		proof.Body.Generation < 1 || !contains(secretPurposeOrder, proof.Body.Purpose) ||
		!validIdentifier(proof.Body.ImmutableRef, secretArtifactMaximumImmutableRefBytes) {
		return errors.New("[D124 secret artifact] possession proof body 无效")
	}
	if err := ValidateSecretArtifactOwner(&proof.Body.Owner); err != nil {
		return err
	}
	canonical, err := MarshalCanonical(proof.Body)
	if err != nil {
		return err
	}
	message, _ := Frame(DomainSecretPossessionProofSignature, canonical)
	return VerifyAuthorityProofSignature(&proof.Body.PublicKey, &proof.ProofSignature, message)
}

func VerifyAuthorityProofSignature(key *AuthorityProofKeyV1, signature *AuthorityProofSignatureV1, message []byte) error {
	public, err := ParseAuthorityProofKey(key)
	if err != nil {
		return err
	}
	if signature == nil || signature.Algorithm != key.Algorithm || signature.KeyID != key.KeyID {
		return errors.New("[D124 secret artifact] proof signature identity 不匹配")
	}
	raw, err := decodeCanonicalBase64URL(signature.Signature)
	if err != nil {
		return errors.New("[D124 secret artifact] proof signature 编码无效")
	}
	switch typed := public.(type) {
	case ed25519.PublicKey:
		if len(raw) != ed25519.SignatureSize || !ed25519.Verify(typed, message, raw) {
			return errors.New("[D124 secret artifact] Ed25519 proof signature 无效")
		}
	case *ecdsa.PublicKey:
		if len(raw) != 64 {
			return errors.New("[D124 secret artifact] P-256 signature 必须是 raw r||s")
		}
		r, s := new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])
		if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(typed.Params().N) >= 0 || s.Cmp(new(big.Int).Rsh(new(big.Int).Set(typed.Params().N), 1)) > 0 {
			return errors.New("[D124 secret artifact] P-256 signature 非 canonical low-S")
		}
		digest := sha256.Sum256(message)
		if !ecdsa.Verify(typed, digest[:], r, s) {
			return errors.New("[D124 secret artifact] P-256 proof signature 无效")
		}
	case *rsa.PublicKey:
		if len(raw) != 256 {
			return errors.New("[D124 secret artifact] RSA signature 长度无效")
		}
		digest := sha256.Sum256(message)
		if rsa.VerifyPKCS1v15(typed, crypto.SHA256, digest[:], raw) != nil {
			return errors.New("[D124 secret artifact] RSA proof signature 无效")
		}
	default:
		return errors.New("[D124 secret artifact] proof key 类型无效")
	}
	return nil
}

func ValidateArtifactAvailabilityPolicy(policy *ArtifactAvailabilityPolicyV1) error {
	if policy == nil || policy.Schema != 1 || !validIdentifier(policy.ClusterID, 128) ||
		!validIdentifier(policy.PolicyID, 128) || policy.Generation < 1 || policy.MaxReceiptAgeSeconds < 1 ||
		policy.RequiredReceiptCount < 1 || policy.RequiredReceiptCount > int64(len(policy.Reporters)) ||
		policy.RequiredFaultDomainCount < 1 || policy.RequiredFaultDomainCount > policy.RequiredReceiptCount {
		return errors.New("[D124 secret artifact] availability policy bounds 无效")
	}
	keyIDs := make(map[string]struct{}, len(policy.Reporters))
	for i := range policy.Reporters {
		reporter := &policy.Reporters[i]
		if !validIdentifier(reporter.ReporterID, 128) || !validIdentifier(reporter.FaultDomain, 128) ||
			!sortedEnum(reporter.AllowedPurposes, secretPurposeOrder, true) ||
			i > 0 && policy.Reporters[i-1].ReporterID >= reporter.ReporterID {
			return errors.New("[D124 secret artifact] availability reporters 无效/未排序")
		}
		if _, err := ParseAuthorityProofKey(&reporter.ReporterKey); err != nil {
			return err
		}
		if _, exists := keyIDs[reporter.ReporterKey.KeyID]; exists {
			return errors.New("[D124 secret artifact] availability reporter key 重复")
		}
		keyIDs[reporter.ReporterKey.KeyID] = struct{}{}
	}
	return nil
}

func ArtifactAvailabilityPolicyHash(policy *ArtifactAvailabilityPolicyV1) (string, error) {
	if err := ValidateArtifactAvailabilityPolicy(policy); err != nil {
		return "", err
	}
	return HashObject(DomainArtifactAvailabilityPolicy, policy)
}

func ArtifactAvailabilityReceiptHash(receipt *ArtifactAvailabilityReceiptV1) (string, error) {
	if receipt == nil {
		return "", errors.New("[D124 secret artifact] availability receipt 缺失")
	}
	return HashObject(DomainArtifactAvailabilityReceipt, receipt)
}

func artifactReceiptRoot(receipts []ArtifactAvailabilityReceiptV1) (string, error) {
	leaves := make([][]byte, len(receipts))
	for i := range receipts {
		hash, err := ArtifactAvailabilityReceiptHash(&receipts[i])
		if err != nil {
			return "", err
		}
		leaf := ArtifactAvailabilityReceiptLeafV1{Schema: 1, ReporterID: receipts[i].Body.ReporterID, ReceiptHash: hash}
		leaves[i], err = MarshalCanonical(leaf)
		if err != nil {
			return "", err
		}
	}
	return "sha256:" + fmt.Sprintf("%x", MerkleRoot(leaves)), nil
}

func sameOwner(left, right SecretArtifactOwnerV1) bool {
	leftBytes, leftErr := MarshalCanonical(left)
	rightBytes, rightErr := MarshalCanonical(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

// VerifySecretArtifactEvidence 在 proposal commit 前一次性钉住 ref、PoP、policy、
// receipt 时效及故障域门槛（D124）。candidateTime 必须来自 committed logical time。
func VerifySecretArtifactEvidence(ref *SecretArtifactRefV2, proof *SecretPossessionProofV1, policy *ArtifactAvailabilityPolicyV1, receipts []ArtifactAvailabilityReceiptV1, candidateTime time.Time, maximumClockSkew time.Duration, exactVersionDigest string) error {
	if err := ValidateSecretArtifactRef(ref); err != nil {
		return err
	}
	if candidateTime.IsZero() || maximumClockSkew < 0 {
		return errors.New("[D124 secret artifact] candidate time/clock skew 无效")
	}
	policyHash, err := ArtifactAvailabilityPolicyHash(policy)
	if err != nil || policyHash != ref.AvailabilityPolicyHash || policy.ClusterID != ref.ClusterID {
		return errors.New("[D124 secret artifact] availability policy binding 不匹配")
	}
	if ref.PublicKey == nil {
		if proof != nil {
			return errors.New("[D124 secret artifact] symmetric/bearer secret 禁止 possession proof")
		}
	} else {
		if proof == nil || proof.Body.ClusterID != ref.ClusterID || proof.Body.ProposalID != ref.ProposalID ||
			proof.Body.SecretID != ref.SecretID || proof.Body.Generation != ref.Generation || proof.Body.Purpose != ref.Purpose ||
			proof.Body.ImmutableRef != ref.ImmutableRef || !sameOwner(proof.Body.Owner, ref.Owner) || proof.Body.PublicKey != *ref.PublicKey {
			return errors.New("[D124 secret artifact] possession proof/ref binding 不匹配")
		}
		proofHash, err := SecretPossessionProofHash(proof)
		if err != nil || ref.PossessionProofHash == nil || proofHash != *ref.PossessionProofHash {
			return errors.New("[D124 secret artifact] possession proof hash 不匹配")
		}
	}
	if ref.BackendKind == "sealed_blob" {
		exactVersionDigest = ref.SealedBlob.CiphertextDigest
	} else if _, err := ParseHash(exactVersionDigest); err != nil {
		return errors.New("[D124 secret artifact] KMS/HSM exact version digest 无效")
	}
	if len(receipts) < int(policy.RequiredReceiptCount) {
		return errors.New("[D124 secret artifact] availability receipt 数量不足")
	}
	reporters := make(map[string]ArtifactAvailabilityReporterRefV1, len(policy.Reporters))
	for _, reporter := range policy.Reporters {
		reporters[reporter.ReporterID] = reporter
	}
	faultDomains := make(map[string]struct{})
	for i := range receipts {
		receipt := &receipts[i]
		body := &receipt.Body
		if body.Schema != 1 || body.ClusterID != ref.ClusterID || body.ProposalID != ref.ProposalID ||
			body.SecretID != ref.SecretID || body.Generation != ref.Generation || body.Purpose != ref.Purpose ||
			body.ImmutableRef != ref.ImmutableRef || body.ArtifactOrVersionDigest != exactVersionDigest ||
			i > 0 && receipts[i-1].Body.ReporterID >= body.ReporterID {
			return errors.New("[D124 secret artifact] availability receipt binding/排序无效")
		}
		reporter, found := reporters[body.ReporterID]
		if !found || !contains(reporter.AllowedPurposes, ref.Purpose) {
			return errors.New("[D124 secret artifact] reporter 未获 purpose 授权")
		}
		observedAt, err := ParseTimeZ(body.ObservedAt)
		if err != nil || !receiptTimeValid(observedAt, candidateTime, maximumClockSkew, policy.MaxReceiptAgeSeconds) {
			return errors.New("[D124 secret artifact] availability receipt 时间无效/过期")
		}
		if ref.BackendKind == "sealed_blob" {
			if body.RecipientKeyRef == nil || !recipientPresent(ref.SealedBlob.RecipientKeyVersions, body.RecipientKeyRef) {
				return errors.New("[D124 secret artifact] sealed receipt recipient version 无效")
			}
		} else if body.RecipientKeyRef != nil {
			return errors.New("[D124 secret artifact] KMS/HSM receipt 禁止 recipient key ref")
		}
		canonical, err := MarshalCanonical(*body)
		if err != nil {
			return err
		}
		message, _ := Frame(DomainArtifactAvailabilityReceiptSign, canonical)
		if err := VerifyAuthorityProofSignature(&reporter.ReporterKey, &receipt.ReporterSignature, message); err != nil {
			return err
		}
		faultDomains[reporter.FaultDomain] = struct{}{}
	}
	root, err := artifactReceiptRoot(receipts)
	if err != nil || root != ref.AvailabilityReceiptsRoot {
		return errors.New("[D124 secret artifact] availability receipts root 不匹配")
	}
	if int64(len(faultDomains)) < policy.RequiredFaultDomainCount {
		return errors.New("[D124 secret artifact] availability receipt 故障域不足")
	}
	return nil
}

func receiptTimeValid(observedAt, candidateTime time.Time, maximumClockSkew time.Duration, maximumAgeSeconds int64) bool {
	if maximumClockSkew < 0 || maximumClockSkew%time.Second != 0 || maximumAgeSeconds < 1 {
		return false
	}
	candidateSeconds, observedSeconds := candidateTime.Unix(), observedAt.Unix()
	future, err := CheckedAdd(candidateSeconds, int64(maximumClockSkew/time.Second))
	if err != nil || observedSeconds > future {
		return false
	}
	oldest, err := CheckedAdd(candidateSeconds, -maximumAgeSeconds)
	return err == nil && observedSeconds >= oldest
}

func recipientPresent(refs []SealedBlobRecipientKeyRefV1, candidate *SealedBlobRecipientKeyRefV1) bool {
	for i := range refs {
		if compareRecipientRefs(&refs[i], candidate) == 0 && refs[i] == *candidate {
			return true
		}
	}
	return false
}

func validateSealedContext(context *SealedSecretContextV1) error {
	if context == nil || context.Schema != 1 || !validIdentifier(context.ClusterID, 128) ||
		!validIdentifier(context.ProposalID, 128) || !validIdentifier(context.SecretID, 128) ||
		!contains(secretPurposeOrder, context.Purpose) || context.Generation < 1 {
		return errors.New("[D124 sealed secret] context header 无效")
	}
	if err := ValidateSecretArtifactOwner(&context.Owner); err != nil {
		return err
	}
	for _, hash := range []string{context.SealingPolicyHash, context.RecipientSetHash} {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	return nil
}

func SealedSecretRecipientSetHash(refs []SealedBlobRecipientKeyRefV1) (string, error) {
	if len(refs) == 0 {
		return "", errors.New("[D124 sealed secret] recipient set 为空")
	}
	for i := range refs {
		if i > 0 && compareRecipientRefs(&refs[i-1], &refs[i]) >= 0 {
			return "", errors.New("[D124 sealed secret] recipient set 未排序")
		}
	}
	return HashObject(DomainSealedSecretRecipientSet, refs)
}

func SealedSecretContextHash(context *SealedSecretContextV1) (string, error) {
	if err := validateSealedContext(context); err != nil {
		return "", err
	}
	return HashObject(DomainSealedSecretContext, context)
}

func SealedSecretEnvelopeHash(envelope *SealedSecretEnvelopeV1) (string, error) {
	if err := ValidateSealedSecretEnvelope(envelope); err != nil {
		return "", err
	}
	return HashObject(DomainSealedSecretEnvelope, envelope)
}

func ValidateSealedSecretEnvelope(envelope *SealedSecretEnvelopeV1) error {
	if envelope == nil || envelope.Schema != 1 || len(envelope.RecipientEnvelopes) == 0 {
		return errors.New("[D124 sealed secret] envelope schema/recipients 无效")
	}
	if err := validateSealedContext(&envelope.Context); err != nil {
		return err
	}
	if _, err := decodeRawURL(envelope.ContentNonce, 12); err != nil {
		return errors.New("[D124 sealed secret] content nonce 无效")
	}
	if value, err := decodeCanonicalBase64URL(envelope.CiphertextAndTag); err != nil || len(value) < 16 {
		return errors.New("[D124 sealed secret] ciphertext/tag 无效")
	}
	for i := range envelope.RecipientEnvelopes {
		entry := &envelope.RecipientEnvelopes[i]
		if err := validateRecipientKeyRef(&entry.RecipientKey, entry.RecipientKey.RecipientKeyProfile); err != nil {
			return err
		}
		if i > 0 && compareRecipientRefs(&envelope.RecipientEnvelopes[i-1].RecipientKey, &entry.RecipientKey) >= 0 {
			return errors.New("[D124 sealed secret] recipient envelopes 未排序/重复")
		}
		switch entry.KeyWrapKind {
		case "p256_ecdh":
			value := entry.P256ECDH
			if entry.RSAOAEP != nil || value == nil || entry.RecipientKey.RecipientKeyProfile != "p256-keystore-ecdh-v1" {
				return errors.New("[D124 sealed secret] P-256 recipient envelope union 无效")
			}
			der, err := decodeCanonicalBase64URL(value.EphemeralSPKIDER)
			if err != nil {
				return errors.New("[D124 sealed secret] ephemeral SPKI 编码无效")
			}
			public, err := x509.ParsePKIXPublicKey(der)
			p256, ok := public.(*ecdsa.PublicKey)
			reencoded, marshalErr := x509.MarshalPKIXPublicKey(public)
			if err != nil || !ok || p256.Curve != elliptic.P256() || marshalErr != nil || !bytes.Equal(reencoded, der) {
				return errors.New("[D124 sealed secret] ephemeral SPKI 不是 strict P-256 DER")
			}
			hash, _ := HashBytes(DomainSealedSecretEphemeralSPKI, der)
			if hash != value.EphemeralSPKIHash {
				return errors.New("[D124 sealed secret] ephemeral SPKI hash 不匹配")
			}
			if _, err := decodeRawURL(value.WrapNonce, 12); err != nil {
				return errors.New("[D124 sealed secret] wrap nonce 无效")
			}
			if wrapped, err := decodeRawURL(value.WrappedCEKAndTag, 48); err != nil || len(wrapped) != 48 {
				return errors.New("[D124 sealed secret] wrapped CEK/tag 无效")
			}
		case "rsa_oaep":
			if entry.P256ECDH != nil || entry.RSAOAEP == nil || entry.RecipientKey.RecipientKeyProfile != "rsa2048-keystore-decrypt-v1" {
				return errors.New("[D124 sealed secret] RSA recipient envelope union 无效")
			}
			if _, err := decodeRawURL(entry.RSAOAEP.WrappedCEK, 256); err != nil {
				return errors.New("[D124 sealed secret] RSA wrapped CEK 无效")
			}
		default:
			return errors.New("[D124 sealed secret] recipient key wrap kind 无效")
		}
	}
	return nil
}

// VerifySealedSecretBinding 验证 immutable blob 的 exact bytes 与 ref 逐字段
// 对应；它不读取 provider alias，也不接触明文（D124）。
func VerifySealedSecretBinding(ref *SecretArtifactRefV2, envelope *SealedSecretEnvelopeV1) error {
	if err := ValidateSecretArtifactRef(ref); err != nil {
		return err
	}
	if ref.BackendKind != "sealed_blob" || envelope == nil {
		return errors.New("[D124 sealed secret] ref 不是 sealed blob")
	}
	hash, err := SealedSecretEnvelopeHash(envelope)
	if err != nil || hash != ref.SealedBlob.CiphertextDigest {
		return errors.New("[D124 sealed secret] envelope ciphertext digest 不匹配")
	}
	blob := ref.SealedBlob
	recipientHash, err := SealedSecretRecipientSetHash(blob.RecipientKeyVersions)
	if err != nil || recipientHash != envelope.Context.RecipientSetHash ||
		envelope.Context.SealingPolicyHash != blob.SealingPolicyHash ||
		envelope.Context.ClusterID != ref.ClusterID || envelope.Context.ProposalID != ref.ProposalID ||
		envelope.Context.SecretID != ref.SecretID || envelope.Context.Purpose != ref.Purpose ||
		envelope.Context.Generation != ref.Generation || !sameOwner(envelope.Context.Owner, ref.Owner) ||
		len(envelope.RecipientEnvelopes) != len(blob.RecipientKeyVersions) {
		return errors.New("[D124 sealed secret] envelope context/ref binding 不匹配")
	}
	for i := range blob.RecipientKeyVersions {
		if envelope.RecipientEnvelopes[i].RecipientKey != blob.RecipientKeyVersions[i] ||
			envelope.RecipientEnvelopes[i].KeyWrapKind != blob.SealingPolicy.KeyWrapKind {
			return errors.New("[D124 sealed secret] envelope recipient projection 不匹配")
		}
	}
	return nil
}

// SecretArtifactRefsRoot 使用 purpose 的规范 enum 序、secret_id、generation、
// proposal_id 排序；叶是 exact JCS ref。这样不同 reader 不会自行选择 map 顺序（D124）。
func SecretArtifactRefsRoot(refs []SecretArtifactRefV2) (string, error) {
	if !sort.SliceIsSorted(refs, func(i, j int) bool { return compareSecretArtifactRefs(&refs[i], &refs[j]) < 0 }) {
		return "", errors.New("[D124 secret artifact] refs 未按规范键排序")
	}
	leaves := make([][]byte, len(refs))
	for i := range refs {
		if err := ValidateSecretArtifactRef(&refs[i]); err != nil {
			return "", err
		}
		if i > 0 && compareSecretArtifactRefs(&refs[i-1], &refs[i]) >= 0 {
			return "", errors.New("[D124 secret artifact] refs 重复/未严格排序")
		}
		canonical, err := MarshalCanonical(refs[i])
		if err != nil {
			return "", err
		}
		leaves[i] = canonical
	}
	return "sha256:" + fmt.Sprintf("%x", MerkleRoot(leaves)), nil
}

func compareSecretArtifactRefs(left, right *SecretArtifactRefV2) int {
	leftPurpose, rightPurpose := secretPurposeOrdinal(left.Purpose), secretPurposeOrdinal(right.Purpose)
	if leftPurpose < rightPurpose {
		return -1
	}
	if leftPurpose > rightPurpose {
		return 1
	}
	if value := strings.Compare(left.SecretID, right.SecretID); value != 0 {
		return value
	}
	if left.Generation < right.Generation {
		return -1
	}
	if left.Generation > right.Generation {
		return 1
	}
	return strings.Compare(left.ProposalID, right.ProposalID)
}

func secretPurposeOrdinal(value string) int {
	for i, purpose := range secretPurposeOrder {
		if purpose == value {
			return i
		}
	}
	return len(secretPurposeOrder)
}

func decodeSecretArtifactRefs(raw []json.RawMessage) ([]SecretArtifactRefV2, error) {
	refs := make([]SecretArtifactRefV2, len(raw))
	for i := range raw {
		canonical, err := DecodeStrict(raw[i], 4<<20, &refs[i])
		if err != nil || !bytes.Equal(canonical, raw[i]) {
			return nil, errors.New("[D124 secret artifact] Device view ref 必须是 exact canonical wire")
		}
	}
	return refs, nil
}

// VerifySecretArtifactRefsRoot 把 Device 私有交付容器中的 exact refs 与公开
// payload root 连接起来；仅检查 hash 字符串而不重算会允许替换授权凭据（D124）。
func VerifySecretArtifactRefsRoot(raw []json.RawMessage, expectedRoot string) error {
	refs, err := decodeSecretArtifactRefs(raw)
	if err != nil {
		return err
	}
	root, err := SecretArtifactRefsRoot(refs)
	if err != nil || root != expectedRoot {
		return errors.New("[D124 secret artifact] Device view secret refs root 不匹配")
	}
	return nil
}
