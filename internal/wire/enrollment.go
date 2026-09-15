package wire

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"net/url"
	"sort"
	"time"
)

const (
	DomainInviteTokenCommitment        = "loom-invite-token-commitment-v2"
	DomainEnrollmentIntent             = "loom-device-enrollment-intent-v1"
	DomainEnrollmentIntentOpening      = "loom-device-enrollment-intent-opening-v1"
	DomainEnrollmentIntentCommitment   = "loom-device-enrollment-intent-commitment-v1"
	DomainPrivateEnrollmentServiceRef  = "loom-private-enrollment-service-ref-v1"
	DomainBootstrapCapabilityID        = "loom-bootstrap-tunnel-capability-id-v1"
	DomainBootstrapCapabilitySignature = "loom-bootstrap-tunnel-capability-signature-v1"
	DomainInviteDescriptor             = "loom-invite-bootstrap-descriptor-v2"
	DomainEnrollmentClaimCore          = "loom-enrollment-claim-core-v2"
	DomainEnrollmentPoPChallenge       = "loom-enrollment-pop-challenge-v1"
	DomainEnrollmentPoPSignature       = "loom-enrollment-pop-signature-v2"
	DomainEnrollmentIdentitySPKI       = "loom-enrollment-identity-spki-v1"
	DomainEnrollmentWrappingSPKI       = "loom-enrollment-wrapping-spki-v1"
	DomainEnrollmentCSRDER             = "loom-enrollment-csr-der-v1"
)

type InviteTokenCommitmentInputV2 struct {
	Schema    int    `json:"schema"`
	ClusterID string `json:"cluster_id"`
	InviteID  string `json:"invite_id"`
	Token     string `json:"token"`
}

type EnrollmentMembershipV1 struct {
	Schema       int    `json:"schema"`
	DesiredState string `json:"desired_state"`
}

type EnrollmentResponsibilitiesV1 struct {
	Schema int      `json:"schema"`
	Values []string `json:"values"`
}

type EnrollmentDestinationGrantV1 struct {
	Kind     string `json:"kind"`
	TargetID string `json:"target_id"`
}

type EnrollmentDestinationGrantsV1 struct {
	Schema int                            `json:"schema"`
	Values []EnrollmentDestinationGrantV1 `json:"values"`
}

type DeviceCertificateProfileRefV1 struct {
	ProfileID                          string `json:"profile_id"`
	Generation                         int64  `json:"generation"`
	DeviceCertificateProfileIntentHash string `json:"device_certificate_profile_intent_hash"`
	DeviceCertificateProfileStateHash  string `json:"device_certificate_profile_state_hash"`
}

type DeviceEnrollmentIntentV1 struct {
	Schema                      int                           `json:"schema"`
	ClusterID                   string                        `json:"cluster_id"`
	InviteID                    string                        `json:"invite_id"`
	DeviceID                    string                        `json:"device_id"`
	Platform                    string                        `json:"platform"`
	DeviceCertificateProfileRef DeviceCertificateProfileRefV1 `json:"device_certificate_profile_ref"`
	WrappingKeyProfiles         []string                      `json:"wrapping_key_profiles"`
	Membership                  EnrollmentMembershipV1        `json:"membership"`
	Responsibilities            EnrollmentResponsibilitiesV1  `json:"responsibilities"`
	Grants                      EnrollmentDestinationGrantsV1 `json:"grants"`
}

type DeviceEnrollmentIntentOpeningV1 struct {
	Schema                     int                      `json:"schema"`
	ClusterID                  string                   `json:"cluster_id"`
	InviteID                   string                   `json:"invite_id"`
	DeviceEnrollmentIntent     DeviceEnrollmentIntentV1 `json:"device_enrollment_intent"`
	DeviceEnrollmentIntentHash string                   `json:"device_enrollment_intent_hash"`
	HidingNonce                string                   `json:"hiding_nonce"`
}

type DeviceEnrollmentIntentCommitmentV1 struct {
	Schema      int    `json:"schema"`
	ClusterID   string `json:"cluster_id"`
	InviteID    string `json:"invite_id"`
	OpeningHash string `json:"opening_hash"`
}

type PrivateEnrollmentServiceRefV1 struct {
	Schema                 int      `json:"schema"`
	ServiceID              string   `json:"service_id"`
	OverlayIP              string   `json:"overlay_ip"`
	TCPPort                int64    `json:"tcp_port"`
	InternalCAProfileRef   string   `json:"internal_ca_profile_ref"`
	ServerIdentitySPKIPins []string `json:"server_identity_spki_pins"`
	ServiceGeneration      int64    `json:"service_generation"`
}

type DistributionMirrorRefV1 struct {
	Schema                      int      `json:"schema"`
	EndpointID                  string   `json:"endpoint_id"`
	DistributionEndpointSetHash string   `json:"distribution_endpoint_set_hash"`
	ListenerGeneration          int64    `json:"listener_generation"`
	BaseURL                     string   `json:"base_url"`
	ServerName                  string   `json:"server_name"`
	WebPKIProfileRef            string   `json:"webpki_profile_ref"`
	SPKIPins                    []string `json:"spki_pins"`
	HintRank                    int64    `json:"hint_rank"`
}

type BootstrapCapabilityResumeBindingV1 struct {
	RequestID                      string `json:"request_id"`
	ClaimOperationHash             string `json:"claim_operation_hash"`
	AdmissionQCHash                string `json:"admission_qc_hash"`
	ClaimCoreHash                  string `json:"claim_core_hash"`
	CSRHash                        string `json:"csr_hash"`
	IdentityKeyHash                string `json:"identity_key_hash"`
	WrappingKeyHash                string `json:"wrapping_key_hash"`
	EnrollmentTransactionStateHash string `json:"enrollment_transaction_state_hash"`
}

type BootstrapTunnelCapabilityBodyV1 struct {
	Schema                           int                                 `json:"schema"`
	ClusterID                        string                              `json:"cluster_id"`
	InviteID                         string                              `json:"invite_id"`
	CommittedInviteRecordHash        string                              `json:"committed_invite_record_hash"`
	InviteIssuancePolicyHash         string                              `json:"invite_issuance_policy_hash"`
	BootstrapIssuerAuthorizationHash string                              `json:"bootstrap_issuer_authorization_hash"`
	BootstrapIssuerRegistryRoot      string                              `json:"bootstrap_issuer_registry_root"`
	EnrollmentServiceRefHash         string                              `json:"enrollment_service_ref_hash"`
	Mode                             string                              `json:"mode"`
	ResumeBinding                    *BootstrapCapabilityResumeBindingV1 `json:"resume_binding,omitempty"`
	IssuedAt                         string                              `json:"issued_at"`
	NotBefore                        string                              `json:"not_before"`
	ExpiresAt                        string                              `json:"expires_at"`
	AllowedIngressSetHash            string                              `json:"allowed_ingress_set_hash"`
	AllowedServiceID                 string                              `json:"allowed_service_id"`
	AllowedDestinationIP             string                              `json:"allowed_destination_ip"`
	AllowedDestinationPrefixLength   int64                               `json:"allowed_destination_prefix_length"`
	AllowedDestinationPort           int64                               `json:"allowed_destination_port"`
	AllowedInsideTransport           string                              `json:"allowed_inside_transport"`
	MaximumConnectionAttempts        int64                               `json:"maximum_connection_attempts"`
	MaximumConcurrentSessions        int64                               `json:"maximum_concurrent_sessions"`
	MaximumSessionSeconds            int64                               `json:"maximum_session_seconds"`
	MaximumTotalBytes                int64                               `json:"maximum_total_bytes"`
	IssuerEpoch                      int64                               `json:"issuer_epoch"`
	IssuerKeyID                      string                              `json:"issuer_key_id"`
}

type BootstrapIssuerSignatureV1 struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

type BootstrapTunnelCapabilityV1 struct {
	Body         BootstrapTunnelCapabilityBodyV1 `json:"body"`
	CapabilityID string                          `json:"capability_id"`
	Signature    BootstrapIssuerSignatureV1      `json:"signature"`
}

// DomainBootstrapTransportCredential 把已签 capability 派生为 HY2/Trojan 的短期
// transport bearer；它不替代 capability signature/authorization 验证。
const DomainBootstrapTransportCredential = "loom-bootstrap-transport-credential-v1"

type InviteBootstrapDescriptorV2 struct {
	Schema                    int                           `json:"schema"`
	ClusterID                 string                        `json:"cluster_id"`
	InviteID                  string                        `json:"invite_id"`
	ExpiresAt                 string                        `json:"expires_at"`
	Token                     string                        `json:"token"`
	TokenCommitment           string                        `json:"token_commitment"`
	BootstrapTunnelCapability BootstrapTunnelCapabilityV1   `json:"bootstrap_tunnel_capability"`
	BootstrapCatalogHash      string                        `json:"bootstrap_catalog_hash"`
	ProofBundleHash           string                        `json:"proof_bundle_hash"`
	EnrollmentServiceRef      PrivateEnrollmentServiceRefV1 `json:"enrollment_service_ref"`
	DistributionMirrors       []DistributionMirrorRefV1     `json:"distribution_mirrors"`
	MinimumRecoveryEpoch      int64                         `json:"minimum_recovery_epoch"`
	TrustedCheckpointHash     string                        `json:"trusted_checkpoint_hash"`
}

type EnrollmentClaimCoreV2 struct {
	Schema                               int    `json:"schema"`
	ClusterID                            string `json:"cluster_id"`
	InviteID                             string `json:"invite_id"`
	RequestID                            string `json:"request_id"`
	CertifiedInviteRecordHash            string `json:"certified_invite_record_hash"`
	DeviceEnrollmentIntentCommitmentHash string `json:"device_enrollment_intent_commitment_hash"`
	DeviceEnrollmentIntentOpeningHash    string `json:"device_enrollment_intent_opening_hash"`
	AcceptedDeviceEnrollmentIntentHash   string `json:"accepted_device_enrollment_intent_hash"`
	ClientPlatform                       string `json:"client_platform"`
	BaseRecoveryEpoch                    int64  `json:"base_recovery_epoch"`
	BaseControlEpoch                     int64  `json:"base_control_epoch"`
	BaseControlSetHash                   string `json:"base_control_set_hash"`
	BaseHeadHash                         string `json:"base_head_hash"`
	DeviceIdentityPublicKey              string `json:"device_identity_public_key"`
	DeviceIdentityKeyProfile             string `json:"device_identity_key_profile"`
	WrappingPublicKey                    string `json:"wrapping_public_key"`
	WrappingKeyProfile                   string `json:"wrapping_key_profile"`
	CSRDER                               string `json:"csr_der"`
	ClientNonce                          string `json:"client_nonce"`
}

type EnrollmentPoPChallengeV1 struct {
	Schema              int    `json:"schema"`
	ClusterID           string `json:"cluster_id"`
	InviteID            string `json:"invite_id"`
	RequestID           string `json:"request_id"`
	EnrollmentServiceID string `json:"enrollment_service_id"`
	ClaimCoreHash       string `json:"claim_core_hash"`
	ServerNonce         string `json:"server_nonce"`
	IssuedAt            string `json:"issued_at"`
	ExpiresAt           string `json:"expires_at"`
}

type EnrollmentPoPBodyV2 struct {
	Schema          int    `json:"schema"`
	ClusterID       string `json:"cluster_id"`
	InviteID        string `json:"invite_id"`
	RequestID       string `json:"request_id"`
	ClaimCoreHash   string `json:"claim_core_hash"`
	TokenCommitment string `json:"token_commitment"`
	ChallengeHash   string `json:"challenge_hash"`
}

type EnrollmentClaimSubmissionV2 struct {
	Schema         int                      `json:"schema"`
	Token          string                   `json:"token"`
	ClaimCore      EnrollmentClaimCoreV2    `json:"claim_core"`
	Challenge      EnrollmentPoPChallengeV1 `json:"challenge"`
	PoPBody        EnrollmentPoPBodyV2      `json:"pop_body"`
	ProofSignature string                   `json:"proof_signature"`
}

// EnrollmentResumeSubmissionV1 只证明仍持有原 identity key，并重用已 committed
// stable core。它刻意没有 token 字段，避免恢复既有事务时重新出示或消费 Invite bearer。
type EnrollmentResumeSubmissionV1 struct {
	Schema         int                      `json:"schema"`
	ClaimCore      EnrollmentClaimCoreV2    `json:"claim_core"`
	Challenge      EnrollmentPoPChallengeV1 `json:"challenge"`
	PoPBody        EnrollmentPoPBodyV2      `json:"pop_body"`
	ProofSignature string                   `json:"proof_signature"`
}

type EnrollmentClaimResultV2 struct {
	Schema               int                         `json:"schema"`
	Status               string                      `json:"status"`
	TransactionStateHash string                      `json:"transaction_state_hash"`
	ResultArtifactHash   string                      `json:"result_artifact_hash,omitempty"`
	ResultArtifact       *EnrollmentResultArtifactV1 `json:"result_artifact,omitempty"`
	// ProgressReceipt 让 reserved/issued_provisional 的客户端取得可验证且可耐久
	// 的 resume binding；兼容 reader 可忽略它，但生产 v2 client 必须验证。
	ProgressReceipt json.RawMessage `json:"progress_receipt,omitempty"`
	// CompletionReceipt 是由 enrollmentv2 定义并独立验证的 canonical proof
	// envelope。wire 层保留 raw bytes，避免基础 wire 包反向依赖事务 reducer；
	// completed 若没有它，客户端无法从 Invite Head 连续验证到 completion Head。
	CompletionReceipt json.RawMessage `json:"completion_receipt,omitempty"`
}

type VerifiedEnrollmentClaimV2 struct {
	claimCoreHash   string
	challengeHash   string
	intentHash      string
	openingHash     string
	commitmentHash  string
	tokenCommitment string
	identityKeyHash string
	wrappingKeyHash string
	csrHash         string
}

func (verified VerifiedEnrollmentClaimV2) ClaimCoreHash() string   { return verified.claimCoreHash }
func (verified VerifiedEnrollmentClaimV2) ChallengeHash() string   { return verified.challengeHash }
func (verified VerifiedEnrollmentClaimV2) IntentHash() string      { return verified.intentHash }
func (verified VerifiedEnrollmentClaimV2) OpeningHash() string     { return verified.openingHash }
func (verified VerifiedEnrollmentClaimV2) CommitmentHash() string  { return verified.commitmentHash }
func (verified VerifiedEnrollmentClaimV2) TokenCommitment() string { return verified.tokenCommitment }
func (verified VerifiedEnrollmentClaimV2) IdentityKeyHash() string { return verified.identityKeyHash }
func (verified VerifiedEnrollmentClaimV2) WrappingKeyHash() string { return verified.wrappingKeyHash }
func (verified VerifiedEnrollmentClaimV2) CSRHash() string         { return verified.csrHash }

func TokenCommitment(clusterID, inviteID, token string) (string, error) {
	if !validIdentifier(clusterID, 128) || !validIdentifier(inviteID, 128) {
		return "", errors.New("[Invite] cluster/invite ID 无效")
	}
	if _, err := decodeRawURL(token, 32); err != nil {
		return "", errors.New("[Invite] token 必须是规范 32-byte base64url")
	}
	return HashObject(DomainInviteTokenCommitment, InviteTokenCommitmentInputV2{
		Schema: 2, ClusterID: clusterID, InviteID: inviteID, Token: token,
	})
}

func ValidateEnrollmentIntent(intent *DeviceEnrollmentIntentV1) error {
	if intent == nil || intent.Schema != 1 || !validIdentifier(intent.ClusterID, 128) ||
		!validIdentifier(intent.InviteID, 128) || !validIdentifier(intent.DeviceID, 128) ||
		!oneOf(intent.Platform, "windows-desktop", "android", "linux-server") ||
		intent.Membership.Schema != 1 || intent.Membership.DesiredState != "active_on_completion" ||
		!sortedUnique(intent.WrappingKeyProfiles) || len(intent.WrappingKeyProfiles) == 0 {
		return errors.New("[Enrollment] intent identity/platform/responsibilities 无效")
	}
	if err := ValidateEnrollmentResponsibilities(&intent.Responsibilities); err != nil {
		return err
	}
	if err := ValidateEnrollmentDestinationGrants(&intent.Grants); err != nil {
		return err
	}
	if intent.DeviceCertificateProfileRef.Generation < 1 || !validIdentifier(intent.DeviceCertificateProfileRef.ProfileID, 128) {
		return errors.New("[Enrollment] Device certificate profile ref 无效")
	}
	for _, hash := range []string{intent.DeviceCertificateProfileRef.DeviceCertificateProfileIntentHash, intent.DeviceCertificateProfileRef.DeviceCertificateProfileStateHash} {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	return nil
}

// ValidateEnrollmentResponsibilities 是服务端 intent 与所有平台 Device view reader
// 共用的职责语义。control 从不属于 Device 自报职责；internet_egress 必须同时
// 承担 forward，不能让签名但语义非法的 view 驱动本机扩大运行面（Issue #11）。
func ValidateEnrollmentResponsibilities(value *EnrollmentResponsibilitiesV1) error {
	if value == nil || value.Schema != 1 ||
		!sortedEnum(value.Values, []string{"use_loom", "forward", "internet_egress"}, true) {
		return errors.New("[Enrollment] responsibilities schema/order/value 无效")
	}
	if contains(value.Values, "internet_egress") && !contains(value.Values, "forward") {
		return errors.New("[Enrollment] internet_egress 必须同时包含 forward")
	}
	return nil
}

func ValidateEnrollmentDestinationGrants(value *EnrollmentDestinationGrantsV1) error {
	if value == nil || value.Schema != 1 || value.Values == nil {
		return errors.New("[Enrollment] destination grants schema 无效")
	}
	for i, grant := range value.Values {
		if !oneOf(grant.Kind, "service", "egress") || !validIdentifier(grant.TargetID, 128) {
			return errors.New("[Enrollment] destination grant 无效")
		}
		if i > 0 {
			previous := value.Values[i-1]
			if previous.Kind > grant.Kind || previous.Kind == grant.Kind && previous.TargetID >= grant.TargetID {
				return errors.New("[Enrollment] grants 必须按 kind/target_id 严格排序")
			}
		}
	}
	return nil
}

func EnrollmentIntentHash(intent *DeviceEnrollmentIntentV1) (string, error) {
	if err := ValidateEnrollmentIntent(intent); err != nil {
		return "", err
	}
	return HashObject(DomainEnrollmentIntent, intent)
}

func ValidateIntentOpening(opening *DeviceEnrollmentIntentOpeningV1) error {
	if opening == nil || opening.Schema != 1 || opening.ClusterID != opening.DeviceEnrollmentIntent.ClusterID ||
		opening.InviteID != opening.DeviceEnrollmentIntent.InviteID {
		return errors.New("[Invite] intent opening identity 不一致")
	}
	intentHash, err := EnrollmentIntentHash(&opening.DeviceEnrollmentIntent)
	if err != nil || intentHash != opening.DeviceEnrollmentIntentHash {
		return errors.New("[Invite] intent opening hash 不匹配")
	}
	if _, err := decodeRawURL(opening.HidingNonce, 32); err != nil {
		return errors.New("[Invite] hiding nonce 无效")
	}
	return nil
}

func IntentOpeningHash(opening *DeviceEnrollmentIntentOpeningV1) (string, error) {
	if err := ValidateIntentOpening(opening); err != nil {
		return "", err
	}
	return HashObject(DomainEnrollmentIntentOpening, opening)
}

func IntentCommitment(opening *DeviceEnrollmentIntentOpeningV1) (DeviceEnrollmentIntentCommitmentV1, string, error) {
	openingHash, err := IntentOpeningHash(opening)
	if err != nil {
		return DeviceEnrollmentIntentCommitmentV1{}, "", err
	}
	commitment := DeviceEnrollmentIntentCommitmentV1{Schema: 1, ClusterID: opening.ClusterID, InviteID: opening.InviteID, OpeningHash: openingHash}
	hash, err := HashObject(DomainEnrollmentIntentCommitment, commitment)
	return commitment, hash, err
}

func PrivateEnrollmentServiceRefHash(ref *PrivateEnrollmentServiceRefV1) (string, error) {
	if err := ValidatePrivateEnrollmentServiceRef(ref); err != nil {
		return "", err
	}
	return HashObject(DomainPrivateEnrollmentServiceRef, ref)
}

func ValidatePrivateEnrollmentServiceRef(ref *PrivateEnrollmentServiceRefV1) error {
	if ref == nil || ref.Schema != 1 || !validIdentifier(ref.ServiceID, 128) || ref.ServiceGeneration < 1 ||
		ref.TCPPort < 1 || ref.TCPPort > 65535 || !validIdentifier(ref.InternalCAProfileRef, 128) ||
		!sortedUnique(ref.ServerIdentitySPKIPins) || len(ref.ServerIdentitySPKIPins) == 0 {
		return errors.New("[Enrollment] private Enrollment service ref 无效")
	}
	for _, pin := range ref.ServerIdentitySPKIPins {
		if _, err := ParseHash(pin); err != nil {
			return errors.New("[Enrollment] private Enrollment service SPKI pin 无效")
		}
	}
	address, err := netip.ParseAddr(ref.OverlayIP)
	if err != nil || address.String() != ref.OverlayIP || !address.IsPrivate() {
		return errors.New("[Enrollment] Enrollment 目的必须是规范私有 overlay IP")
	}
	return nil
}

func CapabilityID(body *BootstrapTunnelCapabilityBodyV1) (string, error) {
	if err := ValidateCapabilityBody(body); err != nil {
		return "", err
	}
	return HashObject(DomainBootstrapCapabilityID, body)
}

func ValidateCapabilityBody(body *BootstrapTunnelCapabilityBodyV1) error {
	if body == nil || body.Schema != 1 || !validIdentifier(body.ClusterID, 128) || !validIdentifier(body.InviteID, 128) ||
		!validIdentifier(body.AllowedServiceID, 128) || !validIdentifier(body.IssuerKeyID, 128) ||
		!oneOf(body.Mode, "initial_claim", "resume_committed_claim") || body.AllowedInsideTransport != "tcp" ||
		body.MaximumConnectionAttempts < 1 || body.MaximumConcurrentSessions != 1 ||
		body.MaximumSessionSeconds < 1 || body.MaximumSessionSeconds > 300 || body.MaximumTotalBytes < 1 ||
		body.AllowedDestinationPort < 1 || body.AllowedDestinationPort > 65535 || body.IssuerEpoch < 0 {
		return errors.New("[capability] schema/mode/limit/transport 无效")
	}
	if (body.Mode == "initial_claim") != (body.ResumeBinding == nil) {
		return errors.New("[capability] resume binding 与 mode 不一致")
	}
	issued, err := ParseTimeZ(body.IssuedAt)
	if err != nil {
		return err
	}
	notBefore, err := ParseTimeZ(body.NotBefore)
	if err != nil {
		return err
	}
	expires, err := ParseTimeZ(body.ExpiresAt)
	if err != nil || !notBefore.Before(expires) || !issued.Before(expires) || expires.Sub(issued) > 30*time.Minute || issued.After(notBefore) {
		return errors.New("[capability] capability time/TTL 无效")
	}
	address, err := netip.ParseAddr(body.AllowedDestinationIP)
	if err != nil || address.String() != body.AllowedDestinationIP || !address.IsPrivate() ||
		(address.Is4() && body.AllowedDestinationPrefixLength != 32) ||
		(address.Is6() && body.AllowedDestinationPrefixLength != 128) {
		return errors.New("[capability] 只允许一个 private Enrollment /32 或 /128")
	}
	for _, hash := range []string{body.CommittedInviteRecordHash, body.InviteIssuancePolicyHash,
		body.BootstrapIssuerAuthorizationHash, body.BootstrapIssuerRegistryRoot,
		body.EnrollmentServiceRefHash, body.AllowedIngressSetHash} {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	if body.ResumeBinding != nil {
		if !validIdentifier(body.ResumeBinding.RequestID, 128) {
			return errors.New("[capability] resume request ID 无效")
		}
		for _, hash := range []string{body.ResumeBinding.ClaimOperationHash, body.ResumeBinding.AdmissionQCHash,
			body.ResumeBinding.ClaimCoreHash, body.ResumeBinding.CSRHash, body.ResumeBinding.IdentityKeyHash,
			body.ResumeBinding.WrappingKeyHash, body.ResumeBinding.EnrollmentTransactionStateHash} {
			if _, err := ParseHash(hash); err != nil {
				return err
			}
		}
	}
	return nil
}

func VerifyBootstrapCapability(capability *BootstrapTunnelCapabilityV1, issuerPublicKey ed25519.PublicKey) error {
	identifier, err := CapabilityID(&capability.Body)
	if err != nil || capability.CapabilityID != identifier || capability.Signature.Algorithm != "ed25519" ||
		capability.Signature.KeyID != capability.Body.IssuerKeyID {
		return errors.New("[capability] ID/signature metadata 无效")
	}
	keyID, err := ControlKeyID(issuerPublicKey)
	if err != nil || keyID != capability.Body.IssuerKeyID {
		return errors.New("[capability] issuer key ID 不匹配")
	}
	rawSignature, err := decodeRawURL(capability.Signature.Signature, ed25519.SignatureSize)
	if err != nil {
		return errors.New("[capability] signature 编码无效")
	}
	canonical, _ := MarshalCanonical(capability.Body)
	message, _ := Frame(DomainBootstrapCapabilitySignature, canonical)
	if !ed25519.Verify(issuerPublicKey, message, rawSignature) {
		return errors.New("[capability] signature 无效")
	}
	return nil
}

func ValidateInviteDescriptor(descriptor *InviteBootstrapDescriptorV2, issuerPublicKey ed25519.PublicKey) error {
	if descriptor == nil || descriptor.Schema != 2 || !validIdentifier(descriptor.ClusterID, 128) ||
		!validIdentifier(descriptor.InviteID, 128) || descriptor.MinimumRecoveryEpoch < 0 ||
		len(descriptor.DistributionMirrors) < 2 || len(descriptor.DistributionMirrors) > 3 {
		return errors.New("[Invite] descriptor header/mirror count 无效")
	}
	expires, err := ParseTimeZ(descriptor.ExpiresAt)
	if err != nil {
		return err
	}
	wantTokenCommitment, err := TokenCommitment(descriptor.ClusterID, descriptor.InviteID, descriptor.Token)
	if err != nil || wantTokenCommitment != descriptor.TokenCommitment {
		return errors.New("[Invite] token commitment 不匹配")
	}
	if err := VerifyBootstrapCapability(&descriptor.BootstrapTunnelCapability, issuerPublicKey); err != nil {
		return err
	}
	body := &descriptor.BootstrapTunnelCapability.Body
	if body.ClusterID != descriptor.ClusterID || body.InviteID != descriptor.InviteID || body.Mode != "initial_claim" {
		return errors.New("[Invite] initial descriptor/capability identity 不一致")
	}
	capabilityExpiry, _ := ParseTimeZ(body.ExpiresAt)
	if capabilityExpiry.After(expires) {
		return errors.New("[capability] initial capability 不得晚于 Invite expiry")
	}
	serviceHash, err := PrivateEnrollmentServiceRefHash(&descriptor.EnrollmentServiceRef)
	if err != nil || serviceHash != body.EnrollmentServiceRefHash ||
		descriptor.EnrollmentServiceRef.ServiceID != body.AllowedServiceID ||
		descriptor.EnrollmentServiceRef.OverlayIP != body.AllowedDestinationIP ||
		descriptor.EnrollmentServiceRef.TCPPort != body.AllowedDestinationPort {
		return errors.New("[capability] Enrollment service exact tuple 不匹配")
	}
	for _, hash := range []string{descriptor.BootstrapCatalogHash, descriptor.ProofBundleHash, descriptor.TrustedCheckpointHash} {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	return validateDistributionMirrorRefs(descriptor.DistributionMirrors)
}

// ValidateDistributionMirrorRefs 供各平台 carrier/fetcher 在任何网络请求前复用
// exact mirror 形状；上层 descriptor 校验不能成为唯一防线。
func ValidateDistributionMirrorRefs(mirrors []DistributionMirrorRefV1) error {
	if len(mirrors) < 2 || len(mirrors) > 3 {
		return errors.New("[Invite] mirror count 无效")
	}
	seenEndpoint := make(map[string]struct{}, len(mirrors))
	seenURL := make(map[string]struct{}, len(mirrors))
	for i, mirror := range mirrors {
		if mirror.Schema != 1 || mirror.ListenerGeneration < 1 || mirror.HintRank < 0 ||
			!validIdentifier(mirror.EndpointID, 128) || !ValidFQDN(mirror.ServerName) ||
			!validIdentifier(mirror.WebPKIProfileRef, 128) ||
			!sortedUnique(mirror.SPKIPins) || len(mirror.SPKIPins) == 0 {
			return errors.New("[Invite] mirror ref 无效")
		}
		for _, pin := range mirror.SPKIPins {
			if _, err := ParseHash(pin); err != nil {
				return errors.New("[Invite] mirror SPKI pin 无效")
			}
		}
		if i > 0 && mirrors[i-1].EndpointID >= mirror.EndpointID {
			return errors.New("[Invite] mirrors 必须按 endpoint_id 严格排序")
		}
		parsed, err := url.ParseRequestURI(mirror.BaseURL)
		if err != nil || parsed == nil || parsed.String() != mirror.BaseURL || parsed.Scheme != "https" || parsed.User != nil ||
			parsed.Opaque != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
			parsed.Hostname() != mirror.ServerName || parsed.Path != "/distribution/sha256/" {
			return errors.New("[Invite] mirror base URL 无效")
		}
		if err := validateExplicitHTTPSBaseURL(mirror.BaseURL, mirror.ServerName); err != nil {
			return err
		}
		if _, err := ParseHash(mirror.DistributionEndpointSetHash); err != nil {
			return err
		}
		if _, duplicate := seenEndpoint[mirror.EndpointID]; duplicate {
			return errors.New("[Invite] mirror endpoint 重复")
		}
		if _, duplicate := seenURL[mirror.BaseURL]; duplicate {
			return errors.New("[Invite] mirror URL 重复")
		}
		seenEndpoint[mirror.EndpointID], seenURL[mirror.BaseURL] = struct{}{}, struct{}{}
	}
	return nil
}

func validateDistributionMirrorRefs(mirrors []DistributionMirrorRefV1) error {
	return ValidateDistributionMirrorRefs(mirrors)
}

func InviteDescriptorHash(descriptor *InviteBootstrapDescriptorV2, issuerPublicKey ed25519.PublicKey) (string, error) {
	if err := ValidateInviteDescriptor(descriptor, issuerPublicKey); err != nil {
		return "", err
	}
	return HashObject(DomainInviteDescriptor, descriptor)
}

func EnrollmentClaimCoreHash(core *EnrollmentClaimCoreV2) (string, error) {
	if core == nil || core.Schema != 2 || !validIdentifier(core.ClusterID, 128) || !validIdentifier(core.InviteID, 128) ||
		!validIdentifier(core.RequestID, 128) || !oneOf(core.ClientPlatform, "windows-desktop", "android", "linux-server") ||
		core.BaseRecoveryEpoch < 0 || core.BaseControlEpoch < 0 {
		return "", errors.New("[Enrollment] claim core identity/authority 无效")
	}
	for _, hash := range []string{core.CertifiedInviteRecordHash, core.DeviceEnrollmentIntentCommitmentHash,
		core.DeviceEnrollmentIntentOpeningHash, core.AcceptedDeviceEnrollmentIntentHash,
		core.BaseControlSetHash, core.BaseHeadHash} {
		if _, err := ParseHash(hash); err != nil {
			return "", err
		}
	}
	if _, err := decodeRawURL(core.ClientNonce, 32); err != nil {
		return "", errors.New("[Enrollment] client nonce 无效")
	}
	identityDER, err := decodeCanonicalBase64URL(core.DeviceIdentityPublicKey)
	if err != nil || !oneOf(core.DeviceIdentityKeyProfile,
		"p256-android-keystore-sha256-v1", "p256-root-only-pkcs8-sha256-v1", "p256-sha256-v1") {
		return "", errors.New("[Enrollment] identity key/profile 编码无效")
	}
	identity, err := x509.ParsePKIXPublicKey(identityDER)
	identityP256, ok := identity.(*ecdsa.PublicKey)
	if err != nil || !ok || identityP256.Curve != elliptic.P256() || !identityP256.Curve.IsOnCurve(identityP256.X, identityP256.Y) {
		return "", errors.New("[Enrollment] identity key 必须是 P-256 SPKI")
	}
	wrappingDER, err := decodeCanonicalBase64URL(core.WrappingPublicKey)
	if err != nil {
		return "", errors.New("[Enrollment] wrapping public key 编码无效")
	}
	wrapping, err := x509.ParsePKIXPublicKey(wrappingDER)
	if err != nil {
		return "", errors.New("[Enrollment] wrapping public key SPKI 无效")
	}
	switch core.WrappingKeyProfile {
	case "p256-keystore-ecdh-v1", "p256-root-only-pkcs8-ecdh-v1":
		key, ok := wrapping.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() || key.X.Cmp(identityP256.X) == 0 && key.Y.Cmp(identityP256.Y) == 0 {
			return "", errors.New("[Enrollment] P-256 wrapping key 必须独立于 identity key")
		}
	case "rsa2048-keystore-decrypt-v1":
		key, ok := wrapping.(*rsa.PublicKey)
		if !ok || key.N.BitLen() != 2048 || key.E != 65537 {
			return "", errors.New("[Enrollment] RSA wrapping key profile 无效")
		}
	default:
		return "", errors.New("[Enrollment] wrapping key profile 未获协议授权")
	}
	switch core.ClientPlatform {
	case "android":
		if core.DeviceIdentityKeyProfile != "p256-android-keystore-sha256-v1" ||
			!oneOf(core.WrappingKeyProfile, "p256-keystore-ecdh-v1", "rsa2048-keystore-decrypt-v1") {
			return "", errors.New("[Enrollment] Android key profile 未绑定 Keystore")
		}
	case "linux-server":
		if core.DeviceIdentityKeyProfile != "p256-root-only-pkcs8-sha256-v1" || core.WrappingKeyProfile != "p256-root-only-pkcs8-ecdh-v1" {
			return "", errors.New("[Enrollment] Linux 软件 key 降级 profile 未显式声明")
		}
	case "windows-desktop":
		if core.DeviceIdentityKeyProfile != "p256-sha256-v1" {
			return "", errors.New("[Enrollment] Windows identity key profile 无效")
		}
	}
	csrDER, err := decodeCanonicalBase64URL(core.CSRDER)
	if err != nil {
		return "", errors.New("[Enrollment] CSR DER 编码无效")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	var csrKey *ecdsa.PublicKey
	var keyOK bool
	if err == nil {
		csrKey, keyOK = csr.PublicKey.(*ecdsa.PublicKey)
	}
	if err != nil || csr.CheckSignature() != nil || !keyOK || csrKey.Curve != elliptic.P256() ||
		csrKey.X.Cmp(identityP256.X) != 0 || csrKey.Y.Cmp(identityP256.Y) != 0 ||
		csr.Subject.CommonName != core.RequestID || len(csr.Subject.Names) != 1 ||
		len(csr.DNSNames)+len(csr.EmailAddresses)+len(csr.IPAddresses)+len(csr.URIs) != 0 {
		return "", errors.New("[Enrollment] CSR/identity/request_id/SAN binding 无效")
	}
	return HashObject(DomainEnrollmentClaimCore, core)
}

// EnrollmentClaimBinaryHashes 固定 admission/resume 使用的三种二进制摘要。
// 它先复用完整 core 校验，防止调用方对未绑定 CSR 或错误 key profile 求出可用摘要。
func EnrollmentClaimBinaryHashes(core *EnrollmentClaimCoreV2) (identityKeyHash, wrappingKeyHash, csrHash string, err error) {
	if _, err = EnrollmentClaimCoreHash(core); err != nil {
		return "", "", "", err
	}
	identityDER, _ := decodeCanonicalBase64URL(core.DeviceIdentityPublicKey)
	wrappingDER, _ := decodeCanonicalBase64URL(core.WrappingPublicKey)
	csrDER, _ := decodeCanonicalBase64URL(core.CSRDER)
	identityKeyHash, err = HashBytes(DomainEnrollmentIdentitySPKI, identityDER)
	if err != nil {
		return "", "", "", err
	}
	wrappingKeyHash, err = HashBytes(DomainEnrollmentWrappingSPKI, wrappingDER)
	if err != nil {
		return "", "", "", err
	}
	csrHash, err = HashBytes(DomainEnrollmentCSRDER, csrDER)
	return identityKeyHash, wrappingKeyHash, csrHash, err
}

func ValidateEnrollmentClaimResult(result *EnrollmentClaimResultV2) error {
	if result == nil || result.Schema != 2 || !oneOf(result.Status, "reserved", "issued_provisional", "completed") {
		return errors.New("[Enrollment] claim result schema/status 无效")
	}
	if _, err := ParseHash(result.TransactionStateHash); err != nil {
		return err
	}
	completed := result.Status == "completed"
	if completed != (result.ResultArtifactHash != "") || completed != (result.ResultArtifact != nil) ||
		completed != (len(result.CompletionReceipt) != 0) {
		return errors.New("[Enrollment] completed/result artifact tagged union 无效")
	}
	if completed && len(result.ProgressReceipt) != 0 {
		return errors.New("[Enrollment] completed 禁止携 progress receipt")
	}
	if len(result.ProgressReceipt) != 0 {
		canonical, err := CanonicalizeStrict(result.ProgressReceipt)
		if err != nil || !bytes.Equal(canonical, result.ProgressReceipt) ||
			len(result.ProgressReceipt) < 2 || result.ProgressReceipt[0] != '{' ||
			result.ProgressReceipt[len(result.ProgressReceipt)-1] != '}' {
			return errors.New("[Enrollment] progress receipt 必须是 exact canonical object")
		}
	}
	if completed {
		canonical, err := CanonicalizeStrict(result.CompletionReceipt)
		if err != nil || !bytes.Equal(canonical, result.CompletionReceipt) ||
			len(result.CompletionReceipt) < 2 || result.CompletionReceipt[0] != '{' ||
			result.CompletionReceipt[len(result.CompletionReceipt)-1] != '}' {
			return errors.New("[Enrollment] completion receipt 必须是 exact canonical object")
		}
	}
	if result.ResultArtifactHash != "" {
		artifactHash, err := EnrollmentResultArtifactHash(result.ResultArtifact)
		if err != nil || artifactHash != result.ResultArtifactHash {
			return errors.New("[Enrollment] claim result artifact/hash 不匹配")
		}
		if _, err := ParseHash(result.ResultArtifactHash); err != nil {
			return err
		}
	}
	return nil
}

func EnrollmentChallengeHash(challenge *EnrollmentPoPChallengeV1, coreHash string, now time.Time) (string, error) {
	if challenge == nil || challenge.Schema != 1 || !validIdentifier(challenge.ClusterID, 128) ||
		!validIdentifier(challenge.InviteID, 128) || !validIdentifier(challenge.RequestID, 128) ||
		!validIdentifier(challenge.EnrollmentServiceID, 128) || challenge.ClaimCoreHash != coreHash {
		return "", errors.New("[Enrollment] PoP challenge identity/core 无效")
	}
	if _, err := decodeRawURL(challenge.ServerNonce, 32); err != nil {
		return "", errors.New("[Enrollment] server nonce 无效")
	}
	issued, err := ParseTimeZ(challenge.IssuedAt)
	if err != nil {
		return "", err
	}
	expires, err := ParseTimeZ(challenge.ExpiresAt)
	if err != nil || !issued.Before(expires) || now.UTC().Before(issued) || !now.UTC().Before(expires) {
		return "", errors.New("[Enrollment] PoP challenge 已过期或尚未生效")
	}
	return HashObject(DomainEnrollmentPoPChallenge, challenge)
}

func VerifyEnrollmentPoP(body *EnrollmentPoPBodyV2, identityPublicKey ed25519.PublicKey, signature string) error {
	rawSignature, err := decodeRawURL(signature, ed25519.SignatureSize)
	if err != nil {
		return errors.New("[Enrollment] PoP signature 编码无效")
	}
	message, err := EnrollmentPoPMessage(body)
	if err != nil {
		return err
	}
	if !ed25519.Verify(identityPublicKey, message, rawSignature) {
		return errors.New("[Enrollment] detached identity PoP 无效")
	}
	return nil
}

// VerifyEnrollmentPoPP256 验证 Android/Linux P-256 identity 的 SHA256withECDSA
// detached PoP，并只接受规范 DER 与 low-S，防止签名可塑性形成两份 wire 身份。
func VerifyEnrollmentPoPP256(body *EnrollmentPoPBodyV2, identityPublicKey *ecdsa.PublicKey, signature string) error {
	if identityPublicKey == nil || identityPublicKey.Curve != elliptic.P256() || !identityPublicKey.Curve.IsOnCurve(identityPublicKey.X, identityPublicKey.Y) {
		return errors.New("[Enrollment] PoP identity key 不是 P-256")
	}
	rawSignature, err := decodeCanonicalBase64URL(signature)
	if err != nil {
		return errors.New("[Enrollment] PoP signature 编码无效")
	}
	var parsed struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(rawSignature, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil || parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
		return errors.New("[Enrollment] ECDSA PoP DER 无效")
	}
	canonicalDER, err := asn1.Marshal(parsed)
	if err != nil || !bytes.Equal(canonicalDER, rawSignature) || parsed.S.Cmp(new(big.Int).Rsh(new(big.Int).Set(identityPublicKey.Params().N), 1)) > 0 {
		return errors.New("[Enrollment] ECDSA PoP 必须是规范 DER low-S")
	}
	message, err := EnrollmentPoPMessage(body)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(message)
	if !ecdsa.Verify(identityPublicKey, digest[:], parsed.R, parsed.S) {
		return errors.New("[Enrollment] detached identity PoP 无效")
	}
	return nil
}

// SignEnrollmentPoPP256 产生跨平台唯一允许的 canonical DER low-S detached PoP。
func SignEnrollmentPoPP256(body *EnrollmentPoPBodyV2, identityPrivateKey *ecdsa.PrivateKey) (string, error) {
	if identityPrivateKey == nil || identityPrivateKey.Curve != elliptic.P256() {
		return "", errors.New("[Enrollment] PoP identity private key 不是 P-256")
	}
	return SignEnrollmentPoPWithSigner(body, identityPrivateKey)
}

// SignEnrollmentPoPWithSigner 只把 SHA-256 digest 交给平台 signer，并把宿主
// 返回的 ECDSA DER 归一化为协议唯一允许的 low-S 表示。共享 verifier 永远不接收
// Windows CNG/DPAPI、Android Keystore 或其他宿主私钥材料。
func SignEnrollmentPoPWithSigner(body *EnrollmentPoPBodyV2, signer crypto.Signer) (string, error) {
	publicKey, ok := signerPublicP256(signer)
	if !ok {
		return "", errors.New("[Enrollment] PoP signer 不是 P-256")
	}
	message, err := EnrollmentPoPMessage(body)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(message)
	raw, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	var signature struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(raw, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil ||
		signature.R.Sign() <= 0 || signature.S.Sign() <= 0 {
		return "", errors.New("[Enrollment] 平台 signer 返回的 ECDSA DER 无效")
	}
	canonical, err := asn1.Marshal(signature)
	if err != nil || !bytes.Equal(canonical, raw) {
		return "", errors.New("[Enrollment] 平台 signer 返回的 ECDSA DER 非规范")
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(publicKey.Params().N), 1)
	s := new(big.Int).Set(signature.S)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(publicKey.Params().N, s)
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{R: signature.R, S: s})
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(der)
	if err := VerifyEnrollmentPoPP256(body, publicKey, encoded); err != nil {
		return "", err
	}
	return encoded, nil
}

func signerPublicP256(signer crypto.Signer) (*ecdsa.PublicKey, bool) {
	if signer == nil {
		return nil, false
	}
	publicKey, ok := signer.Public().(*ecdsa.PublicKey)
	return publicKey, ok && publicKey != nil && publicKey.Curve == elliptic.P256() &&
		publicKey.X != nil && publicKey.Y != nil &&
		publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y)
}

// EnrollmentPoPMessage 返回交给平台 Keystore callback 的 exact framed bytes；
// callback 只负责签名，不能另行解释或重写 JSON。
func EnrollmentPoPMessage(body *EnrollmentPoPBodyV2) ([]byte, error) {
	if body == nil || body.Schema != 2 || !validIdentifier(body.ClusterID, 128) ||
		!validIdentifier(body.InviteID, 128) || !validIdentifier(body.RequestID, 128) {
		return nil, errors.New("[Enrollment] PoP body 无效")
	}
	for _, hash := range []string{body.ClaimCoreHash, body.TokenCommitment, body.ChallengeHash} {
		if _, err := ParseHash(hash); err != nil {
			return nil, err
		}
	}
	canonical, err := MarshalCanonical(body)
	if err != nil {
		return nil, err
	}
	return Frame(DomainEnrollmentPoPSignature, canonical)
}

// VerifyEnrollmentClaimSubmission 验证 inner-TLS 中的完整一次尝试；challenge/signature 不进入稳定事务 hash。
// caller 还必须用有界 replay cache 原子消费返回的 ChallengeHash。
func VerifyEnrollmentClaimSubmission(submission *EnrollmentClaimSubmissionV2, record *CertifiedInviteRecordV2, policy *InviteIssuancePolicyV2, opening *DeviceEnrollmentIntentOpeningV1, enrollmentServiceID string, now time.Time) (VerifiedEnrollmentClaimV2, error) {
	if submission == nil || submission.Schema != 2 || record == nil || opening == nil || now.IsZero() ||
		!validIdentifier(enrollmentServiceID, 128) {
		return VerifiedEnrollmentClaimV2{}, errors.New("[Enrollment] submission context 无效")
	}
	tokenCommitment, err := TokenCommitment(record.ClusterID, record.InviteID, submission.Token)
	if err != nil || tokenCommitment != record.TokenCommitment {
		return VerifiedEnrollmentClaimV2{}, errors.New("[Enrollment] token commitment 不匹配")
	}
	return verifyEnrollmentAttempt(&submission.ClaimCore, &submission.Challenge, &submission.PoPBody,
		submission.ProofSignature, record, policy, opening, enrollmentServiceID, now, tokenCommitment)
}

// VerifyEnrollmentResumeSubmission 验证无 token 的恢复尝试。capability binding 必须先由
// caller 完整验签；本函数再把 fresh PoP、原 core/key/CSR 与该 exact binding 合并验证。
func VerifyEnrollmentResumeSubmission(submission *EnrollmentResumeSubmissionV1,
	binding *BootstrapCapabilityResumeBindingV1, record *CertifiedInviteRecordV2,
	policy *InviteIssuancePolicyV2, opening *DeviceEnrollmentIntentOpeningV1,
	enrollmentServiceID string, now time.Time) (VerifiedEnrollmentClaimV2, error) {
	if submission == nil || submission.Schema != 1 || binding == nil || record == nil || opening == nil ||
		now.IsZero() || !validIdentifier(enrollmentServiceID, 128) {
		return VerifiedEnrollmentClaimV2{}, errors.New("[resume] submission context 无效")
	}
	verified, err := verifyEnrollmentAttempt(&submission.ClaimCore, &submission.Challenge,
		&submission.PoPBody, submission.ProofSignature, record, policy, opening,
		enrollmentServiceID, now, record.TokenCommitment)
	if err != nil {
		return VerifiedEnrollmentClaimV2{}, err
	}
	for _, hash := range []string{binding.ClaimOperationHash, binding.AdmissionQCHash,
		binding.EnrollmentTransactionStateHash} {
		if _, err := ParseHash(hash); err != nil {
			return VerifiedEnrollmentClaimV2{}, err
		}
	}
	if binding.RequestID != submission.ClaimCore.RequestID ||
		binding.ClaimCoreHash != verified.ClaimCoreHash() || binding.CSRHash != verified.CSRHash() ||
		binding.IdentityKeyHash != verified.IdentityKeyHash() ||
		binding.WrappingKeyHash != verified.WrappingKeyHash() {
		return VerifiedEnrollmentClaimV2{}, errors.New("[resume] submission 与 exact committed binding 不匹配")
	}
	return verified, nil
}

func verifyEnrollmentAttempt(core *EnrollmentClaimCoreV2, challenge *EnrollmentPoPChallengeV1,
	pop *EnrollmentPoPBodyV2, proofSignature string, record *CertifiedInviteRecordV2,
	policy *InviteIssuancePolicyV2, opening *DeviceEnrollmentIntentOpeningV1,
	enrollmentServiceID string, now time.Time, tokenCommitment string) (VerifiedEnrollmentClaimV2, error) {
	if core == nil || challenge == nil || pop == nil || tokenCommitment != record.TokenCommitment {
		return VerifiedEnrollmentClaimV2{}, errors.New("[Enrollment] attempt/token commitment context 无效")
	}
	recordHash, err := CertifiedInviteRecordHash(record, policy)
	if err != nil {
		return VerifiedEnrollmentClaimV2{}, err
	}
	intentHash, err := EnrollmentIntentHash(&opening.DeviceEnrollmentIntent)
	if err != nil {
		return VerifiedEnrollmentClaimV2{}, err
	}
	openingHash, err := IntentOpeningHash(opening)
	if err != nil {
		return VerifiedEnrollmentClaimV2{}, err
	}
	commitment := DeviceEnrollmentIntentCommitmentV1{Schema: 1, ClusterID: opening.ClusterID, InviteID: opening.InviteID, OpeningHash: openingHash}
	commitmentHash, err := HashObject(DomainEnrollmentIntentCommitment, commitment)
	if err != nil || commitmentHash != record.DeviceEnrollmentIntentCommitmentHash {
		return VerifiedEnrollmentClaimV2{}, errors.New("[Enrollment] private opening 与 public commitment 不匹配")
	}
	coreHash, err := EnrollmentClaimCoreHash(core)
	if err != nil {
		return VerifiedEnrollmentClaimV2{}, err
	}
	if core.ClusterID != record.ClusterID || core.InviteID != record.InviteID ||
		core.CertifiedInviteRecordHash != recordHash ||
		core.DeviceEnrollmentIntentCommitmentHash != commitmentHash ||
		core.DeviceEnrollmentIntentOpeningHash != openingHash || core.AcceptedDeviceEnrollmentIntentHash != intentHash ||
		core.ClientPlatform != opening.DeviceEnrollmentIntent.Platform ||
		!contains(opening.DeviceEnrollmentIntent.WrappingKeyProfiles, core.WrappingKeyProfile) {
		return VerifiedEnrollmentClaimV2{}, errors.New("[Enrollment] stable claim core 与 record/opening/platform 不匹配")
	}
	if challenge.ClusterID != core.ClusterID || challenge.InviteID != core.InviteID || challenge.RequestID != core.RequestID ||
		challenge.EnrollmentServiceID != enrollmentServiceID {
		return VerifiedEnrollmentClaimV2{}, errors.New("[Enrollment] challenge 与 claim/service identity 不匹配")
	}
	challengeHash, err := EnrollmentChallengeHash(challenge, coreHash, now)
	if err != nil {
		return VerifiedEnrollmentClaimV2{}, err
	}
	if pop.ClusterID != core.ClusterID || pop.InviteID != core.InviteID || pop.RequestID != core.RequestID ||
		pop.ClaimCoreHash != coreHash || pop.TokenCommitment != tokenCommitment || pop.ChallengeHash != challengeHash {
		return VerifiedEnrollmentClaimV2{}, errors.New("[Enrollment] PoP body 与 core/token/challenge 不匹配")
	}
	identityDER, err := decodeCanonicalBase64URL(core.DeviceIdentityPublicKey)
	if err != nil {
		return VerifiedEnrollmentClaimV2{}, err
	}
	parsedIdentity, err := x509.ParsePKIXPublicKey(identityDER)
	identityKey, ok := parsedIdentity.(*ecdsa.PublicKey)
	if err != nil || !ok {
		return VerifiedEnrollmentClaimV2{}, errors.New("[Enrollment] identity SPKI 不是 P-256")
	}
	if err := VerifyEnrollmentPoPP256(pop, identityKey, proofSignature); err != nil {
		return VerifiedEnrollmentClaimV2{}, err
	}
	identityKeyHash, wrappingKeyHash, csrHash, err := EnrollmentClaimBinaryHashes(core)
	if err != nil {
		return VerifiedEnrollmentClaimV2{}, err
	}
	return VerifiedEnrollmentClaimV2{
		claimCoreHash: coreHash, challengeHash: challengeHash, intentHash: intentHash,
		openingHash: openingHash, commitmentHash: commitmentHash, tokenCommitment: tokenCommitment,
		identityKeyHash: identityKeyHash, wrappingKeyHash: wrappingKeyHash, csrHash: csrHash,
	}, nil
}

func decodeCanonicalBase64URL(value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, errors.New("必须是规范无 padding base64url")
	}
	return raw, nil
}

func SignBootstrapCapability(body BootstrapTunnelCapabilityBodyV1, privateKey ed25519.PrivateKey) (BootstrapTunnelCapabilityV1, error) {
	identifier, err := CapabilityID(&body)
	if err != nil {
		return BootstrapTunnelCapabilityV1{}, err
	}
	public := privateKey.Public().(ed25519.PublicKey)
	keyID, _ := ControlKeyID(public)
	if keyID != body.IssuerKeyID {
		return BootstrapTunnelCapabilityV1{}, errors.New("[capability] issuer private key 与 body 不匹配")
	}
	canonical, _ := MarshalCanonical(body)
	message, _ := Frame(DomainBootstrapCapabilitySignature, canonical)
	return BootstrapTunnelCapabilityV1{
		Body: body, CapabilityID: identifier,
		Signature: BootstrapIssuerSignatureV1{Algorithm: "ed25519", KeyID: keyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))},
	}, nil
}

func HashRaw(domain string, value []byte) string {
	framed, _ := Frame(domain, value)
	sum := sha256.Sum256(framed)
	return "sha256:" + fmt.Sprintf("%x", sum[:])
}

func CanonicalSortHashes(values []string) error {
	if !sort.StringsAreSorted(values) {
		return errors.New("[wire] hash 数组未排序")
	}
	for i, value := range values {
		if i > 0 && values[i-1] == value {
			return errors.New("[wire] hash 数组重复")
		}
		if _, err := ParseHash(value); err != nil {
			return err
		}
	}
	return nil
}

func EqualCanonical(left, right any) bool {
	a, errA := MarshalCanonical(left)
	b, errB := MarshalCanonical(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}
