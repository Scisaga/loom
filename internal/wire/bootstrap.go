package wire

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"time"
)

const (
	DomainInviteIssuancePolicy             = "loom-invite-issuance-policy-v2"
	DomainCertifiedInviteRecord            = "loom-certified-invite-record-v2"
	DomainBootstrapEndpointCatalog         = "loom-bootstrap-endpoint-catalog-v1"
	DomainBootstrapIssuerAuthorization     = "loom-bootstrap-issuer-authorization-v1"
	DomainBootstrapIssuerAuthorizationLeaf = "loom-bootstrap-issuer-authorization-leaf-v1"
	DomainEnrollmentPreflightRequest       = "loom-enrollment-intent-preflight-request-v1"
)

type InviteIssuancePolicyV2 struct {
	Schema                             int      `json:"schema"`
	ClusterID                          string   `json:"cluster_id"`
	PolicyID                           string   `json:"policy_id"`
	Generation                         int64    `json:"generation"`
	MinimumTTLSeconds                  int64    `json:"minimum_ttl_seconds"`
	MaximumTTLSeconds                  int64    `json:"maximum_ttl_seconds"`
	MaximumDescriptorBytes             int64    `json:"maximum_descriptor_bytes"`
	MaximumIntentOpeningBytes          int64    `json:"maximum_intent_opening_bytes"`
	MinimumDistributionMirrors         int64    `json:"minimum_distribution_mirrors"`
	MaximumDistributionMirrors         int64    `json:"maximum_distribution_mirrors"`
	AllowedBootstrapTransports         []string `json:"allowed_bootstrap_transports"`
	MaximumInitialCapabilityTTLSeconds int64    `json:"maximum_initial_capability_ttl_seconds"`
	MaximumResumeCapabilityTTLSeconds  int64    `json:"maximum_resume_capability_ttl_seconds"`
	MaximumReservationRetrySeconds     int64    `json:"maximum_reservation_retry_seconds"`
	BootstrapSessionSeconds            int64    `json:"bootstrap_session_seconds"`
	BootstrapTotalBytes                int64    `json:"bootstrap_total_bytes"`
	BootstrapConnectionAttempts        int64    `json:"bootstrap_connection_attempts"`
	BootstrapMaxConcurrentSessions     int64    `json:"bootstrap_max_concurrent_sessions"`
}

type CertifiedInviteRecordV2 struct {
	Schema                               int    `json:"schema"`
	ClusterID                            string `json:"cluster_id"`
	InviteID                             string `json:"invite_id"`
	Generation                           int64  `json:"generation"`
	IssuedAt                             string `json:"issued_at"`
	ExpiresAt                            string `json:"expires_at"`
	DeviceEnrollmentIntentCommitmentHash string `json:"device_enrollment_intent_commitment_hash"`
	TokenCommitment                      string `json:"token_commitment"`
	TokenArtifactBindingHash             string `json:"token_artifact_binding_hash"`
	InviteIssuancePolicyHash             string `json:"invite_issuance_policy_hash"`
	BootstrapIssuerAuthorizationHash     string `json:"bootstrap_issuer_authorization_hash"`
	BootstrapIssuerRegistryRoot          string `json:"bootstrap_issuer_registry_root"`
	BootstrapCatalogHash                 string `json:"bootstrap_catalog_hash"`
	EnrollmentServiceRefHash             string `json:"enrollment_service_ref_hash"`
	OperationID                          string `json:"operation_id"`
	ParentHeadHash                       string `json:"parent_head_hash"`
}

type BootstrapEndpointCatalogV1 struct {
	Schema                  int                           `json:"schema"`
	ClusterID               string                        `json:"cluster_id"`
	CatalogGeneration       int64                         `json:"catalog_generation"`
	ValidFrom               string                        `json:"valid_from"`
	ValidUntil              string                        `json:"valid_until"`
	BootstrapIngressSet     BootstrapIngressEndpointSetV1 `json:"bootstrap_ingress_set"`
	BootstrapIngressSetHash string                        `json:"bootstrap_ingress_set_hash"`
	RequiredClientProtocol  int64                         `json:"required_client_protocol"`
	ParentHeadHash          string                        `json:"parent_head_hash"`
	ConfigQCHash            string                        `json:"config_qc_hash"`
}

type BootstrapIssuerAuthorizationActiveV1 struct {
	IssuerEpoch                 int64    `json:"issuer_epoch"`
	IssuerKeyID                 string   `json:"issuer_key_id"`
	IssuerPublicKey             string   `json:"issuer_public_key"`
	InviteIssuancePolicyHash    string   `json:"invite_issuance_policy_hash"`
	ValidFrom                   string   `json:"valid_from"`
	ValidUntil                  string   `json:"valid_until"`
	MaximumCapabilityTTLSeconds int64    `json:"maximum_capability_ttl_seconds"`
	MaximumConnectionAttempts   int64    `json:"maximum_connection_attempts"`
	MaximumConcurrentSessions   int64    `json:"maximum_concurrent_sessions"`
	MaximumSessionSeconds       int64    `json:"maximum_session_seconds"`
	MaximumTotalBytes           int64    `json:"maximum_total_bytes"`
	PermittedIngressSetHashes   []string `json:"permitted_ingress_set_hashes"`
	PermittedServiceIDs         []string `json:"permitted_service_ids"`
	PermittedModes              []string `json:"permitted_modes"`
}

type BootstrapIssuerAuthorizationRevocationV1 struct {
	RevokedAuthorizationHash string `json:"revoked_authorization_hash"`
	EffectiveAt              string `json:"effective_at"`
	Reason                   string `json:"reason"`
}

type BootstrapIssuerAuthorizationV1 struct {
	Schema                    int                                       `json:"schema"`
	ClusterID                 string                                    `json:"cluster_id"`
	AuthorizationID           string                                    `json:"authorization_id"`
	Generation                int64                                     `json:"generation"`
	Status                    string                                    `json:"status"`
	PreviousAuthorizationHash string                                    `json:"previous_authorization_hash,omitempty"`
	Active                    *BootstrapIssuerAuthorizationActiveV1     `json:"active,omitempty"`
	Revocation                *BootstrapIssuerAuthorizationRevocationV1 `json:"revocation,omitempty"`
	ParentHeadHash            string                                    `json:"parent_head_hash"`
}

type BootstrapIssuerAuthorizationLeafV1 struct {
	Schema            int    `json:"schema"`
	AuthorizationID   string `json:"authorization_id"`
	Generation        int64  `json:"generation"`
	AuthorizationHash string `json:"authorization_hash"`
}

type BootstrapIssuerAuthorizationProofV1 struct {
	Schema            int                                `json:"schema"`
	ClusterID         string                             `json:"cluster_id"`
	Authorization     BootstrapIssuerAuthorizationV1     `json:"authorization"`
	AuthorizationHash string                             `json:"authorization_hash"`
	Leaf              BootstrapIssuerAuthorizationLeafV1 `json:"leaf"`
	LeafIndex         int64                              `json:"leaf_index"`
	RegistryTreeSize  int64                              `json:"registry_tree_size"`
	RegistryAuditPath []string                           `json:"registry_audit_path"`
	RegistryRoot      string                             `json:"registry_root"`
}

type EnrollmentIntentPreflightRequestV1 struct {
	Schema                    int    `json:"schema"`
	ClusterID                 string `json:"cluster_id"`
	InviteID                  string `json:"invite_id"`
	CertifiedInviteRecordHash string `json:"certified_invite_record_hash"`
	CapabilityID              string `json:"capability_id"`
}

type EnrollmentIntentPreflightResponseV1 struct {
	Schema                           int                                `json:"schema"`
	ClusterID                        string                             `json:"cluster_id"`
	InviteID                         string                             `json:"invite_id"`
	RequestHash                      string                             `json:"request_hash"`
	DeviceEnrollmentIntentCommitment DeviceEnrollmentIntentCommitmentV1 `json:"device_enrollment_intent_commitment"`
	DeviceEnrollmentIntentOpening    DeviceEnrollmentIntentOpeningV1    `json:"device_enrollment_intent_opening"`
}

// VerifiedBootstrapCapabilityV1 只由完整 issuer registry/policy/time 验证产生；
// ingress runtime 不接受调用方自行声明 capability 已验证（D115、D131）。
type VerifiedBootstrapCapabilityV1 struct {
	body                BootstrapTunnelCapabilityBodyV1
	capabilityID        string
	transportCredential string
}

func (verified VerifiedBootstrapCapabilityV1) Body() BootstrapTunnelCapabilityBodyV1 {
	body := verified.body
	if body.ResumeBinding != nil {
		binding := *body.ResumeBinding
		body.ResumeBinding = &binding
	}
	return body
}

func (verified VerifiedBootstrapCapabilityV1) CapabilityID() string {
	return verified.capabilityID
}

// TransportCredential 只存在于完整 capability authorization 验证后的 evidence 中。
// HY2 直接使用该短期 bearer；Trojan 再按其协议做 SHA-224。它与 Enrollment token
// 完全无关，不能从 capability ID 或 public catalog 单独恢复（D115、D131）。
func (verified VerifiedBootstrapCapabilityV1) TransportCredential() string {
	return verified.transportCredential
}

// String/GoString 防止把 opaque evidence 直接交给日志格式化时泄露短期 bearer。
func (verified VerifiedBootstrapCapabilityV1) String() string {
	return fmt.Sprintf("VerifiedBootstrapCapabilityV1{capability_id:%q}", verified.capabilityID)
}

func (verified VerifiedBootstrapCapabilityV1) GoString() string {
	return verified.String()
}

func ValidateInviteIssuancePolicy(policy *InviteIssuancePolicyV2) error {
	if policy == nil || policy.Schema != 2 || !validIdentifier(policy.ClusterID, 128) ||
		!validIdentifier(policy.PolicyID, 128) || policy.Generation < 1 ||
		policy.MinimumTTLSeconds < 1 || policy.MaximumTTLSeconds < policy.MinimumTTLSeconds || policy.MaximumTTLSeconds > 1800 ||
		policy.MaximumDescriptorBytes < 1 || policy.MaximumDescriptorBytes > 1<<20 ||
		policy.MaximumIntentOpeningBytes < 1 || policy.MaximumIntentOpeningBytes > 1<<20 ||
		policy.MinimumDistributionMirrors != 2 || policy.MaximumDistributionMirrors != 3 ||
		!sortedEnum(policy.AllowedBootstrapTransports, []string{"hysteria2", "trojan_tls"}, true) ||
		policy.MaximumInitialCapabilityTTLSeconds < 300 || policy.MaximumInitialCapabilityTTLSeconds > 1800 ||
		policy.MaximumResumeCapabilityTTLSeconds < 300 || policy.MaximumResumeCapabilityTTLSeconds > 1800 ||
		policy.MaximumReservationRetrySeconds < 1 || policy.MaximumReservationRetrySeconds > 86400 ||
		policy.BootstrapSessionSeconds < 1 || policy.BootstrapSessionSeconds > 300 ||
		policy.BootstrapTotalBytes < 1 || policy.BootstrapConnectionAttempts < 1 ||
		policy.BootstrapMaxConcurrentSessions != 1 {
		return errors.New("[D131 Invite policy] policy bounds/schema 无效")
	}
	return nil
}

func InviteIssuancePolicyHash(policy *InviteIssuancePolicyV2) (string, error) {
	if err := ValidateInviteIssuancePolicy(policy); err != nil {
		return "", err
	}
	return HashObject(DomainInviteIssuancePolicy, policy)
}

func ValidateCertifiedInviteRecord(record *CertifiedInviteRecordV2, policy *InviteIssuancePolicyV2) error {
	if record == nil || policy == nil || record.Schema != 2 || record.ClusterID != policy.ClusterID ||
		!validIdentifier(record.InviteID, 128) || !validIdentifier(record.OperationID, 128) || record.Generation < 1 {
		return errors.New("[D114 Invite] certified record identity 无效")
	}
	policyHash, err := InviteIssuancePolicyHash(policy)
	if err != nil || policyHash != record.InviteIssuancePolicyHash {
		return errors.New("[D114 Invite] certified record policy hash 不匹配")
	}
	for _, hash := range []string{record.DeviceEnrollmentIntentCommitmentHash, record.TokenCommitment,
		record.TokenArtifactBindingHash, record.BootstrapIssuerAuthorizationHash, record.BootstrapIssuerRegistryRoot,
		record.BootstrapCatalogHash, record.EnrollmentServiceRefHash, record.ParentHeadHash} {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	issued, err := ParseTimeZ(record.IssuedAt)
	if err != nil {
		return err
	}
	expires, err := ParseTimeZ(record.ExpiresAt)
	if err != nil || !issued.Before(expires) {
		return errors.New("[D114 Invite] certified record validity 无效")
	}
	ttl := int64(expires.Sub(issued) / time.Second)
	if ttl < policy.MinimumTTLSeconds || ttl > policy.MaximumTTLSeconds {
		return errors.New("[D114 Invite] Invite TTL 超出 certified policy")
	}
	return nil
}

func CertifiedInviteRecordHash(record *CertifiedInviteRecordV2, policy *InviteIssuancePolicyV2) (string, error) {
	if err := ValidateCertifiedInviteRecord(record, policy); err != nil {
		return "", err
	}
	return HashObject(DomainCertifiedInviteRecord, record)
}

func ValidateBootstrapEndpointCatalog(catalog *BootstrapEndpointCatalogV1) error {
	if catalog == nil || catalog.Schema != 1 || !validIdentifier(catalog.ClusterID, 128) ||
		catalog.CatalogGeneration < 1 || catalog.RequiredClientProtocol < 2 ||
		catalog.ClusterID != catalog.BootstrapIngressSet.ClusterID || catalog.ParentHeadHash != catalog.BootstrapIngressSet.ParentHeadHash {
		return errors.New("[D131 bootstrap catalog] header/set identity 无效")
	}
	if err := ValidateBootstrapIngressSet(&catalog.BootstrapIngressSet); err != nil {
		return err
	}
	from, err := ParseTimeZ(catalog.ValidFrom)
	if err != nil {
		return err
	}
	until, err := ParseTimeZ(catalog.ValidUntil)
	if err != nil || !from.Before(until) {
		return errors.New("[D131 bootstrap catalog] validity 无效")
	}
	setFrom, _ := ParseTimeZ(catalog.BootstrapIngressSet.ValidFrom)
	setUntil, _ := ParseTimeZ(catalog.BootstrapIngressSet.ValidUntil)
	if from.Before(setFrom) || until.After(setUntil) {
		return errors.New("[D131 bootstrap catalog] catalog validity 超出 ingress set")
	}
	setHash, err := BootstrapIngressSetHash(&catalog.BootstrapIngressSet)
	if err != nil || setHash != catalog.BootstrapIngressSetHash {
		return errors.New("[D131 bootstrap catalog] ingress set hash 不匹配")
	}
	qcHash, err := ConfigQCHash(catalog.BootstrapIngressSet.ConfigQC)
	if err != nil || qcHash != catalog.ConfigQCHash {
		return errors.New("[D131 bootstrap catalog] config QC hash 不匹配")
	}
	return nil
}

func BootstrapEndpointCatalogHash(catalog *BootstrapEndpointCatalogV1) (string, error) {
	if err := ValidateBootstrapEndpointCatalog(catalog); err != nil {
		return "", err
	}
	return HashObject(DomainBootstrapEndpointCatalog, catalog)
}

func ValidateBootstrapEndpointCatalogAt(catalog *BootstrapEndpointCatalogV1, now time.Time, clientProtocol int64) error {
	if err := ValidateBootstrapEndpointCatalog(catalog); err != nil {
		return err
	}
	if now.IsZero() || clientProtocol < catalog.RequiredClientProtocol {
		return errors.New("[D131 bootstrap catalog] 可信时间/client protocol 无效")
	}
	from, _ := ParseTimeZ(catalog.ValidFrom)
	until, _ := ParseTimeZ(catalog.ValidUntil)
	instant := now.UTC()
	if instant.Before(from) || !instant.Before(until) {
		return errors.New("[D131 bootstrap catalog] catalog 已过期或尚未生效")
	}
	return nil
}

func BootstrapIssuerAuthorizationHash(authorization *BootstrapIssuerAuthorizationV1) (string, error) {
	if err := ValidateBootstrapIssuerAuthorization(authorization); err != nil {
		return "", err
	}
	return HashObject(DomainBootstrapIssuerAuthorization, authorization)
}

func ValidateBootstrapIssuerAuthorization(authorization *BootstrapIssuerAuthorizationV1) error {
	if authorization == nil || authorization.Schema != 1 || !validIdentifier(authorization.ClusterID, 128) ||
		!validIdentifier(authorization.AuthorizationID, 128) || authorization.Generation < 1 ||
		!oneOf(authorization.Status, "active", "revoked") {
		return errors.New("[D131 bootstrap issuer] authorization header 无效")
	}
	if _, err := ParseHash(authorization.ParentHeadHash); err != nil {
		return err
	}
	if (authorization.Generation == 1) != (authorization.PreviousAuthorizationHash == "") {
		return errors.New("[D131 bootstrap issuer] previous hash/generation 不一致")
	}
	if authorization.PreviousAuthorizationHash != "" {
		if _, err := ParseHash(authorization.PreviousAuthorizationHash); err != nil {
			return err
		}
	}
	if authorization.Status == "active" {
		if authorization.Active == nil || authorization.Revocation != nil {
			return errors.New("[D131 bootstrap issuer] active tagged union 无效")
		}
		active := authorization.Active
		publicKey, err := decodeRawURL(active.IssuerPublicKey, ed25519.PublicKeySize)
		keyID, keyErr := ControlKeyID(publicKey)
		if err != nil || keyErr != nil || keyID != active.IssuerKeyID || active.IssuerEpoch < 0 ||
			active.MaximumCapabilityTTLSeconds < 1 || active.MaximumCapabilityTTLSeconds > 1800 ||
			active.MaximumConnectionAttempts < 1 || active.MaximumConcurrentSessions != 1 ||
			active.MaximumSessionSeconds < 1 || active.MaximumSessionSeconds > 300 || active.MaximumTotalBytes < 1 ||
			!sortedUnique(active.PermittedIngressSetHashes) || len(active.PermittedIngressSetHashes) == 0 ||
			!sortedUnique(active.PermittedServiceIDs) || len(active.PermittedServiceIDs) == 0 ||
			!sortedEnum(active.PermittedModes, []string{"initial_claim", "resume_committed_claim"}, true) {
			return errors.New("[D131 bootstrap issuer] active key/scope/limits 无效")
		}
		for _, hash := range append([]string{active.InviteIssuancePolicyHash}, active.PermittedIngressSetHashes...) {
			if _, err := ParseHash(hash); err != nil {
				return err
			}
		}
		from, err := ParseTimeZ(active.ValidFrom)
		if err != nil {
			return err
		}
		until, err := ParseTimeZ(active.ValidUntil)
		if err != nil || !from.Before(until) {
			return errors.New("[D131 bootstrap issuer] active validity 无效")
		}
		return nil
	}
	if authorization.Active != nil || authorization.Revocation == nil || authorization.Generation == 1 ||
		authorization.Revocation.Reason == "" {
		return errors.New("[D131 bootstrap issuer] revocation tagged union 无效")
	}
	if _, err := ParseHash(authorization.Revocation.RevokedAuthorizationHash); err != nil {
		return err
	}
	_, err := ParseTimeZ(authorization.Revocation.EffectiveAt)
	return err
}

func ValidateBootstrapIssuerAuthorizationSuccessor(previous, next *BootstrapIssuerAuthorizationV1) error {
	if err := ValidateBootstrapIssuerAuthorization(previous); err != nil {
		return err
	}
	if err := ValidateBootstrapIssuerAuthorization(next); err != nil {
		return err
	}
	previousHash, _ := BootstrapIssuerAuthorizationHash(previous)
	if next.ClusterID != previous.ClusterID || next.AuthorizationID != previous.AuthorizationID ||
		next.Generation != previous.Generation+1 || next.PreviousAuthorizationHash != previousHash ||
		previous.Status == "revoked" {
		return errors.New("[D131 bootstrap issuer] authorization lineage 断裂或 revoked 后仍有后代")
	}
	if next.Status == "revoked" && next.Revocation.RevokedAuthorizationHash != previousHash {
		return errors.New("[D131 bootstrap issuer] revocation 未指向最近 active authorization")
	}
	return nil
}

func VerifyBootstrapIssuerAuthorizationProof(proof *BootstrapIssuerAuthorizationProofV1, trustedTime time.Time) error {
	if proof == nil || proof.Schema != 1 || proof.ClusterID != proof.Authorization.ClusterID || trustedTime.IsZero() {
		return errors.New("[D131 bootstrap issuer] proof header/可信时间无效")
	}
	authorizationHash, err := BootstrapIssuerAuthorizationHash(&proof.Authorization)
	if err != nil || authorizationHash != proof.AuthorizationHash || proof.Authorization.Status != "active" {
		return errors.New("[D131 bootstrap issuer] proof authorization hash/status 无效")
	}
	if proof.Leaf.Schema != 1 || proof.Leaf.AuthorizationID != proof.Authorization.AuthorizationID ||
		proof.Leaf.Generation != proof.Authorization.Generation || proof.Leaf.AuthorizationHash != authorizationHash {
		return errors.New("[D131 bootstrap issuer] registry leaf binding 无效")
	}
	root, err := ParseHash(proof.RegistryRoot)
	if err != nil {
		return err
	}
	canonicalLeaf, _ := MarshalCanonical(proof.Leaf)
	path := make([][]byte, len(proof.RegistryAuditPath))
	for i, hash := range proof.RegistryAuditPath {
		path[i], err = ParseHash(hash)
		if err != nil {
			return err
		}
	}
	if err := VerifyMerkleInclusion(canonicalLeaf, proof.LeafIndex, proof.RegistryTreeSize, path, root); err != nil {
		return err
	}
	active := proof.Authorization.Active
	from, _ := ParseTimeZ(active.ValidFrom)
	until, _ := ParseTimeZ(active.ValidUntil)
	instant := trustedTime.UTC()
	if instant.Before(from) || !instant.Before(until) {
		return errors.New("[D131 bootstrap issuer] issuer authorization 已过期或尚未生效")
	}
	return nil
}

func VerifyCapabilityAuthorization(capability *BootstrapTunnelCapabilityV1, proof *BootstrapIssuerAuthorizationProofV1, policy *InviteIssuancePolicyV2, trustedTime time.Time) error {
	if err := VerifyBootstrapIssuerAuthorizationProof(proof, trustedTime); err != nil {
		return err
	}
	policyHash, err := InviteIssuancePolicyHash(policy)
	if err != nil {
		return err
	}
	active := proof.Authorization.Active
	publicKey, _ := decodeRawURL(active.IssuerPublicKey, ed25519.PublicKeySize)
	if err := VerifyBootstrapCapability(capability, ed25519.PublicKey(publicKey)); err != nil {
		return err
	}
	body := &capability.Body
	if body.ClusterID != proof.ClusterID || body.BootstrapIssuerAuthorizationHash != proof.AuthorizationHash ||
		body.BootstrapIssuerRegistryRoot != proof.RegistryRoot || body.InviteIssuancePolicyHash != policyHash ||
		active.InviteIssuancePolicyHash != policyHash || body.IssuerEpoch != active.IssuerEpoch ||
		body.IssuerKeyID != active.IssuerKeyID || !contains(active.PermittedIngressSetHashes, body.AllowedIngressSetHash) ||
		!contains(active.PermittedServiceIDs, body.AllowedServiceID) || !contains(active.PermittedModes, body.Mode) {
		return errors.New("[D131 capability] issuer authorization exact binding/scope 无效")
	}
	issued, _ := ParseTimeZ(body.IssuedAt)
	notBefore, _ := ParseTimeZ(body.NotBefore)
	expires, _ := ParseTimeZ(body.ExpiresAt)
	ttl := int64(expires.Sub(issued) / time.Second)
	modeTTL := policy.MaximumInitialCapabilityTTLSeconds
	if body.Mode == "resume_committed_claim" {
		modeTTL = policy.MaximumResumeCapabilityTTLSeconds
	}
	if ttl > active.MaximumCapabilityTTLSeconds || ttl > modeTTL ||
		body.MaximumConnectionAttempts > active.MaximumConnectionAttempts || body.MaximumConnectionAttempts > policy.BootstrapConnectionAttempts ||
		body.MaximumConcurrentSessions > active.MaximumConcurrentSessions || body.MaximumConcurrentSessions > policy.BootstrapMaxConcurrentSessions ||
		body.MaximumSessionSeconds > active.MaximumSessionSeconds || body.MaximumSessionSeconds > policy.BootstrapSessionSeconds ||
		body.MaximumTotalBytes > active.MaximumTotalBytes || body.MaximumTotalBytes > policy.BootstrapTotalBytes {
		return errors.New("[D131 capability] capability 超出 issuer/policy 限额")
	}
	instant := trustedTime.UTC()
	if instant.Before(notBefore) || !instant.Before(expires) {
		return errors.New("[D131 capability] capability 已过期或尚未生效")
	}
	authorizationFrom, _ := ParseTimeZ(active.ValidFrom)
	authorizationUntil, _ := ParseTimeZ(active.ValidUntil)
	if issued.Before(authorizationFrom) || expires.After(authorizationUntil) {
		return errors.New("[D131 capability] capability validity 超出 issuer authorization")
	}
	return nil
}

func VerifyCapabilityAuthorizationEvidence(capability *BootstrapTunnelCapabilityV1,
	proof *BootstrapIssuerAuthorizationProofV1, policy *InviteIssuancePolicyV2,
	trustedTime time.Time) (VerifiedBootstrapCapabilityV1, error) {
	if err := VerifyCapabilityAuthorization(capability, proof, policy, trustedTime); err != nil {
		return VerifiedBootstrapCapabilityV1{}, err
	}
	body := capability.Body
	if body.ResumeBinding != nil {
		binding := *body.ResumeBinding
		body.ResumeBinding = &binding
	}
	credential, err := HashObject(DomainBootstrapTransportCredential, capability)
	if err != nil {
		return VerifiedBootstrapCapabilityV1{}, err
	}
	return VerifiedBootstrapCapabilityV1{body: body, capabilityID: capability.CapabilityID,
		transportCredential: credential}, nil
}

// VerifyInviteDescriptorBindings 把 QR、certified record、policy、public commitment 与 issuer proof
// 合成一个不可拆分的校验步骤；record 的 operation inclusion/head QC 由 proof-bundle 的上一层验证。
func VerifyInviteDescriptorBindings(descriptor *InviteBootstrapDescriptorV2, record *CertifiedInviteRecordV2, policy *InviteIssuancePolicyV2, commitment *DeviceEnrollmentIntentCommitmentV1, proof *BootstrapIssuerAuthorizationProofV1, trustedTime time.Time) error {
	if descriptor == nil || record == nil || commitment == nil || proof == nil {
		return errors.New("[D115 Invite] descriptor binding 输入不完整")
	}
	if err := VerifyCapabilityAuthorization(&descriptor.BootstrapTunnelCapability, proof, policy, trustedTime); err != nil {
		return err
	}
	publicKey, _ := decodeRawURL(proof.Authorization.Active.IssuerPublicKey, ed25519.PublicKeySize)
	if err := ValidateInviteDescriptor(descriptor, ed25519.PublicKey(publicKey)); err != nil {
		return err
	}
	canonicalDescriptor, err := MarshalCanonical(descriptor)
	if err != nil || int64(len(canonicalDescriptor)) > policy.MaximumDescriptorBytes {
		return errors.New("[D115 Invite] descriptor 超出 certified policy 大小上限")
	}
	recordHash, err := CertifiedInviteRecordHash(record, policy)
	if err != nil {
		return err
	}
	commitmentHash, err := HashObject(DomainEnrollmentIntentCommitment, commitment)
	if err != nil {
		return err
	}
	serviceHash, _ := PrivateEnrollmentServiceRefHash(&descriptor.EnrollmentServiceRef)
	body := &descriptor.BootstrapTunnelCapability.Body
	if descriptor.ClusterID != record.ClusterID || descriptor.InviteID != record.InviteID ||
		descriptor.ExpiresAt != record.ExpiresAt || descriptor.TokenCommitment != record.TokenCommitment ||
		descriptor.BootstrapCatalogHash != record.BootstrapCatalogHash || serviceHash != record.EnrollmentServiceRefHash ||
		commitment.Schema != 1 || commitment.ClusterID != record.ClusterID || commitment.InviteID != record.InviteID ||
		commitmentHash != record.DeviceEnrollmentIntentCommitmentHash || proof.AuthorizationHash != record.BootstrapIssuerAuthorizationHash ||
		proof.RegistryRoot != record.BootstrapIssuerRegistryRoot || body.CommittedInviteRecordHash != recordHash ||
		body.InviteIssuancePolicyHash != record.InviteIssuancePolicyHash ||
		body.BootstrapIssuerAuthorizationHash != record.BootstrapIssuerAuthorizationHash ||
		body.BootstrapIssuerRegistryRoot != record.BootstrapIssuerRegistryRoot {
		return errors.New("[D115 Invite] descriptor/record/policy/commitment/issuer exact binding 不匹配")
	}
	return nil
}

func EnrollmentIntentPreflightRequestHash(request *EnrollmentIntentPreflightRequestV1) (string, error) {
	if request == nil || request.Schema != 1 || !validIdentifier(request.ClusterID, 128) || !validIdentifier(request.InviteID, 128) {
		return "", errors.New("[D131 Enrollment preflight] request identity 无效")
	}
	for _, hash := range []string{request.CertifiedInviteRecordHash, request.CapabilityID} {
		if _, err := ParseHash(hash); err != nil {
			return "", err
		}
	}
	return HashObject(DomainEnrollmentPreflightRequest, request)
}

func VerifyEnrollmentIntentPreflight(response *EnrollmentIntentPreflightResponseV1, request *EnrollmentIntentPreflightRequestV1, expectedCommitmentHash string) error {
	requestHash, err := EnrollmentIntentPreflightRequestHash(request)
	if err != nil {
		return err
	}
	if response == nil || response.Schema != 1 || response.ClusterID != request.ClusterID ||
		response.InviteID != request.InviteID || response.RequestHash != requestHash {
		return errors.New("[D131 Enrollment preflight] response/request identity 无效")
	}
	openingHash, err := IntentOpeningHash(&response.DeviceEnrollmentIntentOpening)
	if err != nil || response.DeviceEnrollmentIntentCommitment.Schema != 1 ||
		response.DeviceEnrollmentIntentCommitment.ClusterID != request.ClusterID ||
		response.DeviceEnrollmentIntentCommitment.InviteID != request.InviteID ||
		response.DeviceEnrollmentIntentCommitment.OpeningHash != openingHash {
		return errors.New("[D131 Enrollment preflight] opening/commitment 不匹配")
	}
	commitmentHash, err := HashObject(DomainEnrollmentIntentCommitment, response.DeviceEnrollmentIntentCommitment)
	if err != nil || commitmentHash != expectedCommitmentHash {
		return errors.New("[D131 Enrollment preflight] public commitment hash 不匹配")
	}
	return nil
}

// ValidateDescriptorMirrorBindings 禁止 descriptor 用另一组 URL/pin 覆盖 certified EndpointSet。
func ValidateDescriptorMirrorBindings(descriptor *InviteBootstrapDescriptorV2, endpointSets map[string]DistributionEndpointSetV1) error {
	if descriptor == nil {
		return errors.New("[D115 Invite] descriptor 不能为空")
	}
	return ValidateDistributionMirrorBindings(descriptor.ClusterID, descriptor.DistributionMirrors, endpointSets)
}

// ValidateDistributionMirrorBindings 同时供 initial 与 resume descriptor 复用，
// 确保 URL/pin/listener generation 来自 exact certified EndpointSet（D115、D130）。
func ValidateDistributionMirrorBindings(clusterID string, mirrors []DistributionMirrorRefV1,
	endpointSets map[string]DistributionEndpointSetV1) error {
	if !validIdentifier(clusterID, 128) {
		return errors.New("[D115 Invite] mirror cluster identity 无效")
	}
	if err := ValidateDistributionMirrorRefs(mirrors); err != nil {
		return err
	}
	seenServers := make(map[string]struct{}, len(mirrors))
	seenNames := make(map[string]struct{}, len(mirrors))
	for _, mirror := range mirrors {
		set, ok := endpointSets[mirror.DistributionEndpointSetHash]
		if !ok {
			return errors.New("[D115 Invite] mirror 缺 exact DistributionEndpointSet")
		}
		setHash, err := DistributionEndpointSetHash(&set)
		if err != nil || setHash != mirror.DistributionEndpointSetHash || set.ClusterID != clusterID {
			return errors.New("[D115 Invite] mirror EndpointSet hash/cluster 不匹配")
		}
		matched := false
		matchedServer := ""
		for _, endpoint := range set.Endpoints {
			if endpoint.EndpointID != mirror.EndpointID {
				continue
			}
			for _, generation := range endpoint.ListenerGenerations {
				if generation.ListenerGeneration != mirror.ListenerGeneration {
					continue
				}
				if generation.PublishedState == "draining" || generation.DialTargetFQDN != mirror.ServerName {
					return errors.New("[D115 Invite] mirror listener state/name/WebPKI profile 不匹配")
				}
				expectedIdentities := append([]string{mirror.WebPKIProfileRef}, mirror.SPKIPins...)
				sort.Strings(expectedIdentities)
				if !EqualCanonical(expectedIdentities, generation.TransportIdentityRefs) {
					return errors.New("[D115 Invite] mirror WebPKI/SPKI identities 与 listener generation 不完全相等")
				}
				expectedURL := "https://" + generation.DialTargetFQDN + ":" + strconv.FormatInt(generation.PublicPort, 10) + endpoint.DistributionPathPrefix
				if mirror.BaseURL != expectedURL {
					return fmt.Errorf("[D115 Invite] mirror base URL 应为 %s", expectedURL)
				}
				matched = true
				matchedServer = endpoint.LogicalServerID
			}
		}
		if !matched {
			return errors.New("[D115 Invite] mirror endpoint/listener generation 不存在")
		}
		if _, duplicate := seenServers[matchedServer]; duplicate {
			return errors.New("[D115 Invite] distribution mirrors 未跨 logical server 分散")
		}
		if _, duplicate := seenNames[mirror.ServerName]; duplicate {
			return errors.New("[D115 Invite] distribution mirrors 未跨 FQDN 分散")
		}
		seenServers[matchedServer], seenNames[mirror.ServerName] = struct{}{}, struct{}{}
	}
	return nil
}

func validateExplicitHTTPSBaseURL(raw, serverName string) error {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Hostname() != serverName || parsed.Port() == "" {
		return errors.New("[D115 Invite] mirror 必须携带显式 HTTPS port")
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port == 0 {
		return errors.New("[D115 Invite] mirror HTTPS port 无效")
	}
	return nil
}
