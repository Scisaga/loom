package wire

import (
	"crypto/ed25519"
	"errors"
	"time"
)

const (
	DomainEnrollmentResumeDescriptor    = "loom-enrollment-resume-descriptor-v1"
	DomainEnrollmentResumeAuthorization = "loom-enrollment-resume-authorization-v1"
)

// EnrollmentResumeAuthorizationV1 是管理员 control operation 的 exact payload。
// operation certification 负责授权，签发器再线性核对 transaction state。
type EnrollmentResumeAuthorizationV1 struct {
	Schema                       int    `json:"schema"`
	ClusterID                    string `json:"cluster_id"`
	InviteID                     string `json:"invite_id"`
	RequestID                    string `json:"request_id"`
	DeviceID                     string `json:"device_id"`
	ExpectedTransactionStateHash string `json:"expected_transaction_state_hash"`
	ExpiresAt                    string `json:"expires_at"`
}

func EnrollmentResumeAuthorizationHash(value *EnrollmentResumeAuthorizationV1) (string, error) {
	if value == nil || value.Schema != 1 || !validIdentifier(value.ClusterID, 128) ||
		!validIdentifier(value.InviteID, 128) || !validIdentifier(value.RequestID, 128) ||
		!validIdentifier(value.DeviceID, 128) {
		return "", errors.New("[resume] admin authorization identity 无效")
	}
	if _, err := ParseHash(value.ExpectedTransactionStateHash); err != nil {
		return "", err
	}
	if _, err := ParseTimeZ(value.ExpiresAt); err != nil {
		return "", err
	}
	return HashObject(DomainEnrollmentResumeAuthorization, value)
}

// EnrollmentResumeDescriptorV1 只恢复一个已 certified reservation；它没有 token，
// 也不能授权另一份 claim core 或另一组本机 key。
type EnrollmentResumeDescriptorV1 struct {
	Schema                         int                           `json:"schema"`
	ClusterID                      string                        `json:"cluster_id"`
	InviteID                       string                        `json:"invite_id"`
	RequestID                      string                        `json:"request_id"`
	ExpiresAt                      string                        `json:"expires_at"`
	ResumeTunnelCapability         BootstrapTunnelCapabilityV1   `json:"resume_tunnel_capability"`
	ClaimCoreHash                  string                        `json:"claim_core_hash"`
	ClaimOperationHash             string                        `json:"claim_operation_hash"`
	AdmissionQCHash                string                        `json:"admission_qc_hash"`
	EnrollmentTransactionStateHash string                        `json:"enrollment_transaction_state_hash"`
	BootstrapCatalogHash           string                        `json:"bootstrap_catalog_hash"`
	ProofBundleHash                string                        `json:"proof_bundle_hash"`
	EnrollmentServiceRef           PrivateEnrollmentServiceRefV1 `json:"enrollment_service_ref"`
	DistributionMirrors            []DistributionMirrorRefV1     `json:"distribution_mirrors"`
}

// EnrollmentResumeExpectedV1 是客户端受保护 pending state 的本机投影，不进入 wire。
type EnrollmentResumeExpectedV1 struct {
	ClusterID                      string `json:"cluster_id"`
	InviteID                       string `json:"invite_id"`
	RequestID                      string `json:"request_id"`
	ClaimCoreHash                  string `json:"claim_core_hash"`
	ClaimOperationHash             string `json:"claim_operation_hash"`
	AdmissionQCHash                string `json:"admission_qc_hash"`
	CSRHash                        string `json:"csr_hash"`
	IdentityKeyHash                string `json:"identity_key_hash"`
	WrappingKeyHash                string `json:"wrapping_key_hash"`
	EnrollmentTransactionStateHash string `json:"enrollment_transaction_state_hash"`
	RetryNotAfter                  string `json:"retry_not_after"`
}

func ValidateEnrollmentResumeDescriptor(descriptor *EnrollmentResumeDescriptorV1, issuerPublicKey ed25519.PublicKey) error {
	if descriptor == nil || descriptor.Schema != 1 || !validIdentifier(descriptor.ClusterID, 128) ||
		!validIdentifier(descriptor.InviteID, 128) || !validIdentifier(descriptor.RequestID, 128) {
		return errors.New("[resume] descriptor identity 无效")
	}
	descriptorExpiry, err := ParseTimeZ(descriptor.ExpiresAt)
	if err != nil {
		return err
	}
	if err := VerifyBootstrapCapability(&descriptor.ResumeTunnelCapability, issuerPublicKey); err != nil {
		return err
	}
	body := &descriptor.ResumeTunnelCapability.Body
	binding := body.ResumeBinding
	if body.Mode != "resume_committed_claim" || binding == nil ||
		body.ClusterID != descriptor.ClusterID || body.InviteID != descriptor.InviteID ||
		binding.RequestID != descriptor.RequestID {
		return errors.New("[resume] capability mode/transaction identity 不匹配")
	}
	capabilityExpiry, _ := ParseTimeZ(body.ExpiresAt)
	if descriptorExpiry.After(capabilityExpiry) {
		return errors.New("[resume] descriptor expiry 晚于 capability")
	}
	serviceHash, err := PrivateEnrollmentServiceRefHash(&descriptor.EnrollmentServiceRef)
	if err != nil || serviceHash != body.EnrollmentServiceRefHash ||
		descriptor.EnrollmentServiceRef.ServiceID != body.AllowedServiceID ||
		descriptor.EnrollmentServiceRef.OverlayIP != body.AllowedDestinationIP ||
		descriptor.EnrollmentServiceRef.TCPPort != body.AllowedDestinationPort {
		return errors.New("[resume] private Enrollment service exact tuple 不匹配")
	}
	if descriptor.ClaimCoreHash != binding.ClaimCoreHash ||
		descriptor.ClaimOperationHash != binding.ClaimOperationHash ||
		descriptor.AdmissionQCHash != binding.AdmissionQCHash ||
		descriptor.EnrollmentTransactionStateHash != binding.EnrollmentTransactionStateHash {
		return errors.New("[resume] descriptor/capability stable binding 不匹配")
	}
	for _, hash := range []string{descriptor.ClaimCoreHash, descriptor.ClaimOperationHash,
		descriptor.AdmissionQCHash, descriptor.EnrollmentTransactionStateHash,
		descriptor.BootstrapCatalogHash, descriptor.ProofBundleHash} {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	return validateDistributionMirrorRefs(descriptor.DistributionMirrors)
}

func EnrollmentResumeDescriptorHash(descriptor *EnrollmentResumeDescriptorV1, issuerPublicKey ed25519.PublicKey) (string, error) {
	if err := ValidateEnrollmentResumeDescriptor(descriptor, issuerPublicKey); err != nil {
		return "", err
	}
	return HashObject(DomainEnrollmentResumeDescriptor, descriptor)
}

// VerifyEnrollmentResumeDescriptorBindings 把带外 descriptor 绑定到本机 pending core、
// certified issuer scope 与 exact catalog。本机 transaction hash 是已验 floor；descriptor
// 绑定的是签发时服务端当前状态，响应仍须用 progress/completion receipt 证明单调前进。
func VerifyEnrollmentResumeDescriptorBindings(descriptor *EnrollmentResumeDescriptorV1, expected EnrollmentResumeExpectedV1,
	catalog *BootstrapEndpointCatalogV1, proof *BootstrapIssuerAuthorizationProofV1,
	policy *InviteIssuancePolicyV2, trustedTime time.Time, clientProtocol int64) error {
	if descriptor == nil || catalog == nil || proof == nil || policy == nil || trustedTime.IsZero() {
		return errors.New("[resume] binding context 不完整")
	}
	if proof.Authorization.Active == nil {
		return errors.New("[resume] issuer authorization 非 active")
	}
	publicKey, err := decodeRawURL(proof.Authorization.Active.IssuerPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return errors.New("[resume] issuer public key 无效")
	}
	if err := ValidateEnrollmentResumeDescriptor(descriptor, ed25519.PublicKey(publicKey)); err != nil {
		return err
	}
	if err := VerifyCapabilityAuthorization(&descriptor.ResumeTunnelCapability, proof, policy, trustedTime); err != nil {
		return err
	}
	encoded, err := MarshalCanonical(descriptor)
	if err != nil || int64(len(encoded)) > policy.MaximumDescriptorBytes ||
		int64(len(descriptor.DistributionMirrors)) < policy.MinimumDistributionMirrors ||
		int64(len(descriptor.DistributionMirrors)) > policy.MaximumDistributionMirrors {
		return errors.New("[resume] descriptor size/mirror count 超出 certified policy")
	}
	if err := ValidateBootstrapEndpointCatalogAt(catalog, trustedTime, clientProtocol); err != nil {
		return err
	}
	catalogHash, err := BootstrapEndpointCatalogHash(catalog)
	if err != nil || catalogHash != descriptor.BootstrapCatalogHash ||
		catalog.BootstrapIngressSetHash != descriptor.ResumeTunnelCapability.Body.AllowedIngressSetHash {
		return errors.New("[resume] catalog/hash/ingress binding 不匹配")
	}
	binding := descriptor.ResumeTunnelCapability.Body.ResumeBinding
	if expected.ClusterID != descriptor.ClusterID || expected.InviteID != descriptor.InviteID || expected.RequestID != descriptor.RequestID ||
		expected.ClaimCoreHash != descriptor.ClaimCoreHash || expected.ClaimOperationHash != descriptor.ClaimOperationHash ||
		expected.AdmissionQCHash != descriptor.AdmissionQCHash ||
		expected.CSRHash != binding.CSRHash || expected.IdentityKeyHash != binding.IdentityKeyHash ||
		expected.WrappingKeyHash != binding.WrappingKeyHash {
		return errors.New("[resume] descriptor 与本机 pending stable transaction 不匹配")
	}
	retryDeadline, err := ParseTimeZ(expected.RetryNotAfter)
	if err != nil {
		return err
	}
	descriptorExpiry, _ := ParseTimeZ(descriptor.ExpiresAt)
	if descriptorExpiry.After(retryDeadline) || !trustedTime.UTC().Before(descriptorExpiry) {
		return errors.New("[resume] descriptor 已过期或晚于 transaction retry deadline")
	}
	return nil
}
