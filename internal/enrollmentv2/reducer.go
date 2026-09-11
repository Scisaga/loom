// Package enrollmentv2 实现 reservation → provisional issuance → approval →
// completion 的纯 CAS reducer。token、challenge 和 detached PoP 不进入这里，
// 只有已由 enrollment-purpose quorum 固化的 admission QC 能授权 reservation（D129、D130）。
package enrollmentv2

import (
	"errors"
	"fmt"
	"time"

	"loom/internal/wire"
)

const (
	DomainClaimOperation       = "loom-enrollment-claim-operation-v2"
	DomainProvisionalOperation = "loom-enrollment-provisional-issuance-operation-v1"
	DomainCompletionOperation  = "loom-enrollment-completion-operation-v2"
	DomainTransactionState     = "loom-enrollment-transaction-state-v2"
)

type InviteContext struct {
	ClusterID                            string `json:"cluster_id"`
	InviteID                             string `json:"invite_id"`
	Status                               string `json:"status"`
	CertifiedInviteRecordHash            string `json:"certified_invite_record_hash"`
	DeviceEnrollmentIntentCommitmentHash string `json:"device_enrollment_intent_commitment_hash"`
	DeviceEnrollmentIntentOpeningHash    string `json:"device_enrollment_intent_opening_hash"`
	TokenCommitment                      string `json:"token_commitment"`
	ExpiresAt                            string `json:"expires_at"`
	MaximumReservationRetrySeconds       int64  `json:"maximum_reservation_retry_seconds"`
}

type ClaimOperationV2 struct {
	Schema                               int    `json:"schema"`
	ClusterID                            string `json:"cluster_id"`
	OperationID                          string `json:"operation_id"`
	InviteID                             string `json:"invite_id"`
	RequestID                            string `json:"request_id"`
	CertifiedInviteRecordHash            string `json:"certified_invite_record_hash"`
	DeviceEnrollmentIntentCommitmentHash string `json:"device_enrollment_intent_commitment_hash"`
	DeviceEnrollmentIntentOpeningHash    string `json:"device_enrollment_intent_opening_hash"`
	TokenCommitment                      string `json:"token_commitment"`
	ClaimCoreHash                        string `json:"claim_core_hash"`
	AdmissionQCHash                      string `json:"admission_qc_hash"`
	IdentityKeyHash                      string `json:"identity_key_hash"`
	WrappingKeyHash                      string `json:"wrapping_key_hash"`
	CSRHash                              string `json:"csr_hash"`
	ReservedAt                           string `json:"reserved_at"`
	RetryNotAfter                        string `json:"retry_not_after"`
}

type ProvisionalIssuanceOperationV1 struct {
	Schema                        int                                   `json:"schema"`
	ClusterID                     string                                `json:"cluster_id"`
	OperationID                   string                                `json:"operation_id"`
	InviteID                      string                                `json:"invite_id"`
	RequestID                     string                                `json:"request_id"`
	ExpectedTransactionStateHash  string                                `json:"expected_transaction_state_hash"`
	ClaimOperationHash            string                                `json:"claim_operation_hash"`
	ProvisionalIssuanceHash       string                                `json:"provisional_issuance_hash"`
	IssuanceRegistryLeaf          wire.EnrollmentIssuanceRegistryLeafV1 `json:"issuance_registry_leaf"`
	PreviousIssuanceRegistryRoot  string                                `json:"previous_issuance_registry_root"`
	ResultingIssuanceRegistryRoot string                                `json:"resulting_issuance_registry_root"`
	IssuedAt                      string                                `json:"issued_at"`
}

type CompletionOperationV2 struct {
	Schema                           int    `json:"schema"`
	ClusterID                        string `json:"cluster_id"`
	OperationID                      string `json:"operation_id"`
	InviteID                         string `json:"invite_id"`
	RequestID                        string `json:"request_id"`
	ExpectedTransactionStateHash     string `json:"expected_transaction_state_hash"`
	ClaimOperationHash               string `json:"claim_operation_hash"`
	ProvisionalIssuanceOperationHash string `json:"provisional_issuance_operation_hash"`
	ProvisionalIssuanceHash          string `json:"provisional_issuance_hash"`
	ResultingIssuanceRegistryRoot    string `json:"resulting_issuance_registry_root"`
	EnrollmentApprovalQCHash         string `json:"enrollment_approval_qc_hash"`
	ResultArtifactHash               string `json:"result_artifact_hash"`
}

type TransactionStateV2 struct {
	Schema                           int    `json:"schema"`
	ClusterID                        string `json:"cluster_id"`
	InviteID                         string `json:"invite_id"`
	RequestID                        string `json:"request_id"`
	ClaimCoreHash                    string `json:"claim_core_hash"`
	IdentityKeyHash                  string `json:"identity_key_hash"`
	WrappingKeyHash                  string `json:"wrapping_key_hash"`
	Status                           string `json:"status"`
	ClaimOperationHash               string `json:"claim_operation_hash"`
	ProvisionalIssuanceOperationHash string `json:"provisional_issuance_operation_hash,omitempty"`
	ProvisionalIssuanceHash          string `json:"provisional_issuance_hash,omitempty"`
	ResultingIssuanceRegistryRoot    string `json:"resulting_issuance_registry_root,omitempty"`
	EnrollmentApprovalQCHash         string `json:"enrollment_approval_qc_hash,omitempty"`
	CompletionOperationHash          string `json:"completion_operation_hash,omitempty"`
	ResultArtifactHash               string `json:"result_artifact_hash,omitempty"`
}

func Reserve(invite InviteContext, operation ClaimOperationV2, admission *wire.StableEnrollmentAdmissionQCV1, set *wire.ControlSetV1, committedAt string) (TransactionStateV2, error) {
	if invite.Status != "available" || invite.ClusterID != operation.ClusterID || invite.InviteID != operation.InviteID || operation.Schema != 2 || operation.OperationID == "" || operation.RequestID == "" {
		return TransactionStateV2{}, errors.New("[D130 Enrollment] Invite 不可用或 claim identity 不匹配")
	}
	if set == nil {
		return TransactionStateV2{}, errors.New("[D129 Enrollment] admission ControlSet 不能为空")
	}
	if err := wire.VerifyEnrollmentAdmissionQC(admission, set); err != nil {
		return TransactionStateV2{}, err
	}
	qcHash, _ := wire.EnrollmentAdmissionQCHash(admission)
	attestation := admission.Attestation
	if operation.AdmissionQCHash != qcHash || operation.CertifiedInviteRecordHash != invite.CertifiedInviteRecordHash ||
		operation.DeviceEnrollmentIntentCommitmentHash != invite.DeviceEnrollmentIntentCommitmentHash || operation.DeviceEnrollmentIntentOpeningHash != invite.DeviceEnrollmentIntentOpeningHash ||
		operation.TokenCommitment != invite.TokenCommitment || attestation.ClusterID != operation.ClusterID || attestation.InviteID != operation.InviteID || attestation.RequestID != operation.RequestID ||
		attestation.CertifiedInviteRecordHash != operation.CertifiedInviteRecordHash || attestation.DeviceEnrollmentIntentCommitmentHash != operation.DeviceEnrollmentIntentCommitmentHash ||
		attestation.DeviceEnrollmentIntentOpeningHash != operation.DeviceEnrollmentIntentOpeningHash || attestation.TokenCommitment != operation.TokenCommitment ||
		attestation.ClaimCoreHash != operation.ClaimCoreHash || attestation.IdentityKeyHash != operation.IdentityKeyHash || attestation.WrappingKeyHash != operation.WrappingKeyHash || attestation.CSRHash != operation.CSRHash {
		return TransactionStateV2{}, errors.New("[D129 Enrollment] claim/admission/invite exact binding 不匹配")
	}
	expires, err := wire.ParseTimeZ(invite.ExpiresAt)
	if err != nil || invite.MaximumReservationRetrySeconds < 0 {
		return TransactionStateV2{}, errors.New("[D130 Enrollment] Invite expiry/retry policy 无效")
	}
	wantRetry, err := checkedAddSeconds(expires, invite.MaximumReservationRetrySeconds)
	if err != nil || attestation.AdmissionNotAfter != invite.ExpiresAt || attestation.RetryNotAfter != wantRetry || operation.RetryNotAfter != wantRetry {
		return TransactionStateV2{}, errors.New("[D130 Enrollment] admission/retry deadline 不是 certified policy 的精确结果")
	}
	commitTime, err := wire.ParseTimeZ(committedAt)
	if err != nil || commitTime.After(expires) || operation.ReservedAt != committedAt {
		return TransactionStateV2{}, errors.New("[D130 Enrollment] reservation commit 已晚于 Invite expiry 或时间 anchor 不匹配")
	}
	operationHash, err := wire.HashObject(DomainClaimOperation, operation)
	if err != nil {
		return TransactionStateV2{}, err
	}
	return TransactionStateV2{Schema: 2, ClusterID: operation.ClusterID, InviteID: operation.InviteID, RequestID: operation.RequestID, ClaimCoreHash: operation.ClaimCoreHash, IdentityKeyHash: operation.IdentityKeyHash, WrappingKeyHash: operation.WrappingKeyHash, Status: "reserved", ClaimOperationHash: operationHash}, nil
}

func RecordProvisional(current TransactionStateV2, operation ProvisionalIssuanceOperationV1) (TransactionStateV2, error) {
	if current.Status != "reserved" || operation.Schema != 1 || operation.OperationID == "" || !sameTransaction(current, operation.ClusterID, operation.InviteID, operation.RequestID) {
		return TransactionStateV2{}, errors.New("[D130 Enrollment] provisional issuance 只能从 exact reserved transaction CAS")
	}
	currentHash, _ := TransactionHash(current)
	if operation.ExpectedTransactionStateHash != currentHash || operation.ClaimOperationHash != current.ClaimOperationHash || operation.PreviousIssuanceRegistryRoot == operation.ResultingIssuanceRegistryRoot ||
		wire.ValidateEnrollmentIssuanceRegistryLeaf(&operation.IssuanceRegistryLeaf) != nil ||
		operation.IssuanceRegistryLeaf.ClaimOperationHash != operation.ClaimOperationHash ||
		operation.IssuanceRegistryLeaf.ProvisionalIssuanceHash != operation.ProvisionalIssuanceHash {
		return TransactionStateV2{}, errors.New("[D130 Enrollment] provisional issuance CAS/registry root 无效")
	}
	for _, hash := range []string{operation.ProvisionalIssuanceHash, operation.PreviousIssuanceRegistryRoot, operation.ResultingIssuanceRegistryRoot} {
		if _, err := wire.ParseHash(hash); err != nil {
			return TransactionStateV2{}, err
		}
	}
	if _, err := wire.ParseTimeZ(operation.IssuedAt); err != nil {
		return TransactionStateV2{}, err
	}
	operationHash, err := wire.HashObject(DomainProvisionalOperation, operation)
	if err != nil {
		return TransactionStateV2{}, err
	}
	next := current
	next.Status = "issued_provisional"
	next.ProvisionalIssuanceOperationHash = operationHash
	next.ProvisionalIssuanceHash = operation.ProvisionalIssuanceHash
	next.ResultingIssuanceRegistryRoot = operation.ResultingIssuanceRegistryRoot
	return next, nil
}

func Complete(current TransactionStateV2, operation CompletionOperationV2, approval *wire.StableEnrollmentApprovalQCV2, set *wire.ControlSetV1) (TransactionStateV2, error) {
	if current.Status != "issued_provisional" || operation.Schema != 2 || operation.OperationID == "" || !sameTransaction(current, operation.ClusterID, operation.InviteID, operation.RequestID) {
		return TransactionStateV2{}, errors.New("[D130 Enrollment] completion 只能从 exact issued_provisional transaction CAS")
	}
	if set == nil {
		return TransactionStateV2{}, errors.New("[D130 Enrollment] approval ControlSet 不能为空")
	}
	if err := wire.VerifyEnrollmentApprovalQC(approval, set); err != nil {
		return TransactionStateV2{}, err
	}
	currentHash, _ := TransactionHash(current)
	qcHash, _ := wire.EnrollmentApprovalQCHash(approval)
	attestation := approval.Attestation
	if operation.ExpectedTransactionStateHash != currentHash || operation.ClaimOperationHash != current.ClaimOperationHash ||
		operation.ProvisionalIssuanceOperationHash != current.ProvisionalIssuanceOperationHash || operation.ProvisionalIssuanceHash != current.ProvisionalIssuanceHash ||
		operation.ResultingIssuanceRegistryRoot != current.ResultingIssuanceRegistryRoot || operation.EnrollmentApprovalQCHash != qcHash ||
		attestation.ClusterID != current.ClusterID || attestation.InviteID != current.InviteID || attestation.RequestID != current.RequestID ||
		attestation.ClaimOperationHash != current.ClaimOperationHash || attestation.ProvisionalIssuanceOperationHash != current.ProvisionalIssuanceOperationHash ||
		attestation.ProvisionalIssuanceHash != current.ProvisionalIssuanceHash || attestation.ResultingIssuanceRegistryRoot != current.ResultingIssuanceRegistryRoot ||
		attestation.ResultArtifactHash != operation.ResultArtifactHash {
		return TransactionStateV2{}, errors.New("[D130 Enrollment] completion/approval exact binding 不匹配")
	}
	operationHash, err := wire.HashObject(DomainCompletionOperation, operation)
	if err != nil {
		return TransactionStateV2{}, err
	}
	next := current
	next.Status = "completed"
	next.EnrollmentApprovalQCHash = qcHash
	next.CompletionOperationHash = operationHash
	next.ResultArtifactHash = operation.ResultArtifactHash
	return next, nil
}

func Abort(current TransactionStateV2) (TransactionStateV2, error) {
	if current.Status != "reserved" && current.Status != "issued_provisional" {
		return TransactionStateV2{}, errors.New("[D130 Enrollment] 只有未完成 transaction 可 certified abort")
	}
	next := current
	next.Status = "aborted"
	return next, nil
}

func TransactionHash(state TransactionStateV2) (string, error) {
	if state.Schema != 2 || state.ClusterID == "" || state.InviteID == "" || state.RequestID == "" || !oneOf(state.Status, "reserved", "issued_provisional", "completed", "aborted") {
		return "", errors.New("[D130 Enrollment] transaction state 无效")
	}
	return wire.HashObject(DomainTransactionState, state)
}

func sameTransaction(state TransactionStateV2, clusterID, inviteID, requestID string) bool {
	return state.ClusterID == clusterID && state.InviteID == inviteID && state.RequestID == requestID
}

func checkedAddSeconds(value time.Time, seconds int64) (string, error) {
	if seconds < 0 || seconds > int64((365*24*time.Hour)/time.Second) {
		return "", errors.New("[D130 Enrollment] reservation retry 秒数越界")
	}
	result := value.Add(time.Duration(seconds) * time.Second).UTC().Format(time.RFC3339)
	if _, err := wire.ParseTimeZ(result); err != nil {
		return "", fmt.Errorf("[D130 Enrollment] reservation retry 时间越界: %w", err)
	}
	return result, nil
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
