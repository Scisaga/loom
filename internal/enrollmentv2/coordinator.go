package enrollmentv2

import (
	"context"
	"errors"

	"loom/internal/wire"
)

var ErrEnrollmentProgressPending = errors.New("enrollment progress pending")

type ReservationPlanV2 struct {
	OperationID string
	CommittedAt string
}

type ProvisionalPlanV1 struct {
	Operation ProvisionalIssuanceOperationV1
	Issuance  wire.EnrollmentProvisionalIssuanceV1
	Profile   wire.DeviceCertificateProfileStateV1
	Result    wire.EnrollmentResultArtifactV1
}

type CompletionPlanV2 struct {
	OperationID string
}

// WorkflowBackend 把跨 control 的签名收集、Raft 坐标分配与 CA 私钥操作留在
// 各自 purpose-separated 服务；Coordinator 只接受随后能由 reducer 独立重验的制品。
type WorkflowBackend interface {
	CollectAdmission(context.Context, VerifiedClaimAttemptV2,
		wire.EnrollmentAdmissionAttestationBodyV1) (wire.StableEnrollmentAdmissionQCV1, error)
	PlanReservation(context.Context, VerifiedClaimAttemptV2,
		wire.StableEnrollmentAdmissionQCV1) (ReservationPlanV2, error)
	Provision(context.Context, VerifiedClaimAttemptV2, DurableRecord) (ProvisionalPlanV1, error)
	CollectApproval(context.Context, VerifiedClaimAttemptV2,
		DurableRecord) (wire.StableEnrollmentApprovalQCV2, wire.ControlSetV1, error)
	PlanCompletion(context.Context, VerifiedClaimAttemptV2, DurableRecord,
		wire.StableEnrollmentApprovalQCV2) (CompletionPlanV2, error)
}

// TransactionRepository 的生产实现必须把每次 CAS 接入 replicated Raft apply；文件
// Store 是同一确定性状态机的本地耐久实现，可用于单成员集和故障恢复测试。
type TransactionRepository interface {
	SnapshotRecord(string) (DurableRecord, bool)
	Reserve(InviteContext, ClaimPrivateEvidenceV1, ClaimOperationV2, *wire.StableEnrollmentAdmissionQCV1,
		*wire.ControlSetV1, string) (TransactionStateV2, error)
	RecordProvisional(ProvisionalIssuanceOperationV1, wire.EnrollmentProvisionalIssuanceV1,
		wire.DeviceCertificateProfileStateV1, wire.EnrollmentResultArtifactV1) (TransactionStateV2, error)
	Complete(CompletionOperationV2, *wire.StableEnrollmentApprovalQCV2,
		*wire.ControlSetV1) (TransactionStateV2, error)
}

type Coordinator struct {
	repository TransactionRepository
	backend    WorkflowBackend
}

func NewCoordinator(repository TransactionRepository, backend WorkflowBackend) (*Coordinator, error) {
	if repository == nil || backend == nil {
		return nil, errors.New("[D130 Enrollment] coordinator repository/backend 不能为空")
	}
	return &Coordinator{repository: repository, backend: backend}, nil
}

// ProcessClaim 可直接作为 PrivateService 的 ClaimProcessor。每次调用从 durable
// record 恢复，completed 不再触发外部动作；明确的 pending 返回 202 所需稳定状态。
func (coordinator *Coordinator) ProcessClaim(ctx context.Context,
	attempt VerifiedClaimAttemptV2) (wire.EnrollmentClaimResultV2, error) {
	if err := ctx.Err(); err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	record, found := coordinator.repository.SnapshotRecord(attempt.InviteContext().InviteID)
	if found {
		if err := validateAttemptAgainstRecord(attempt, &record); err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		if record.State.Status == "completed" {
			return enrollmentResult(record.State)
		}
	} else {
		attestation, err := attempt.AdmissionAttestation()
		if err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		admission, err := coordinator.backend.CollectAdmission(ctx, attempt, attestation)
		if err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		if !wire.EqualCanonical(admission.Attestation, attestation) ||
			wire.VerifyEnrollmentAdmissionQC(&admission, &attempt.material.ControlSet) != nil {
			return wire.EnrollmentClaimResultV2{}, errors.New("[D129 Enrollment] backend admission QC 未绑定 exact verified attempt/base ControlSet")
		}
		plan, err := coordinator.backend.PlanReservation(ctx, attempt, admission)
		if err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		operation, err := claimOperationForAdmission(&admission, plan)
		if err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		if _, err := coordinator.repository.Reserve(attempt.InviteContext(), attempt.PrivateClaimEvidence(), operation, &admission,
			&attempt.material.ControlSet, plan.CommittedAt); err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		record, found = coordinator.repository.SnapshotRecord(operation.InviteID)
		if !found {
			return wire.EnrollmentClaimResultV2{}, errors.New("[D130 Enrollment] reservation CAS 后缺 durable record")
		}
	}

	if record.State.Status == "reserved" {
		plan, err := coordinator.backend.Provision(ctx, attempt, record)
		if errors.Is(err, ErrEnrollmentProgressPending) {
			return enrollmentResult(record.State)
		}
		if err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		if _, err := coordinator.repository.RecordProvisional(plan.Operation, plan.Issuance, plan.Profile, plan.Result); err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		record, found = coordinator.repository.SnapshotRecord(record.InviteID)
		if !found {
			return wire.EnrollmentClaimResultV2{}, errors.New("[D130 Enrollment] provisional CAS 后缺 durable record")
		}
	}

	if record.State.Status == "issued_provisional" {
		approval, set, err := coordinator.backend.CollectApproval(ctx, attempt, record)
		if errors.Is(err, ErrEnrollmentProgressPending) {
			return enrollmentResult(record.State)
		}
		if err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		if err := validateApprovalAgainstIssuance(&record, &approval); err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		if err := wire.VerifyEnrollmentApprovalQC(&approval, &set); err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		plan, err := coordinator.backend.PlanCompletion(ctx, attempt, record, approval)
		if errors.Is(err, ErrEnrollmentProgressPending) {
			return enrollmentResult(record.State)
		}
		if err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		operation, err := completionOperationForRecord(record, &approval, plan)
		if err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		state, err := coordinator.repository.Complete(operation, &approval, &set)
		if err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		record.State = state
	}
	return enrollmentResult(record.State)
}

func claimOperationForAdmission(admission *wire.StableEnrollmentAdmissionQCV1,
	plan ReservationPlanV2) (ClaimOperationV2, error) {
	if plan.OperationID == "" {
		return ClaimOperationV2{}, errors.New("[D130 Enrollment] reservation operation ID 不能为空")
	}
	if _, err := wire.ParseTimeZ(plan.CommittedAt); err != nil {
		return ClaimOperationV2{}, err
	}
	attestation := admission.Attestation
	admissionHash, err := wire.EnrollmentAdmissionQCHash(admission)
	if err != nil {
		return ClaimOperationV2{}, err
	}
	return ClaimOperationV2{
		Schema: 2, ClusterID: attestation.ClusterID, OperationID: plan.OperationID,
		InviteID: attestation.InviteID, RequestID: attestation.RequestID,
		CertifiedInviteRecordHash:            attestation.CertifiedInviteRecordHash,
		DeviceEnrollmentIntentCommitmentHash: attestation.DeviceEnrollmentIntentCommitmentHash,
		DeviceEnrollmentIntentOpeningHash:    attestation.DeviceEnrollmentIntentOpeningHash,
		TokenCommitment:                      attestation.TokenCommitment, ClaimCoreHash: attestation.ClaimCoreHash,
		AdmissionQCHash: admissionHash, IdentityKeyHash: attestation.IdentityKeyHash,
		WrappingKeyHash: attestation.WrappingKeyHash, CSRHash: attestation.CSRHash,
		ReservedAt: plan.CommittedAt, RetryNotAfter: attestation.RetryNotAfter,
	}, nil
}

func completionOperationForRecord(record DurableRecord, approval *wire.StableEnrollmentApprovalQCV2,
	plan CompletionPlanV2) (CompletionOperationV2, error) {
	if plan.OperationID == "" || record.ProvisionalOperation == nil {
		return CompletionOperationV2{}, errors.New("[D130 Enrollment] completion plan/provisional operation 无效")
	}
	stateHash, err := TransactionHash(record.State)
	if err != nil {
		return CompletionOperationV2{}, err
	}
	approvalHash, err := wire.EnrollmentApprovalQCHash(approval)
	if err != nil {
		return CompletionOperationV2{}, err
	}
	return CompletionOperationV2{
		Schema: 2, ClusterID: record.State.ClusterID, OperationID: plan.OperationID,
		InviteID: record.State.InviteID, RequestID: record.State.RequestID,
		ExpectedTransactionStateHash: stateHash, ClaimOperationHash: record.State.ClaimOperationHash,
		ProvisionalIssuanceOperationHash: record.State.ProvisionalIssuanceOperationHash,
		ProvisionalIssuanceHash:          record.State.ProvisionalIssuanceHash,
		ResultingIssuanceRegistryRoot:    record.State.ResultingIssuanceRegistryRoot,
		EnrollmentApprovalQCHash:         approvalHash, ResultArtifactHash: approval.Attestation.ResultArtifactHash,
	}, nil
}

func validateAttemptAgainstRecord(attempt VerifiedClaimAttemptV2, record *DurableRecord) error {
	if record == nil {
		return errors.New("[D130 Enrollment] durable record 不能为空")
	}
	invite := attempt.InviteContext()
	claim := attempt.Claim()
	if invite.ClusterID != record.Invite.ClusterID || invite.InviteID != record.Invite.InviteID ||
		invite.CertifiedInviteRecordHash != record.Invite.CertifiedInviteRecordHash ||
		invite.DeviceEnrollmentIntentCommitmentHash != record.Invite.DeviceEnrollmentIntentCommitmentHash ||
		invite.DeviceEnrollmentIntentOpeningHash != record.Invite.DeviceEnrollmentIntentOpeningHash ||
		invite.TokenCommitment != record.TokenCommitment || invite.ExpiresAt != record.Invite.ExpiresAt ||
		invite.MaximumReservationRetrySeconds != record.Invite.MaximumReservationRetrySeconds ||
		claim.ClaimCoreHash() != record.State.ClaimCoreHash || claim.IdentityKeyHash() != record.State.IdentityKeyHash ||
		claim.WrappingKeyHash() != record.State.WrappingKeyHash || claim.CSRHash() != record.ClaimOperation.CSRHash ||
		attempt.submission.ClaimCore.RequestID != record.State.RequestID ||
		!wire.EqualCanonical(attempt.PrivateClaimEvidence(), record.ClaimEvidence) {
		return errors.New("[D130 Enrollment] resume attempt 与 durable stable claim/core/key 不匹配")
	}
	return nil
}

func enrollmentResult(state TransactionStateV2) (wire.EnrollmentClaimResultV2, error) {
	stateHash, err := TransactionHash(state)
	if err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	result := wire.EnrollmentClaimResultV2{Schema: 2, Status: state.Status,
		TransactionStateHash: stateHash, ResultArtifactHash: state.ResultArtifactHash}
	if err := wire.ValidateEnrollmentClaimResult(&result); err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	return result, nil
}
