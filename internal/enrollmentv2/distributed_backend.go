package enrollmentv2

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"loom/internal/wire"
)

const (
	DomainClaimOperationID       = "loom-enrollment-claim-operation-id-v1"
	DomainProvisionalOperationID = "loom-enrollment-provisional-operation-id-v1"
)

// EnrollmentCommitCoordinateV1 由持有当前 Raft leadership 的 sequencer 冻结；
// operation 中所有时间和日志坐标只能从这里取得，不能由 CA 或 ingress 自选。
type EnrollmentCommitCoordinateV1 struct {
	Schema               int    `json:"schema"`
	ClusterID            string `json:"cluster_id"`
	RecoveryEpoch        int64  `json:"recovery_epoch"`
	RaftTerm             int64  `json:"raft_term"`
	RaftIndex            int64  `json:"raft_index"`
	PreviousLogEntryHash string `json:"previous_log_entry_hash"`
	ParentHeadHash       string `json:"parent_head_hash"`
	CommittedLogicalTime string `json:"committed_logical_time"`
}

// EnrollmentHeadMutationV1 是交给全局 state projector 的最小 typed mutation。
// 私有 result bytes 不进入 Raft；completion 只把 exact view/secret refs 交给私有投影器。
type EnrollmentHeadMutationV1 struct {
	OperationLeaf     wire.ControlOperationLeafV1 `json:"operation_leaf"`
	InitialDeviceView *wire.DeviceViewPayloadV2   `json:"initial_device_view,omitempty"`
	// completion 的 [] 是有效空集合，必须跨 journal 编解码保留，不能变成 nil。
	SecretArtifactRefs []json.RawMessage `json:"secret_artifact_refs"`
	// Preimage 只在认证的 control 副本间复制，不放进 Head 或公开分发。
	// 它使 daemon 能独立重算 CAS，而不是相信调用方提供的 object hash。
	Preimage *EnrollmentMutationPreimageV1 `json:"preimage,omitempty"`
}

type EnrollmentOperationCommitResultV1 struct {
	Certification         CertifiedEnrollmentOperationProofV1 `json:"certification"`
	IntermediateHeads     []wire.HeadEntryV2                  `json:"intermediate_heads,omitempty"`
	ControlSetTransitions []wire.ControlSetTransitionBundleV1 `json:"control_set_transitions,omitempty"`
	DeviceViewEnvelope    *wire.DeviceViewEnvelopeV2          `json:"device_view_envelope,omitempty"`
}

type EnrollmentOperationBuilder func(EnrollmentCommitCoordinateV1) (EnrollmentHeadMutationV1, error)

// EnrollmentOperationSequencer 必须把 builder 产生的 exact leaf 走完 Raft
// commit/apply/config-QC；相同 operation ID 的重试只能返回第一次的 certified bytes。
type EnrollmentOperationSequencer interface {
	CommitEnrollmentOperation(context.Context, string, *wire.HeadEntryV2,
		EnrollmentOperationBuilder) (EnrollmentOperationCommitResultV1, error)
}

type EnrollmentAdmissionQuorum interface {
	CollectAdmission(context.Context, VerifiedClaimAttemptV2,
		wire.EnrollmentAdmissionAttestationBodyV1) (wire.StableEnrollmentAdmissionQCV1, error)
}

type EnrollmentApprovalQuorum interface {
	CollectApproval(context.Context,
		wire.EnrollmentApprovalAttestationBodyV2) (wire.StableEnrollmentApprovalQCV2, error)
}

type PreparedProvisionalV1 struct {
	Operation ProvisionalIssuanceOperationV1       `json:"operation"`
	Issuance  wire.EnrollmentProvisionalIssuanceV1 `json:"issuance"`
	Profile   wire.DeviceCertificateProfileStateV1 `json:"profile"`
	Result    wire.EnrollmentResultArtifactV1      `json:"result"`
}

// DurableProvisionalPreparer 隔离 CA/secret 私钥。实现必须先耐久化 exact first-result，
// 相同 operation ID + coordinate 重试返回逐字节相同制品，冲突则失败关闭。
type DurableProvisionalPreparer interface {
	PrepareProvisional(context.Context, string, VerifiedClaimAttemptV2, DurableRecord,
		EnrollmentCommitCoordinateV1) (PreparedProvisionalV1, error)
}

// DistributedWorkflowBackend 是 Coordinator 的生产分布式实现：它只信任可独立
// 重验的 quorum、CA first-result 与 certified Head 结果，不接受裸 ack/hash。
type DistributedWorkflowBackend struct {
	admission    EnrollmentAdmissionQuorum
	sequencer    EnrollmentOperationSequencer
	provision    DurableProvisionalPreparer
	readApproval ApprovalEvidenceReader
	approval     EnrollmentApprovalQuorum
	now          func() time.Time
}

func NewDistributedWorkflowBackend(admission EnrollmentAdmissionQuorum,
	sequencer EnrollmentOperationSequencer, provision DurableProvisionalPreparer,
	readApproval ApprovalEvidenceReader, approval EnrollmentApprovalQuorum,
	now func() time.Time) (*DistributedWorkflowBackend, error) {
	if admission == nil || sequencer == nil || provision == nil || readApproval == nil ||
		approval == nil || now == nil {
		return nil, errors.New("[Enrollment] distributed workflow dependencies 不完整")
	}
	return &DistributedWorkflowBackend{admission: admission, sequencer: sequencer,
		provision: provision, readApproval: readApproval, approval: approval, now: now}, nil
}

func (backend *DistributedWorkflowBackend) CollectAdmission(ctx context.Context,
	attempt VerifiedClaimAttemptV2, attestation wire.EnrollmentAdmissionAttestationBodyV1) (wire.StableEnrollmentAdmissionQCV1, error) {
	qc, err := backend.admission.CollectAdmission(ctx, attempt, attestation)
	if err != nil {
		return wire.StableEnrollmentAdmissionQCV1{}, err
	}
	if !wire.EqualCanonical(qc.Attestation, attestation) ||
		wire.VerifyEnrollmentAdmissionQC(&qc, &attempt.material.ControlSet) != nil {
		return wire.StableEnrollmentAdmissionQCV1{}, errors.New("[Enrollment] admission quorum 返回错误 exact QC")
	}
	return qc, nil
}

func (backend *DistributedWorkflowBackend) PlanReservation(ctx context.Context,
	attempt VerifiedClaimAttemptV2, admission wire.StableEnrollmentAdmissionQCV1) (ReservationPlanV2, error) {
	operationID, err := ClaimOperationID(&admission)
	if err != nil {
		return ReservationPlanV2{}, err
	}
	baseHead := clonePrivateValue(attempt.material.RecordHead)
	result, err := backend.sequencer.CommitEnrollmentOperation(ctx, operationID, &baseHead,
		func(coordinate EnrollmentCommitCoordinateV1) (EnrollmentHeadMutationV1, error) {
			plan := ReservationPlanV2{OperationID: operationID, CommittedAt: coordinate.CommittedLogicalTime}
			operation, err := claimOperationForAdmission(&admission, plan)
			if err != nil {
				return EnrollmentHeadMutationV1{}, err
			}
			if err := validateCommitCoordinate(&coordinate, operation.ClusterID); err != nil {
				return EnrollmentHeadMutationV1{}, err
			}
			if _, err := Reserve(attempt.InviteContext(), operation, &admission,
				&attempt.material.ControlSet, operation.ReservedAt); err != nil {
				return EnrollmentHeadMutationV1{}, err
			}
			if err := validateClaimPrivateEvidencePointer(attempt.PrivateClaimEvidence(), &operation); err != nil {
				return EnrollmentHeadMutationV1{}, err
			}
			objectID, err := wire.HashObject(DomainClaimOperation, operation)
			if err != nil {
				return EnrollmentHeadMutationV1{}, err
			}
			return EnrollmentHeadMutationV1{OperationLeaf: wire.ControlOperationLeafV1{
				Schema: 1, OperationID: operationID, ObjectID: objectID},
				Preimage: &EnrollmentMutationPreimageV1{Schema: 1, Kind: "reservation",
					Reservation: &EnrollmentReservationPreimageV1{Material: cloneInviteMaterial(attempt.material),
						Evidence: attempt.PrivateClaimEvidence(), Operation: operation, Admission: admission}}}, nil
		})
	if err != nil {
		return ReservationPlanV2{}, err
	}
	plan := ReservationPlanV2{OperationID: operationID,
		CommittedAt:           result.Certification.Head.Body.Payload.CommittedLogicalTime,
		BaseHead:              baseHead,
		IntermediateHeads:     append([]wire.HeadEntryV2(nil), result.IntermediateHeads...),
		ControlSetTransitions: cloneControlSetTransitions(result.ControlSetTransitions),
		Certification:         result.Certification}
	operation, err := claimOperationForAdmission(&admission, plan)
	if err != nil {
		return ReservationPlanV2{}, err
	}
	if err := validateOperationCertification(&plan.Certification, operation.OperationID,
		DomainClaimOperation, operation, &plan.Certification.ControlSet, operation.ReservedAt); err != nil {
		return ReservationPlanV2{}, err
	}
	if err := validateReservationHeadLineage(&plan.BaseHead, plan.IntermediateHeads,
		plan.ControlSetTransitions,
		&plan.Certification, &admission, &attempt.material.ControlSet); err != nil {
		return ReservationPlanV2{}, err
	}
	return plan, nil
}

func (backend *DistributedWorkflowBackend) Provision(ctx context.Context,
	attempt VerifiedClaimAttemptV2, record DurableRecord) (ProvisionalPlanV1, error) {
	operationID, err := ProvisionalOperationID(&record)
	if err != nil {
		return ProvisionalPlanV1{}, err
	}
	var prepared PreparedProvisionalV1
	result, err := backend.sequencer.CommitEnrollmentOperation(ctx, operationID,
		&record.ReservationCertification.Head,
		func(coordinate EnrollmentCommitCoordinateV1) (EnrollmentHeadMutationV1, error) {
			value, err := backend.provision.PrepareProvisional(ctx, operationID, attempt, record, coordinate)
			if err != nil {
				return EnrollmentHeadMutationV1{}, err
			}
			if err := validatePreparedProvisional(&value, operationID, &record, &coordinate); err != nil {
				return EnrollmentHeadMutationV1{}, err
			}
			prepared = value
			objectID, err := wire.HashObject(DomainProvisionalOperation, value.Operation)
			if err != nil {
				return EnrollmentHeadMutationV1{}, err
			}
			return EnrollmentHeadMutationV1{OperationLeaf: wire.ControlOperationLeafV1{
				Schema: 1, OperationID: operationID, ObjectID: objectID},
				Preimage: &EnrollmentMutationPreimageV1{Schema: 1, Kind: "provisional",
					Provisional: &EnrollmentProvisionalPreimageV1{Record: cloneDurableRecord(record),
						Prepared: clonePreparedProvisional(value)}}}, nil
		})
	if err != nil {
		return ProvisionalPlanV1{}, err
	}
	coordinate := coordinateForCertifiedHead(&result.Certification.Head)
	if prepared.Operation.OperationID == "" {
		prepared, err = backend.provision.PrepareProvisional(ctx, operationID, attempt, record, coordinate)
		if err != nil {
			return ProvisionalPlanV1{}, err
		}
	}
	if err := validatePreparedProvisional(&prepared, operationID, &record, &coordinate); err != nil {
		return ProvisionalPlanV1{}, err
	}
	if err := validateOperationCertification(&result.Certification, prepared.Operation.OperationID,
		DomainProvisionalOperation, prepared.Operation, &result.Certification.ControlSet,
		prepared.Operation.IssuedAt); err != nil {
		return ProvisionalPlanV1{}, err
	}
	return ProvisionalPlanV1{Operation: prepared.Operation, Issuance: prepared.Issuance,
		Profile: prepared.Profile, Result: prepared.Result, Certification: result.Certification,
		IntermediateHeads:     append([]wire.HeadEntryV2(nil), result.IntermediateHeads...),
		ControlSetTransitions: cloneControlSetTransitions(result.ControlSetTransitions)}, nil
}

func (backend *DistributedWorkflowBackend) CollectApproval(ctx context.Context,
	_ VerifiedClaimAttemptV2, record DurableRecord) (wire.StableEnrollmentApprovalQCV2, wire.ControlSetV1, error) {
	evidence, err := backend.readApproval(ctx, record.State.ClusterID, record.State.InviteID, record.State.RequestID)
	if err != nil {
		return wire.StableEnrollmentApprovalQCV2{}, wire.ControlSetV1{}, err
	}
	if err := validateApprovalEvidenceRecord(&evidence, &record); err != nil {
		return wire.StableEnrollmentApprovalQCV2{}, wire.ControlSetV1{}, err
	}
	attestation, set, err := ApprovalAttestationForEvidence(&evidence, backend.now().UTC())
	if err != nil {
		return wire.StableEnrollmentApprovalQCV2{}, wire.ControlSetV1{}, err
	}
	qc, err := backend.approval.CollectApproval(ctx, attestation)
	if err != nil {
		return wire.StableEnrollmentApprovalQCV2{}, wire.ControlSetV1{}, err
	}
	if !wire.EqualCanonical(qc.Attestation, attestation) || wire.VerifyEnrollmentApprovalQC(&qc, &set) != nil {
		return wire.StableEnrollmentApprovalQCV2{}, wire.ControlSetV1{},
			errors.New("[Enrollment] approval quorum 返回错误 exact QC")
	}
	return qc, set, nil
}

func (backend *DistributedWorkflowBackend) CommitCompletion(ctx context.Context,
	_ VerifiedClaimAttemptV2, record DurableRecord, approval wire.StableEnrollmentApprovalQCV2,
	operation CompletionOperationV2) (CompletionCertificationV1, error) {
	if record.ProvisionalCertification == nil || record.ResultArtifact == nil {
		return CompletionCertificationV1{}, errors.New("[Enrollment] completion 缺 durable issuance/result")
	}
	wantID, err := completionOperationID(record, &approval)
	if err != nil || operation.OperationID != wantID {
		return CompletionCertificationV1{}, errors.New("[Enrollment] completion operation ID 不是 exact deterministic ID")
	}
	completed, err := Complete(record.State, operation, &approval, &record.ProvisionalCertification.ControlSet)
	if err != nil {
		return CompletionCertificationV1{}, err
	}
	result, err := backend.sequencer.CommitEnrollmentOperation(ctx, operation.OperationID,
		&record.ProvisionalCertification.Head,
		func(coordinate EnrollmentCommitCoordinateV1) (EnrollmentHeadMutationV1, error) {
			if err := validateCommitCoordinate(&coordinate, operation.ClusterID); err != nil {
				return EnrollmentHeadMutationV1{}, err
			}
			objectID, err := wire.HashObject(DomainCompletionOperation, operation)
			if err != nil {
				return EnrollmentHeadMutationV1{}, err
			}
			refs, err := resultSecretRefsRaw(record.ResultArtifact.SecretArtifactRefs)
			if err != nil {
				return EnrollmentHeadMutationV1{}, err
			}
			view := clonePrivateValue(record.ResultArtifact.InitialDeviceView)
			return EnrollmentHeadMutationV1{OperationLeaf: wire.ControlOperationLeafV1{
				Schema: 1, OperationID: operation.OperationID, ObjectID: objectID},
				InitialDeviceView: &view, SecretArtifactRefs: refs,
				Preimage: &EnrollmentMutationPreimageV1{Schema: 1, Kind: "completion",
					Completion: &EnrollmentCompletionPreimageV1{Record: cloneDurableRecord(record),
						Operation: operation, Approval: approval}}}, nil
		})
	if err != nil {
		return CompletionCertificationV1{}, err
	}
	if result.DeviceViewEnvelope == nil {
		return CompletionCertificationV1{}, errors.New("[Enrollment] completion sequencer 缺同 Head Device view proof")
	}
	certification := CompletionCertificationV1{Schema: 1, Operation: result.Certification,
		IntermediateHeads:     append([]wire.HeadEntryV2(nil), result.IntermediateHeads...),
		ControlSetTransitions: cloneControlSetTransitions(result.ControlSetTransitions),
		DeviceViewEnvelope:    clonePrivateValue(*result.DeviceViewEnvelope)}
	if _, err := validateCompletionCertification(&record, &operation,
		&certification, &completed); err != nil {
		return CompletionCertificationV1{}, err
	}
	return certification, nil
}

func ClaimOperationID(admission *wire.StableEnrollmentAdmissionQCV1) (string, error) {
	if admission == nil {
		return "", errors.New("[Enrollment] claim operation ID 缺 admission QC")
	}
	qcHash, err := wire.EnrollmentAdmissionQCHash(admission)
	if err != nil {
		return "", err
	}
	attestation := admission.Attestation
	return wire.HashObject(DomainClaimOperationID, struct {
		Schema          int    `json:"schema"`
		ClusterID       string `json:"cluster_id"`
		InviteID        string `json:"invite_id"`
		RequestID       string `json:"request_id"`
		ClaimCoreHash   string `json:"claim_core_hash"`
		AdmissionQCHash string `json:"admission_qc_hash"`
	}{Schema: 1, ClusterID: attestation.ClusterID, InviteID: attestation.InviteID,
		RequestID: attestation.RequestID, ClaimCoreHash: attestation.ClaimCoreHash,
		AdmissionQCHash: qcHash})
}

func ProvisionalOperationID(record *DurableRecord) (string, error) {
	if record == nil || record.State.Status != "reserved" {
		return "", errors.New("[Enrollment] provisional operation ID 缺 reserved transaction")
	}
	return wire.HashObject(DomainProvisionalOperationID, struct {
		Schema             int    `json:"schema"`
		ClusterID          string `json:"cluster_id"`
		InviteID           string `json:"invite_id"`
		RequestID          string `json:"request_id"`
		ClaimOperationHash string `json:"claim_operation_hash"`
	}{Schema: 1, ClusterID: record.State.ClusterID, InviteID: record.State.InviteID,
		RequestID: record.State.RequestID, ClaimOperationHash: record.State.ClaimOperationHash})
}

func validatePreparedProvisional(prepared *PreparedProvisionalV1, operationID string,
	record *DurableRecord, coordinate *EnrollmentCommitCoordinateV1) error {
	if prepared == nil || record == nil || coordinate == nil || prepared.Operation.OperationID != operationID ||
		prepared.Operation.IssuedAt != coordinate.CommittedLogicalTime ||
		prepared.Issuance.Body.IssuanceLogCoordinate.RecoveryEpoch != coordinate.RecoveryEpoch ||
		prepared.Issuance.Body.IssuanceLogCoordinate.RaftIndex != coordinate.RaftIndex {
		return errors.New("[Enrollment] provisional first-result 未绑定 sequencer coordinate")
	}
	if err := validateCommitCoordinate(coordinate, record.State.ClusterID); err != nil {
		return err
	}
	if _, err := RecordProvisional(record.State, prepared.Operation); err != nil {
		return err
	}
	if err := validateProvisionalEvidence(&prepared.Operation, &prepared.Issuance,
		&prepared.Profile, &prepared.Result); err != nil {
		return err
	}
	reservationQCHash, err := wire.ConfigQCHash(record.ReservationCertification.ConfigQC)
	if err != nil || prepared.Issuance.Body.ReservationHeadHash != record.ReservationCertification.Head.HeadHash ||
		prepared.Issuance.Body.ReservationHeadQCHash != reservationQCHash {
		return errors.New("[Enrollment] provisional first-result 未绑定 reservation Head/QC")
	}
	return nil
}

func validateApprovalEvidenceRecord(evidence *EnrollmentApprovalEvidenceV1, record *DurableRecord) error {
	if evidence == nil || record == nil || record.ProvisionalOperation == nil ||
		record.ProvisionalIssuance == nil || record.DeviceCertificateProfile == nil || record.ResultArtifact == nil ||
		record.ProvisionalCertification == nil ||
		!wire.EqualCanonical(evidence.Invite, record.Invite) ||
		!wire.EqualCanonical(evidence.ClaimEvidence, record.ClaimEvidence) ||
		!wire.EqualCanonical(evidence.ClaimOperation, record.ClaimOperation) ||
		!wire.EqualCanonical(evidence.AdmissionQC, record.AdmissionQC) ||
		!wire.EqualCanonical(evidence.AdmissionControlSet, record.AdmissionControlSet) ||
		!wire.EqualCanonical(evidence.ReservationBaseHead, record.ReservationBaseHead) ||
		!equalHeadSequences(evidence.BaseToReservationHeads, record.BaseToReservationHeads) ||
		!equalControlSetTransitionSequences(evidence.BaseToReservationTransitions, record.BaseToReservationTransitions) ||
		!wire.EqualCanonical(evidence.Reservation, record.ReservationCertification) ||
		!wire.EqualCanonical(evidence.ProvisionalOperation, *record.ProvisionalOperation) ||
		!wire.EqualCanonical(evidence.ProvisionalIssuance, *record.ProvisionalIssuance) ||
		!wire.EqualCanonical(evidence.DeviceCertificateProfile, *record.DeviceCertificateProfile) ||
		!equalHeadSequences(evidence.IntermediateHeads, record.ReservationToIssuanceHeads) ||
		!equalControlSetTransitionSequences(evidence.ControlSetTransitions, record.ReservationToIssuanceTransitions) ||
		!wire.EqualCanonical(evidence.Issuance, *record.ProvisionalCertification) ||
		!wire.EqualCanonical(evidence.ResultArtifact, *record.ResultArtifact) {
		return errors.New("[Enrollment] approval reader 未返回 exact durable transaction evidence")
	}
	return nil
}

func equalHeadSequences(left, right []wire.HeadEntryV2) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !wire.EqualCanonical(left[index], right[index]) {
			return false
		}
	}
	return true
}

func equalControlSetTransitionSequences(left, right []wire.ControlSetTransitionBundleV1) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !wire.EqualCanonical(left[index], right[index]) {
			return false
		}
	}
	return true
}

func cloneControlSetTransitions(values []wire.ControlSetTransitionBundleV1) []wire.ControlSetTransitionBundleV1 {
	if values == nil {
		return nil
	}
	result := make([]wire.ControlSetTransitionBundleV1, len(values))
	for index := range values {
		result[index] = clonePrivateValue(values[index])
	}
	return result
}

func validateCommitCoordinate(coordinate *EnrollmentCommitCoordinateV1, clusterID string) error {
	if coordinate == nil || coordinate.Schema != 1 || coordinate.ClusterID != clusterID ||
		coordinate.RecoveryEpoch < 0 || coordinate.RaftTerm < 1 || coordinate.RaftIndex < 1 {
		return errors.New("[Raft] enrollment commit coordinate 无效")
	}
	for _, value := range []string{coordinate.PreviousLogEntryHash, coordinate.ParentHeadHash} {
		if _, err := wire.ParseHash(value); err != nil {
			return err
		}
	}
	_, err := wire.ParseTimeZ(coordinate.CommittedLogicalTime)
	return err
}

func coordinateForCertifiedHead(head *wire.HeadEntryV2) EnrollmentCommitCoordinateV1 {
	payload := head.Body.Payload
	return EnrollmentCommitCoordinateV1{Schema: 1, ClusterID: payload.ClusterID,
		RecoveryEpoch: payload.RecoveryEpoch, RaftTerm: payload.RaftTerm,
		RaftIndex: payload.RaftIndex, PreviousLogEntryHash: payload.PreviousLogEntryHash,
		ParentHeadHash: payload.ParentHeadHash, CommittedLogicalTime: payload.CommittedLogicalTime}
}

func validateClaimPrivateEvidencePointer(evidence ClaimPrivateEvidenceV1, operation *ClaimOperationV2) error {
	return validateClaimPrivateEvidence(&evidence, operation)
}
