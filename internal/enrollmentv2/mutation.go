package enrollmentv2

import (
	"errors"

	"loom/internal/wire"
)

// EnrollmentMutationPreimageV1 是全局控制日志的私有输入。各分支恰有一个；
// 不保存 raw token、CSR、challenge 或 detached PoP。Admission QC 承诺其验签结果。
type EnrollmentMutationPreimageV1 struct {
	Schema      int                              `json:"schema"`
	Kind        string                           `json:"kind"`
	Reservation *EnrollmentReservationPreimageV1 `json:"reservation,omitempty"`
	Provisional *EnrollmentProvisionalPreimageV1 `json:"provisional,omitempty"`
	Completion  *EnrollmentCompletionPreimageV1  `json:"completion,omitempty"`
	Expiry      *EnrollmentExpiryPreimageV1      `json:"expiry,omitempty"`
}

type EnrollmentReservationPreimageV1 struct {
	Material  InviteMaterialV2                   `json:"material"`
	Evidence  ClaimPrivateEvidenceV1             `json:"evidence"`
	Operation ClaimOperationV2                   `json:"operation"`
	Admission wire.StableEnrollmentAdmissionQCV1 `json:"admission"`
}

type EnrollmentProvisionalPreimageV1 struct {
	Record   DurableRecord         `json:"record"`
	Prepared PreparedProvisionalV1 `json:"prepared"`
}

type EnrollmentCompletionPreimageV1 struct {
	Record    DurableRecord                     `json:"record"`
	Operation CompletionOperationV2             `json:"operation"`
	Approval  wire.StableEnrollmentApprovalQCV2 `json:"approval"`
}

// ReduceEnrollmentMutation 重算单个事务的候选状态。current 来自全局 certified
// 投影，不能由请求替换；返回值仍须经过 Raft commit/QC 才能生效。
// issuance registry 和其他 Device 的唯一性由全局 projector 另外检查。
func ReduceEnrollmentMutation(mutation EnrollmentHeadMutationV1, current *TransactionStateV2,
	coordinate EnrollmentCommitCoordinateV1) (TransactionStateV2, error) {
	fail := func() (TransactionStateV2, error) {
		return TransactionStateV2{}, errors.New("[D130 Enrollment] mutation preimage/leaf/CAS 不一致")
	}
	p := mutation.Preimage
	if p == nil || p.Schema != 1 || mutation.OperationLeaf.Schema != 1 {
		return fail()
	}
	branches := 0
	for _, exists := range []bool{p.Reservation != nil, p.Provisional != nil, p.Completion != nil, p.Expiry != nil} {
		if exists {
			branches++
		}
	}
	if branches != 1 {
		return fail()
	}
	var state TransactionStateV2
	var objectID, operationID string
	var err error
	switch {
	case p.Kind == "reservation" && p.Reservation != nil:
		r := p.Reservation
		if current != nil || mutation.InitialDeviceView != nil || len(mutation.SecretArtifactRefs) != 0 ||
			r.Operation.ReservedAt != coordinate.CommittedLogicalTime {
			return fail()
		}
		if err := validateCertifiedInviteMaterial(&r.Material, coordinate.ClusterID, r.Operation.InviteID); err != nil {
			return TransactionStateV2{}, err
		}
		if err := validateClaimPrivateEvidence(&r.Evidence, &r.Operation); err != nil {
			return TransactionStateV2{}, err
		}
		if !wire.EqualCanonical(r.Evidence.Opening, r.Material.Opening) {
			return fail()
		}
		recordHash, err := wire.CertifiedInviteRecordHash(&r.Material.Record, &r.Material.Policy)
		if err != nil || recordHash != r.Operation.CertifiedInviteRecordHash {
			return fail()
		}
		invite := InviteContext{ClusterID: r.Material.Record.ClusterID, InviteID: r.Material.Record.InviteID,
			Status: r.Material.Status, CertifiedInviteRecordHash: recordHash,
			DeviceEnrollmentIntentCommitmentHash: r.Operation.DeviceEnrollmentIntentCommitmentHash,
			DeviceEnrollmentIntentOpeningHash:    r.Operation.DeviceEnrollmentIntentOpeningHash,
			TokenCommitment:                      r.Material.Record.TokenCommitment, ExpiresAt: r.Material.Record.ExpiresAt,
			MaximumReservationRetrySeconds: r.Material.Policy.MaximumReservationRetrySeconds}
		operationID, err = ClaimOperationID(&r.Admission)
		if err != nil || operationID != r.Operation.OperationID {
			return fail()
		}
		state, err = Reserve(invite, r.Operation, &r.Admission, &r.Material.ControlSet, coordinate.CommittedLogicalTime)
		if err != nil {
			return TransactionStateV2{}, err
		}
		objectID, err = wire.HashObject(DomainClaimOperation, r.Operation)
	case p.Kind == "provisional" && p.Provisional != nil:
		r := p.Provisional
		if current == nil || !wire.EqualCanonical(*current, r.Record.State) ||
			mutation.InitialDeviceView != nil || len(mutation.SecretArtifactRefs) != 0 {
			return fail()
		}
		if err := validateDurableRecord(&r.Record); err != nil {
			return TransactionStateV2{}, err
		}
		operationID, err = ProvisionalOperationID(&r.Record)
		if err != nil {
			return fail()
		}
		if err := validatePreparedProvisional(&r.Prepared, operationID, &r.Record, &coordinate); err != nil {
			return TransactionStateV2{}, err
		}
		state, err = RecordProvisional(*current, r.Prepared.Operation)
		if err != nil {
			return TransactionStateV2{}, err
		}
		objectID, err = wire.HashObject(DomainProvisionalOperation, r.Prepared.Operation)
	case p.Kind == "completion" && p.Completion != nil:
		r := p.Completion
		if current == nil || !wire.EqualCanonical(*current, r.Record.State) ||
			r.Record.ResultArtifact == nil || r.Record.ProvisionalCertification == nil ||
			mutation.InitialDeviceView == nil ||
			!wire.EqualCanonical(*mutation.InitialDeviceView, r.Record.ResultArtifact.InitialDeviceView) {
			return fail()
		}
		if err := validateDurableRecord(&r.Record); err != nil {
			return TransactionStateV2{}, err
		}
		refs, err := resultSecretRefsRaw(r.Record.ResultArtifact.SecretArtifactRefs)
		if err != nil || !wire.EqualCanonical(refs, mutation.SecretArtifactRefs) {
			return fail()
		}
		if err := validateApprovalAgainstIssuance(&r.Record, &r.Approval); err != nil {
			return TransactionStateV2{}, err
		}
		operationID, err = completionOperationID(r.Record, &r.Approval)
		if err != nil || operationID != r.Operation.OperationID {
			return fail()
		}
		state, err = Complete(*current, r.Operation, &r.Approval, &r.Record.ProvisionalCertification.ControlSet)
		if err != nil {
			return TransactionStateV2{}, err
		}
		objectID, err = wire.HashObject(DomainCompletionOperation, r.Operation)
	case p.Kind == "expiry" && p.Expiry != nil:
		r := p.Expiry
		if current == nil || !wire.EqualCanonical(*current, r.Record.State) || mutation.InitialDeviceView != nil || len(mutation.SecretArtifactRefs) != 0 {
			return fail()
		}
		if err := validateDurableRecord(&r.Record); err != nil {
			return TransactionStateV2{}, err
		}
		state, err = ExpireTransaction(r.Record, r.Operation, coordinate.CommittedLogicalTime)
		operationID = r.Operation.OperationID
		if err == nil {
			objectID, err = wire.HashObject(DomainExpiryOperation, r.Operation)
		}
	default:
		return fail()
	}
	if err != nil || mutation.OperationLeaf.ObjectID != objectID || mutation.OperationLeaf.OperationID != operationID ||
		state.ClusterID != coordinate.ClusterID {
		return fail()
	}
	if err := validateCommitCoordinate(&coordinate, state.ClusterID); err != nil {
		return TransactionStateV2{}, err
	}
	return state, nil
}
