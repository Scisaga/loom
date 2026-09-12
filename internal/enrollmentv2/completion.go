package enrollmentv2

import (
	"bytes"
	"encoding/json"
	"errors"

	"loom/internal/wire"
)

const DomainCompletionOperationID = "loom-enrollment-completion-operation-id-v1"

// CompletionCertificationV1 证明 exact completion operation 与首次 active Device view
// 同时进入同一份 certified Head；只有该证据存在时才能消费 Invite 和释放结果（D130）。
type CompletionCertificationV1 struct {
	Schema                int                                 `json:"schema"`
	Operation             CertifiedEnrollmentOperationProofV1 `json:"operation"`
	IntermediateHeads     []wire.HeadEntryV2                  `json:"intermediate_heads,omitempty"`
	ControlSetTransitions []wire.ControlSetTransitionBundleV1 `json:"control_set_transitions,omitempty"`
	DeviceViewEnvelope    wire.DeviceViewEnvelopeV2           `json:"device_view_envelope"`
}

// CompletionProjectionV1 是一次原子 apply 的显式结果：Invite、Device 与 artifact
// release 不允许分别落盘，避免崩溃产生“已消费但未激活”或提前交付（D130）。
type CompletionProjectionV1 struct {
	Schema                        int    `json:"schema"`
	InviteStatus                  string `json:"invite_status"`
	DeviceStatus                  string `json:"device_status"`
	ResultReleaseStatus           string `json:"result_release_status"`
	InviteID                      string `json:"invite_id"`
	RequestID                     string `json:"request_id"`
	TokenCommitment               string `json:"token_commitment"`
	ClaimOperationHash            string `json:"claim_operation_hash"`
	CompletionOperationHash       string `json:"completion_operation_hash"`
	CompletionHeadHash            string `json:"completion_head_hash"`
	CompletionHeadQCHash          string `json:"completion_head_qc_hash"`
	DeviceID                      string `json:"device_id"`
	DeviceGeneration              int64  `json:"device_generation"`
	DeviceCertificateHash         string `json:"device_certificate_hash"`
	DeviceViewHash                string `json:"device_view_hash"`
	ResultArtifactHash            string `json:"result_artifact_hash"`
	CompletedTransactionStateHash string `json:"completed_transaction_state_hash"`
}

func completionOperationID(record DurableRecord, approval *wire.StableEnrollmentApprovalQCV2) (string, error) {
	if record.ProvisionalOperation == nil || approval == nil {
		return "", errors.New("[D130 Enrollment] completion operation ID 缺 stable input")
	}
	approvalHash, err := wire.EnrollmentApprovalQCHash(approval)
	if err != nil {
		return "", err
	}
	return wire.HashObject(DomainCompletionOperationID, struct {
		Schema                           int    `json:"schema"`
		ClusterID                        string `json:"cluster_id"`
		InviteID                         string `json:"invite_id"`
		RequestID                        string `json:"request_id"`
		ClaimOperationHash               string `json:"claim_operation_hash"`
		ProvisionalIssuanceOperationHash string `json:"provisional_issuance_operation_hash"`
		EnrollmentApprovalQCHash         string `json:"enrollment_approval_qc_hash"`
	}{Schema: 1, ClusterID: record.State.ClusterID, InviteID: record.State.InviteID,
		RequestID: record.State.RequestID, ClaimOperationHash: record.State.ClaimOperationHash,
		ProvisionalIssuanceOperationHash: record.State.ProvisionalIssuanceOperationHash,
		EnrollmentApprovalQCHash:         approvalHash})
}

func validateCompletionCertification(record *DurableRecord, operation *CompletionOperationV2,
	certification *CompletionCertificationV1, completed *TransactionStateV2) (CompletionProjectionV1, error) {
	if record == nil || operation == nil || certification == nil || completed == nil ||
		record.ResultArtifact == nil || certification.Schema != 1 {
		return CompletionProjectionV1{}, errors.New("[D130 Enrollment] completion certification 输入不完整")
	}
	if certification.Operation.PreviousControlSet != nil {
		return CompletionProjectionV1{}, errors.New("[D130 Enrollment] completion operation 必须由 stable ControlSet 认证")
	}
	completionSet := &certification.Operation.ControlSet
	operationHash, err := wire.HashObject(DomainCompletionOperation, *operation)
	if err != nil {
		return CompletionProjectionV1{}, err
	}
	qcHash, err := verifyCertifiedEnrollmentOperation(&certification.Operation,
		operation.OperationID, operationHash)
	if err != nil {
		return CompletionProjectionV1{}, err
	}
	if record.ProvisionalCertification == nil {
		return CompletionProjectionV1{}, errors.New("[D130 Enrollment] completion 缺 issuance Head certification")
	}
	if err := VerifyEnrollmentHeadLineage(&record.ProvisionalCertification.Head,
		certification.IntermediateHeads, certification.ControlSetTransitions,
		&certification.Operation.Head, completionSet); err != nil {
		return CompletionProjectionV1{}, errors.New("[D130 Enrollment] issuance→completion Head lineage 不连续")
	}
	envelope := &certification.DeviceViewEnvelope
	operationProof := &certification.Operation
	if !wire.EqualCanonical(envelope.SignedCurrent.Head, operationProof.Head) ||
		!equalCanonicalJSON(envelope.SignedCurrent.QuorumCertificate, operationProof.ConfigQC) ||
		!wire.EqualCanonical(envelope.Payload, record.ResultArtifact.InitialDeviceView) {
		return CompletionProjectionV1{}, errors.New("[D130 Enrollment] completion operation/view 未绑定同一 certified Head/result")
	}
	wantRefs, err := resultSecretRefsRaw(record.ResultArtifact.SecretArtifactRefs)
	if err != nil || !equalRawMessages(envelope.SecretArtifactRefs, wantRefs) {
		return CompletionProjectionV1{}, errors.New("[D124 secret artifact] completion view 未携 exact result secret refs")
	}
	floors, err := wire.VerifyDeviceViewEnvelope(envelope, completionSet)
	if err != nil {
		return CompletionProjectionV1{}, err
	}
	view := &record.ResultArtifact.InitialDeviceView
	intent := &record.ClaimEvidence.Opening.DeviceEnrollmentIntent
	if view.Active == nil || view.DeviceGeneration != 1 || envelope.Leaf.PreviousViewHash != wire.EmptyHashV1 ||
		view.DeviceID != intent.DeviceID || view.Active.IdentitySPKIHash != record.State.IdentityKeyHash ||
		!wire.EqualCanonical(view.Active.Membership, intent.Membership) ||
		!wire.EqualCanonical(view.Active.Responsibilities, intent.Responsibilities) ||
		!wire.EqualCanonical(view.Active.Grants, intent.Grants) || floors.DeviceViewHash == "" {
		return CompletionProjectionV1{}, errors.New("[D130 Enrollment] completion active Device projection 与 admitted intent 不一致")
	}
	certificateDER, err := wire.EnrollmentResultCertificateDER(record.ResultArtifact)
	if err != nil {
		return CompletionProjectionV1{}, err
	}
	certificateHash, err := wire.DeviceCertificateHash(certificateDER)
	if err != nil {
		return CompletionProjectionV1{}, err
	}
	resultHash, err := wire.EnrollmentResultArtifactHash(record.ResultArtifact)
	if err != nil {
		return CompletionProjectionV1{}, err
	}
	transactionHash, err := TransactionHash(*completed)
	if err != nil {
		return CompletionProjectionV1{}, err
	}
	projection := CompletionProjectionV1{Schema: 1, InviteStatus: "consumed", DeviceStatus: "active",
		ResultReleaseStatus: "authorized", InviteID: record.InviteID, RequestID: record.State.RequestID,
		TokenCommitment: record.TokenCommitment, ClaimOperationHash: record.State.ClaimOperationHash,
		CompletionOperationHash: operationHash, CompletionHeadHash: operationProof.Head.HeadHash,
		CompletionHeadQCHash: qcHash, DeviceID: view.DeviceID, DeviceGeneration: view.DeviceGeneration,
		DeviceCertificateHash: certificateHash, DeviceViewHash: floors.DeviceViewHash,
		ResultArtifactHash: resultHash, CompletedTransactionStateHash: transactionHash}
	return projection, nil
}

func resultSecretRefsRaw(refs []wire.SecretArtifactRefV2) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, 0, len(refs))
	for index := range refs {
		value, err := wire.MarshalCanonical(refs[index])
		if err != nil {
			return nil, err
		}
		result = append(result, json.RawMessage(value))
	}
	return result, nil
}

func equalRawMessages(left, right []json.RawMessage) bool {
	if left == nil || right == nil || len(left) != len(right) {
		return false
	}
	for index := range left {
		if !equalCanonicalJSON(left[index], right[index]) {
			return false
		}
	}
	return true
}

func equalCanonicalJSON(left, right []byte) bool {
	leftCanonical, leftErr := wire.CanonicalizeStrict(left)
	rightCanonical, rightErr := wire.CanonicalizeStrict(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftCanonical, rightCanonical)
}
