package enrollmentv2

import (
	"bytes"
	"errors"

	"loom/internal/wire"
)

// EnrollmentProgressReceiptV1 给尚未 completed 的客户端一份不含 token 的
// certified transaction projection，使带外 resume descriptor 可以与本机 pending
// claim 比较，而不是让客户端相信管理员抄来的裸 hash（D130）。
type EnrollmentProgressReceiptV1 struct {
	Schema                           int                                  `json:"schema"`
	Invite                           InviteContext                        `json:"invite"`
	ClaimEvidence                    ClaimPrivateEvidenceV1               `json:"claim_evidence"`
	ClaimOperation                   ClaimOperationV2                     `json:"claim_operation"`
	AdmissionQC                      wire.StableEnrollmentAdmissionQCV1   `json:"admission_qc"`
	AdmissionControlSet              wire.ControlSetV1                    `json:"admission_control_set"`
	ReservationBaseHead              wire.HeadEntryV2                     `json:"reservation_base_head"`
	BaseToReservationHeads           []wire.HeadEntryV2                   `json:"base_to_reservation_heads,omitempty"`
	BaseToReservationTransitions     []wire.ControlSetTransitionBundleV1  `json:"base_to_reservation_transitions,omitempty"`
	ReservationCertification         CertifiedEnrollmentOperationProofV1  `json:"reservation_certification"`
	ProvisionalOperation             *ProvisionalIssuanceOperationV1      `json:"provisional_operation,omitempty"`
	ProvisionalCertification         *CertifiedEnrollmentOperationProofV1 `json:"provisional_certification,omitempty"`
	ReservationToIssuanceHeads       []wire.HeadEntryV2                   `json:"reservation_to_issuance_heads,omitempty"`
	ReservationToIssuanceTransitions []wire.ControlSetTransitionBundleV1  `json:"reservation_to_issuance_transitions,omitempty"`
}

type EnrollmentProgressExpectedV1 struct {
	Record         wire.CertifiedInviteRecordV2
	Policy         wire.InviteIssuancePolicyV2
	Opening        wire.DeviceEnrollmentIntentOpeningV1
	ClaimCore      wire.EnrollmentClaimCoreV2
	BaseHead       wire.HeadEntryV2
	BaseControlSet wire.ControlSetV1
}

type VerifiedEnrollmentProgressV1 struct {
	status   string
	expected wire.EnrollmentResumeExpectedV1
}

func (verified VerifiedEnrollmentProgressV1) Status() string {
	return verified.status
}

func (verified VerifiedEnrollmentProgressV1) ResumeExpected() wire.EnrollmentResumeExpectedV1 {
	return verified.expected
}

func progressReceiptForRecord(record *DurableRecord) ([]byte, error) {
	if record == nil || (record.State.Status != "reserved" && record.State.Status != "issued_provisional") {
		return nil, errors.New("[D130 Enrollment] progress receipt transaction state 无效")
	}
	receipt := EnrollmentProgressReceiptV1{
		Schema: 1, Invite: record.Invite, ClaimEvidence: record.ClaimEvidence,
		ClaimOperation: record.ClaimOperation, AdmissionQC: record.AdmissionQC,
		AdmissionControlSet: record.AdmissionControlSet, ReservationBaseHead: record.ReservationBaseHead,
		BaseToReservationHeads:       append([]wire.HeadEntryV2(nil), record.BaseToReservationHeads...),
		BaseToReservationTransitions: cloneControlSetTransitions(record.BaseToReservationTransitions),
		ReservationCertification:     record.ReservationCertification,
	}
	if record.State.Status == "issued_provisional" {
		if record.ProvisionalOperation == nil || record.ProvisionalCertification == nil {
			return nil, errors.New("[D130 Enrollment] issued progress receipt 缺 provisional proof")
		}
		operation := clonePrivateValue(*record.ProvisionalOperation)
		certification := clonePrivateValue(*record.ProvisionalCertification)
		receipt.ProvisionalOperation = &operation
		receipt.ProvisionalCertification = &certification
		receipt.ReservationToIssuanceHeads = append([]wire.HeadEntryV2(nil), record.ReservationToIssuanceHeads...)
		receipt.ReservationToIssuanceTransitions = cloneControlSetTransitions(record.ReservationToIssuanceTransitions)
	}
	return wire.MarshalCanonical(receipt)
}

// VerifyEnrollmentProgressReceipt 从本机 claim 与 Invite proof 重放到服务端声明的
// 当前事务状态，并产生带外 resume 验证所需的全部 exact hash（D129、D130）。
func VerifyEnrollmentProgressReceipt(raw []byte, result *wire.EnrollmentClaimResultV2,
	expected EnrollmentProgressExpectedV1) (VerifiedEnrollmentProgressV1, error) {
	if len(raw) == 0 || result == nil ||
		(result.Status != "reserved" && result.Status != "issued_provisional") {
		return VerifiedEnrollmentProgressV1{}, errors.New("[D130 client] progress receipt/context 不完整")
	}
	var receipt EnrollmentProgressReceiptV1
	canonical, err := wire.DecodeStrict(raw, 32<<20, &receipt)
	if err != nil || !bytes.Equal(canonical, raw) || receipt.Schema != 1 {
		return VerifiedEnrollmentProgressV1{}, errors.New("[D130 client] progress receipt 不是 exact canonical wire")
	}
	if err := wire.ValidateCertifiedInviteRecord(&expected.Record, &expected.Policy); err != nil {
		return VerifiedEnrollmentProgressV1{}, err
	}
	if err := wire.ValidateIntentOpening(&expected.Opening); err != nil {
		return VerifiedEnrollmentProgressV1{}, err
	}
	coreHash, err := wire.EnrollmentClaimCoreHash(&expected.ClaimCore)
	if err != nil {
		return VerifiedEnrollmentProgressV1{}, err
	}
	identityHash, wrappingHash, csrHash, err := wire.EnrollmentClaimBinaryHashes(&expected.ClaimCore)
	if err != nil {
		return VerifiedEnrollmentProgressV1{}, err
	}
	recordHash, _ := wire.CertifiedInviteRecordHash(&expected.Record, &expected.Policy)
	openingHash, _ := wire.IntentOpeningHash(&expected.Opening)
	intentHash, _ := wire.EnrollmentIntentHash(&expected.Opening.DeviceEnrollmentIntent)
	baseSetHash, setErr := wire.ControlSetHash(&expected.BaseControlSet)
	if setErr != nil || expected.ClaimCore.CertifiedInviteRecordHash != recordHash ||
		expected.ClaimCore.DeviceEnrollmentIntentCommitmentHash != expected.Record.DeviceEnrollmentIntentCommitmentHash ||
		expected.ClaimCore.DeviceEnrollmentIntentOpeningHash != openingHash ||
		expected.ClaimCore.AcceptedDeviceEnrollmentIntentHash != intentHash ||
		expected.ClaimCore.BaseHeadHash != expected.BaseHead.HeadHash ||
		expected.ClaimCore.BaseRecoveryEpoch != expected.BaseHead.Body.Payload.RecoveryEpoch ||
		expected.ClaimCore.BaseControlEpoch != expected.BaseHead.Body.Payload.ControlEpoch ||
		expected.ClaimCore.BaseControlSetHash != baseSetHash ||
		expected.BaseHead.Body.Payload.ControlSetHash != baseSetHash {
		return VerifiedEnrollmentProgressV1{}, errors.New("[D130 client] 本机 claim 未绑定已验 Invite authority")
	}
	wantInvite := InviteContext{
		ClusterID: expected.Record.ClusterID, InviteID: expected.Record.InviteID, Status: "available",
		CertifiedInviteRecordHash:            recordHash,
		DeviceEnrollmentIntentCommitmentHash: expected.Record.DeviceEnrollmentIntentCommitmentHash,
		DeviceEnrollmentIntentOpeningHash:    openingHash, TokenCommitment: expected.Record.TokenCommitment,
		ExpiresAt:                      expected.Record.ExpiresAt,
		MaximumReservationRetrySeconds: expected.Policy.MaximumReservationRetrySeconds,
	}
	wantEvidence := ClaimPrivateEvidenceV1{Schema: 1, Opening: expected.Opening,
		WrappingPublicKey:  expected.ClaimCore.WrappingPublicKey,
		WrappingKeyProfile: expected.ClaimCore.WrappingKeyProfile}
	operation := &receipt.ClaimOperation
	if !wire.EqualCanonical(receipt.Invite, wantInvite) ||
		!wire.EqualCanonical(receipt.ClaimEvidence, wantEvidence) ||
		!wire.EqualCanonical(receipt.AdmissionControlSet, expected.BaseControlSet) ||
		!wire.EqualCanonical(receipt.ReservationBaseHead, expected.BaseHead) ||
		operation.ClusterID != expected.ClaimCore.ClusterID || operation.InviteID != expected.ClaimCore.InviteID ||
		operation.RequestID != expected.ClaimCore.RequestID || operation.CertifiedInviteRecordHash != recordHash ||
		operation.DeviceEnrollmentIntentCommitmentHash != expected.Record.DeviceEnrollmentIntentCommitmentHash ||
		operation.DeviceEnrollmentIntentOpeningHash != openingHash || operation.TokenCommitment != expected.Record.TokenCommitment ||
		operation.ClaimCoreHash != coreHash || operation.IdentityKeyHash != identityHash ||
		operation.WrappingKeyHash != wrappingHash || operation.CSRHash != csrHash {
		return VerifiedEnrollmentProgressV1{}, errors.New("[D130 client] progress receipt 未绑定本机 stable claim/core/key")
	}
	reserved, err := Reserve(receipt.Invite, receipt.ClaimOperation, &receipt.AdmissionQC,
		&receipt.AdmissionControlSet, receipt.ClaimOperation.ReservedAt)
	if err != nil {
		return VerifiedEnrollmentProgressV1{}, err
	}
	if err := validateClaimPrivateEvidence(&receipt.ClaimEvidence, &receipt.ClaimOperation); err != nil {
		return VerifiedEnrollmentProgressV1{}, err
	}
	if err := validateOperationCertification(&receipt.ReservationCertification,
		receipt.ClaimOperation.OperationID, DomainClaimOperation, receipt.ClaimOperation,
		&receipt.ReservationCertification.ControlSet, receipt.ClaimOperation.ReservedAt); err != nil {
		return VerifiedEnrollmentProgressV1{}, err
	}
	if err := validateReservationHeadLineage(&receipt.ReservationBaseHead,
		receipt.BaseToReservationHeads, receipt.BaseToReservationTransitions,
		&receipt.ReservationCertification, &receipt.AdmissionQC,
		&receipt.AdmissionControlSet); err != nil {
		return VerifiedEnrollmentProgressV1{}, err
	}
	state := reserved
	if result.Status == "reserved" {
		if receipt.ProvisionalOperation != nil || receipt.ProvisionalCertification != nil ||
			len(receipt.ReservationToIssuanceHeads) != 0 || len(receipt.ReservationToIssuanceTransitions) != 0 {
			return VerifiedEnrollmentProgressV1{}, errors.New("[D130 client] reserved receipt 提前携 provisional proof")
		}
	} else {
		if receipt.ProvisionalOperation == nil || receipt.ProvisionalCertification == nil {
			return VerifiedEnrollmentProgressV1{}, errors.New("[D130 client] issued receipt 缺 provisional proof")
		}
		state, err = RecordProvisional(reserved, *receipt.ProvisionalOperation)
		if err != nil {
			return VerifiedEnrollmentProgressV1{}, err
		}
		if err := validateOperationCertification(receipt.ProvisionalCertification,
			receipt.ProvisionalOperation.OperationID, DomainProvisionalOperation,
			*receipt.ProvisionalOperation, &receipt.ProvisionalCertification.ControlSet,
			receipt.ProvisionalOperation.IssuedAt); err != nil {
			return VerifiedEnrollmentProgressV1{}, err
		}
		if err := VerifyEnrollmentHeadLineage(&receipt.ReservationCertification.Head,
			receipt.ReservationToIssuanceHeads, receipt.ReservationToIssuanceTransitions,
			&receipt.ProvisionalCertification.Head,
			&receipt.ProvisionalCertification.ControlSet); err != nil {
			return VerifiedEnrollmentProgressV1{}, err
		}
	}
	stateHash, err := TransactionHash(state)
	if err != nil || stateHash != result.TransactionStateHash {
		return VerifiedEnrollmentProgressV1{}, errors.New("[D130 client] progress transaction state hash 不可重放")
	}
	claimOperationHash, _ := wire.HashObject(DomainClaimOperation, receipt.ClaimOperation)
	admissionQCHash, _ := wire.EnrollmentAdmissionQCHash(&receipt.AdmissionQC)
	return VerifiedEnrollmentProgressV1{status: result.Status, expected: wire.EnrollmentResumeExpectedV1{
		ClusterID: expected.ClaimCore.ClusterID, InviteID: expected.ClaimCore.InviteID,
		RequestID: expected.ClaimCore.RequestID, ClaimCoreHash: coreHash,
		ClaimOperationHash: claimOperationHash, AdmissionQCHash: admissionQCHash,
		CSRHash: csrHash, IdentityKeyHash: identityHash, WrappingKeyHash: wrappingHash,
		EnrollmentTransactionStateHash: stateHash, RetryNotAfter: receipt.ClaimOperation.RetryNotAfter,
	}}, nil
}
