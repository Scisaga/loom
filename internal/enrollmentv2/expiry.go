package enrollmentv2

import (
	"errors"

	"loom/internal/wire"
)

const DomainExpiryOperation = "loom-enrollment-expiry-operation-v1"

// 已认证 reservation 的 retry deadline 是不可延长的上界。过期仅终止该事务，
// 保留 token 占用和签发记录；不能生成新 claim、重新签发或释放任何 Device 材料。
type EnrollmentExpiryOperationV1 struct {
	Schema                       int    `json:"schema"`
	OperationID                  string `json:"operation_id"`
	ClusterID                    string `json:"cluster_id"`
	InviteID                     string `json:"invite_id"`
	RequestID                    string `json:"request_id"`
	ExpectedTransactionStateHash string `json:"expected_transaction_state_hash"`
	RetryNotAfter                string `json:"retry_not_after"`
}

type EnrollmentExpiryPreimageV1 struct {
	Record    DurableRecord               `json:"record"`
	Operation EnrollmentExpiryOperationV1 `json:"operation"`
}

type EnrollmentExpiryEvidenceV1 struct {
	Operation             EnrollmentExpiryOperationV1         `json:"operation"`
	Certification         CertifiedEnrollmentOperationProofV1 `json:"certification"`
	IntermediateHeads     []wire.HeadEntryV2                  `json:"intermediate_heads,omitempty"`
	ControlSetTransitions []wire.ControlSetTransitionBundleV1 `json:"control_set_transitions,omitempty"`
}

func TransactionExpiryOperation(record DurableRecord) (EnrollmentExpiryOperationV1, error) {
	state := record.State
	if state.Status != "reserved" && state.Status != "issued_provisional" {
		return EnrollmentExpiryOperationV1{}, errors.New("[Enrollment] 只能终止未完成的过期事务")
	}
	hash, err := TransactionHash(state)
	if err != nil {
		return EnrollmentExpiryOperationV1{}, err
	}
	id, err := wire.HashObject("loom-enrollment-expiry-operation-id-v1", hash)
	return EnrollmentExpiryOperationV1{1, id, state.ClusterID, state.InviteID, state.RequestID, hash, record.ClaimOperation.RetryNotAfter}, err
}

func ExpireTransaction(record DurableRecord, operation EnrollmentExpiryOperationV1, at string) (TransactionStateV2, error) {
	state := record.State
	want, err := TransactionExpiryOperation(record)
	if err != nil || !wire.EqualCanonical(want, operation) {
		return TransactionStateV2{}, errors.New("[Enrollment] 过期操作未绑定原事务")
	}
	deadline, err := wire.ParseTimeZ(record.ClaimOperation.RetryNotAfter)
	if err != nil {
		return TransactionStateV2{}, err
	}
	instant, err := wire.ParseTimeZ(at)
	if err != nil || instant.Before(deadline) {
		return TransactionStateV2{}, errors.New("[Enrollment] 尚未到达认证的 retry deadline")
	}
	return Abort(state)
}

func validateExpiryRecord(record *DurableRecord) error {
	if record.Expiry == nil || record.State.Status != "aborted" {
		return errors.New("[Enrollment] 终止事务缺认证证据")
	}
	previous := cloneDurableRecord(*record)
	evidence := previous.Expiry
	previous.Expiry = nil
	previous.State.Status = "reserved"
	from := &previous.ReservationCertification.Head
	if previous.ProvisionalOperation != nil {
		previous.State.Status = "issued_provisional"
		if previous.ProvisionalCertification == nil {
			return errors.New("[Enrollment] 缺原签发认证")
		}
		from = &previous.ProvisionalCertification.Head
	}
	if err := validateDurableRecord(&previous); err != nil {
		return err
	}
	cert := &evidence.Certification
	next, err := ExpireTransaction(previous, evidence.Operation, cert.Head.Body.Payload.CommittedLogicalTime)
	if err != nil || !wire.EqualCanonical(next, record.State) {
		return errors.New("[Enrollment] 终止状态与原事务、期限不一致")
	}
	if err := validateOperationCertification(cert, evidence.Operation.OperationID, DomainExpiryOperation, evidence.Operation,
		&cert.ControlSet, cert.Head.Body.Payload.CommittedLogicalTime); err != nil {
		return err
	}
	return VerifyEnrollmentHeadLineage(from, evidence.IntermediateHeads, evidence.ControlSetTransitions, &cert.Head, &cert.ControlSet)
}

func (s *Store) Expire(evidence EnrollmentExpiryEvidenceV1) (TransactionStateV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneDurableState(s.state)
	for i, record := range next.Records {
		if record.InviteID != evidence.Operation.InviteID {
			continue
		}
		if record.Expiry != nil {
			if !wire.EqualCanonical(*record.Expiry, evidence) {
				return TransactionStateV2{}, errors.New("[Enrollment] 终止重放与首份结果不一致")
			}
			return record.State, nil
		}
		state, err := ExpireTransaction(record, evidence.Operation, evidence.Certification.Head.Body.Payload.CommittedLogicalTime)
		if err != nil {
			return TransactionStateV2{}, err
		}
		record.State, record.Expiry = state, &evidence
		next.Records[i] = record
		if err := validateDurableState(&next); err != nil {
			return TransactionStateV2{}, err
		}
		if err := s.persistLocked(next); err != nil {
			return TransactionStateV2{}, err
		}
		s.state = cloneDurableState(next)
		return state, nil
	}
	return TransactionStateV2{}, errors.New("[Enrollment] 终止操作缺原事务")
}
