package main

import (
	"context"
	"errors"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

// 在新的业务提交前回收已过认证 retry deadline 的事务。没有轮询、网络
// 探测或本地释放；状态变更仍使用同一 sequencer 的 Raft/QC 和原日志。
func (runtime *controlRuntime) expireEnrollmentTransactions(ctx context.Context) error {
	runtime.mu.Lock()
	activated := false
	for _, record := range runtime.journal.Records {
		if record.Result == nil {
			// 原提交的恢复必须先完成；回收不能挡住其幂等重试。
			runtime.mu.Unlock()
			return nil
		}
		activated = activated || record.Activation != nil
	}
	if !activated {
		runtime.mu.Unlock()
		return nil
	}
	history, err := runtime.certifiedApplicationsLocked()
	var application *controlApplicationV1
	if len(history) > 0 {
		application = history[len(history)-1]
	}
	var records []enrollmentv2.DurableRecord
	if err == nil && application != nil {
		for _, transaction := range application.Transactions {
			if transaction.Status != "reserved" && transaction.Status != "issued_provisional" {
				continue
			}
			record, found := runtime.enrollmentStore.SnapshotRecord(transaction.InviteID)
			if !found || !wire.EqualCanonical(record.State, transaction) {
				err = errors.New("[Enrollment] 待回收事务与认证日志不一致")
				break
			}
			deadline, parseErr := wire.ParseTimeZ(record.ClaimOperation.RetryNotAfter)
			if parseErr != nil {
				err = parseErr
				break
			}
			if !runtime.now().UTC().Before(deadline) {
				records = append(records, record)
			}
		}
	}
	runtime.mu.Unlock()
	if err != nil {
		return err
	}
	for _, record := range records {
		operation, err := enrollmentv2.TransactionExpiryOperation(record)
		if err != nil {
			return err
		}
		from := &record.ReservationCertification.Head
		if record.ProvisionalCertification != nil {
			from = &record.ProvisionalCertification.Head
		}
		_, err = runtime.CommitEnrollmentOperation(ctx, operation.OperationID, from,
			func(coordinate enrollmentv2.EnrollmentCommitCoordinateV1) (enrollmentv2.EnrollmentHeadMutationV1, error) {
				if _, err := enrollmentv2.ExpireTransaction(record, operation, coordinate.CommittedLogicalTime); err != nil {
					return enrollmentv2.EnrollmentHeadMutationV1{}, err
				}
				hash, err := wire.HashObject(enrollmentv2.DomainExpiryOperation, operation)
				return enrollmentv2.EnrollmentHeadMutationV1{
					OperationLeaf: wire.ControlOperationLeafV1{Schema: 1, OperationID: operation.OperationID, ObjectID: hash},
					Preimage:      &enrollmentv2.EnrollmentMutationPreimageV1{Schema: 1, Kind: "expiry", Expiry: &enrollmentv2.EnrollmentExpiryPreimageV1{Record: record, Operation: operation}}}, err
			})
		if err != nil {
			return err
		}
	}
	return nil
}
