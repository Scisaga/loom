package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"time"

	"loom/internal/controlplane"
	"loom/internal/wire"
)

const controlActivationKind = "local_runtime_activation"

var controlActivationSchemas = wire.OperationSchemaRegistry{controlActivationKind: 1}

// 原始 owner 与 v1 platform 签名授权迁移，当前 admin 另签 exact statement
// 留下操作者归属。所有这些输入和实际 application 一同在原 operation journal 落盘。
type controlRuntimeActivationV1 struct {
	Bundle                wire.RuntimeActivationBundleV1 `json:"bundle"`
	Application           controlApplicationV1           `json:"application"`
	PreviousAuthorization wire.AdminAuthorizationV1      `json:"previous_authorization"`
	PreviousProfile       wire.AdminCertificateProfileV1 `json:"previous_profile"`
}

func (runtime *controlRuntime) verifyActivationRecord(index int) error {
	record := runtime.journal.Records[index]
	activation := record.Activation
	if activation == nil || record.AdminRotation != nil || record.Enrollment != nil || record.Invite != nil || record.DevicePublication != nil || record.BootstrapAdvertisement != nil || len(record.AdditionalLeaves) != 0 ||
		record.Operation.Body.Kind != controlActivationKind {
		return errors.New("[D104 activation] journal union 无效")
	}
	for i := 0; i < index; i++ {
		if runtime.journal.Records[i].Activation != nil {
			return errors.New("[D104 activation] 禁止重复迁移")
		}
	}
	bundle, statement := &activation.Bundle, &activation.Bundle.Proof.Statement
	var parent *wire.HeadEntryV2
	for _, log := range runtime.storage.SnapshotRaft().Log {
		if log.Head != nil && log.Head.HeadHash == statement.ParentHeadHash {
			parent = log.Head
			break
		}
	}
	if parent == nil || !wire.EqualCanonical(*parent, bundle.Parent) || !wire.EqualCanonical(runtime.config.ControlSet, bundle.ControlSet) {
		return errors.New("[D104 activation] 原 parent/ControlSet 不属于当前日志")
	}
	roots, err := activation.Application.roots()
	if err != nil {
		return err
	}
	if !wire.EqualCanonical(roots, statement.Roots) || !wire.EqualCanonical(activation.Application.RecoveryPolicy, bundle.RecoveryPolicy) {
		return errors.New("[D104 activation] 实际 application 与 owner 签署的迁移不一致")
	}
	migrationRoot, err := wire.RuntimeDeviceMigrationRoot(activation.Application.DeviceMigrations)
	if err != nil || migrationRoot != statement.DeviceMigrationRoot {
		return errors.New("[设备迁移] 实际逐设备身份/floor 与原 owner 签名不一致")
	}
	for _, migration := range activation.Application.DeviceMigrations {
		if migration.Issuance.RecoveryEpoch != record.Candidate.Body.Payload.RecoveryEpoch ||
			migration.Issuance.RaftIndex != record.Candidate.Body.Payload.RaftIndex {
			return errors.New("[设备迁移] 原身份签发坐标未进入实际迁移日志")
		}
		profileFound := false
		for _, profile := range activation.Application.CARegistry.DeviceProfiles {
			hash, err := wire.DeviceCertificateProfileStateHash(&profile)
			if err == nil && hash == migration.DeviceCertificateProfileHash && profile.Status == "active" {
				profileFound = true
			}
		}
		if !profileFound {
			return errors.New("[设备迁移] 原身份的证书 profile 不属于迁移后的 active CA registry")
		}
	}
	var matchingControl bool
	for _, service := range activation.Application.Services {
		if service.Role == "control_api" {
			matchingControl = wire.EqualCanonical(service, runtime.config.ControlService)
		}
	}
	if !matchingControl {
		return errors.New("[D131 activation] 迁移改变了原 control 服务身份")
	}
	at, err := wire.ParseTimeZ(record.Candidate.Body.Payload.CommittedLogicalTime)
	if err != nil {
		return err
	}
	if err := wire.VerifyRecoveryPrivateCustody(&activation.Application.RecoveryPolicy, &activation.Application.RecoveryCustody, at, 0); err != nil {
		return err
	}
	old, profile := activation.PreviousAuthorization, activation.PreviousProfile
	if err := wire.ValidateAdminAuthorizationAt(&old, &profile, at); err != nil {
		return err
	}
	oldACL, err := wire.AdminACLRoot([]wire.AdminAuthorizationV1{old}, map[string]wire.AdminCertificateProfileV1{profile.ProfileID: profile})
	if err != nil || oldACL != parent.Body.Payload.AdminACLRoot {
		return errors.New("[D104 activation] 操作者不是原 certified ACL 的管理员")
	}
	if len(activation.Application.Authorizations) != 1 {
		return errors.New("[D104 activation] 一次迁移只保留原管理员")
	}
	next := activation.Application.Authorizations[0]
	oldHash, _ := wire.AdminAuthorizationHash(&old, &profile)
	if next.AdminID != old.AdminID || next.AdminCertificateDigest != old.AdminCertificateDigest ||
		next.AdminCertificateDER != old.AdminCertificateDER || next.AuthorizationID != old.AuthorizationID ||
		next.Generation != old.Generation+1 || next.PreviousAuthorizationHash != oldHash || next.NotAfter != old.NotAfter ||
		!wire.EqualCanonical(next.CertificateProfileRef, old.CertificateProfileRef) || !wire.EqualCanonical(next.Scopes, old.Scopes) ||
		!wire.EqualCanonical(activation.Application.adminProfiles()[profile.ProfileID], profile) {
		return errors.New("[D104 activation] 迁移替换了原管理员身份、scope 或有效期")
	}
	der, _ := base64.RawURLEncoding.DecodeString(old.AdminCertificateDER)
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	if err := wire.VerifyControlOperation(&record.Operation, certificate.RawSubjectPublicKeyInfo, at, controlActivationSchemas); err != nil {
		return err
	}
	statementHash, err := wire.RuntimeActivationStatementHash(statement)
	if err != nil {
		return err
	}
	body, base := record.Operation.Body, parent.Body.Payload
	if body.ClusterID != base.ClusterID || body.BaseRecoveryEpoch != base.RecoveryEpoch ||
		body.BaseRecoveryStatementHash != base.RecoveryStatementHash || body.BaseRecoveryPolicyHash != base.RecoveryPolicyHash ||
		body.BaseControlEpoch != base.ControlEpoch || body.BaseControlSetHash != base.ControlSetHash ||
		body.BaseControlRevision != base.ControlRevision || body.ParentHeadHash != parent.HeadHash ||
		body.PayloadHash != statementHash || body.AdminCertDigest != old.AdminCertificateDigest || body.AuthorID != old.AdminID ||
		body.OperationID != statement.OperationID || record.Leaf.OperationID != statement.OperationID || record.Leaf.ObjectID != statementHash {
		return errors.New("[D104 activation] 当前管理员签名未绑定 exact 迁移 statement")
	}
	p := &record.Candidate.Body.Payload
	expected, err := wire.RuntimeActivationHeadBody(bundle, p.RaftTerm, p.RaftIndex, p.PreviousLogEntryHash, p.CommittedLogicalTime)
	if err != nil {
		return err
	}
	if !wire.EqualCanonical(expected, record.Candidate.Body) {
		return errors.New("[D104 activation] candidate 未重算迁移 preimage")
	}
	return nil
}

// activateRuntimeLocked 只由持有本机离线维护锁的调用方进入。它追加到同一个
// Raft/journal，原 config、身份文件、SSOT 和旧 Head 均不覆盖（D104、D119）。
func (runtime *controlRuntime) activateRuntime(activation controlRuntimeActivationV1,
	operation wire.ControlOperationV1) (*controlCertifiedOperationResultV1, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for i := range runtime.journal.Records {
		record := &runtime.journal.Records[i]
		if record.Activation == nil {
			continue
		}
		if !wire.EqualCanonical(*record.Activation, activation) || !wire.EqualCanonical(record.Operation, operation) {
			return nil, errors.New("[D104 activation] 已有另一迁移，不能覆盖")
		}
		if err := runtime.finishCommittedLocked(); err != nil {
			return nil, err
		}
		if record.Result == nil {
			if err := runtime.recoverPendingOperationsLocked(); err != nil {
				return nil, err
			}
		}
		return record.Result, nil
	}
	state, raft := runtime.store.Snapshot(), runtime.storage.SnapshotRaft()
	if state.CertifiedHead == nil || state.CertifiedQC == nil || state.Active != nil ||
		state.CertifiedHead.HeadHash != activation.Bundle.Parent.HeadHash ||
		raft.LastApplied != raft.CommitIndex || int64(len(raft.Log)) != raft.CommitIndex || len(raft.Log) == 0 {
		return nil, errors.New("[D104 activation] 迁移要求原 exact stable certified Head")
	}
	for _, record := range runtime.journal.Records {
		if record.Result == nil {
			return nil, errors.New("[D104 activation] 必须先完成已有 operation")
		}
	}
	logical := runtime.now().UTC().Truncate(time.Second).Format(time.RFC3339)
	body, err := wire.RuntimeActivationHeadBody(&activation.Bundle, raft.CurrentTerm, int64(len(raft.Log))+1,
		raft.Log[len(raft.Log)-1].EntryHash, logical)
	if err != nil {
		return nil, err
	}
	candidate, err := wire.NewHeadEntry(body)
	if err != nil {
		return nil, err
	}
	statement := activation.Bundle.Proof.Statement
	statementHash, _ := wire.RuntimeActivationStatementHash(&statement)
	runtime.journal.Records = append(runtime.journal.Records, controlOperationRecordV1{Schema: 1,
		Operation: operation, Leaf: wire.ControlOperationLeafV1{Schema: 1, OperationID: statement.OperationID, ObjectID: statementHash},
		Candidate: candidate, Activation: &activation, Phases: []controlplane.Phase{controlplane.PhasePending}})
	index := len(runtime.journal.Records) - 1
	if err := runtime.verifyCommittedHead(context.Background(), candidate); err != nil {
		runtime.journal.Records = runtime.journal.Records[:index]
		return nil, err
	}
	if err := runtime.persistJournalLocked(); err != nil {
		runtime.journal.Records = runtime.journal.Records[:index]
		return nil, err
	}
	if runtime.checkpoint != nil {
		if err := runtime.checkpoint(controlplane.PhasePending); err != nil {
			return nil, err
		}
	}
	if _, err := runtime.leader.ReplicateHead(context.Background(), runtime.store, candidate); err != nil {
		return nil, err
	}
	if err := runtime.finishCommittedLocked(); err != nil {
		return nil, err
	}
	return runtime.journal.Records[index].Result, nil
}
