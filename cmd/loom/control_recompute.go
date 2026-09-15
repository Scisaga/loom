package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"

	"loom/internal/wire"
)

// verifyAdminOperationRecord 独立重验管理签名与 parent ACL，并按 kind 重算 Head。
// operation_root 一致只能证明 leaf 集合，不能证明其余根来自正确 reducer（D104）。
func (runtime *controlRuntime) verifyAdminOperationRecord(index int) error {
	record := &runtime.journal.Records[index]
	if record.Schema != 1 || record.AdminRotation != nil || record.Activation != nil || record.Enrollment != nil ||
		(record.Operation.Body.Kind != controlPingKind && record.Operation.Body.Kind != controlCreateInviteKind && record.Operation.Body.Kind != controlPublishDeviceKind) {
		return errors.New("[D104] 未登记的管理 operation")
	}
	if record.Operation.Body.Kind == controlPingKind && (record.Invite != nil || record.DevicePublication != nil || len(record.AdditionalLeaves) != 0) ||
		record.Operation.Body.Kind == controlCreateInviteKind && (record.Invite == nil || record.DevicePublication != nil || len(record.AdditionalLeaves) != 1) ||
		record.Operation.Body.Kind == controlPublishDeviceKind && (record.DevicePublication == nil || record.Invite != nil || len(record.AdditionalLeaves) != 0) {
		return errors.New("[D104] 管理 operation union/leaf 不一致")
	}
	var parent *wire.HeadEntryV2
	for _, log := range runtime.storage.SnapshotRaft().Log {
		if log.Head != nil && log.Head.HeadHash == record.Operation.Body.ParentHeadHash {
			parent = log.Head
			break
		}
	}
	if parent == nil {
		return errors.New("[D104] operation parent 缺持久日志")
	}
	var initial controlDiskConfigV1
	if err := readCanonicalFile(filepath.Join(runtime.dir, controlConfigName), 8<<20, &initial); err != nil {
		return err
	}
	profiles, authorizations := initial.AdminProfiles, initial.Authorizations
	for previous := 0; previous < index; previous++ {
		if activation := runtime.journal.Records[previous].Activation; activation != nil {
			if err := runtime.verifyActivationRecord(previous); err != nil {
				return err
			}
			profiles = activation.Application.adminProfiles()
			authorizations = append([]wire.AdminAuthorizationV1(nil), activation.Application.Authorizations...)
			continue
		}
		rotation := runtime.journal.Records[previous].AdminRotation
		if rotation == nil {
			continue
		}
		if err := runtime.verifyAdminRotationRecord(previous); err != nil {
			return err
		}
		p := rotation.Payload
		if len(authorizations) != 1 || !wire.EqualCanonical(authorizations[0], p.PreviousAuthorization) ||
			!wire.EqualCanonical(profiles[p.PreviousProfile.ProfileID], p.PreviousProfile) {
			return errors.New("[D104] operation parent ACL history 不连续")
		}
		profiles = map[string]wire.AdminCertificateProfileV1{p.NextProfile.ProfileID: p.NextProfile}
		authorizations = []wire.AdminAuthorizationV1{p.NextAuthorization}
	}
	acl, err := wire.AdminACLRoot(authorizations, profiles)
	if err != nil || acl != parent.Body.Payload.AdminACLRoot {
		return errors.New("[D104] operation authorization 不是 parent 承诺的 ACL")
	}
	at, err := wire.ParseTimeZ(record.Candidate.Body.Payload.CommittedLogicalTime)
	if err != nil {
		return err
	}
	var authorized bool
	for _, authorization := range authorizations {
		if authorization.AdminCertificateDigest != record.Operation.Body.AdminCertDigest {
			continue
		}
		profile, ok := profiles[authorization.CertificateProfileRef.ProfileID]
		if !ok {
			return errors.New("[D104] operation 缺管理员证书 profile")
		}
		scope := wire.AdminResourceScopeV1{ScopeKind: "cluster", Cluster: &struct{}{}}
		if err := wire.AuthorizeControlOperation(&record.Operation, &authorization, &profile, &scope, at, controlOperationSchemas); err != nil {
			return err
		}
		der, _ := base64.RawURLEncoding.DecodeString(authorization.AdminCertificateDER)
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		objectID, err := wire.ControlOperationObjectID(&record.Operation, certificate.RawSubjectPublicKeyInfo, at, controlOperationSchemas)
		if err != nil || record.Leaf.Schema != 1 || record.Leaf.ObjectID != objectID ||
			record.Leaf.OperationID != record.Operation.Body.OperationID {
			return errors.New("[D104] operation leaf 与已授权签名对象不一致")
		}
		authorized = true
	}
	if !authorized {
		return errors.New("[D104] operation 未获 parent ACL 授权")
	}
	body, base := record.Operation.Body, parent.Body.Payload
	if body.ClusterID != base.ClusterID || body.BaseRecoveryEpoch != base.RecoveryEpoch ||
		body.BaseRecoveryStatementHash != base.RecoveryStatementHash || body.BaseRecoveryPolicyHash != base.RecoveryPolicyHash ||
		body.BaseControlEpoch != base.ControlEpoch || body.BaseControlSetHash != base.ControlSetHash ||
		body.BaseControlRevision != base.ControlRevision || body.ParentHeadHash != parent.HeadHash {
		return errors.New("[D104] operation 未精确绑定 parent authority")
	}
	expected, actual := parent.Body, record.Candidate.Body
	expected.Payload.HeadKind = "ordinary"
	expected.Payload.RaftTerm, expected.Payload.RaftIndex = actual.Payload.RaftTerm, actual.Payload.RaftIndex
	expected.Payload.ControlRevision = actual.Payload.RaftIndex
	expected.Payload.PreviousLogEntryHash = actual.Payload.PreviousLogEntryHash
	expected.Payload.ParentHeadHash, expected.Payload.OperationRoot = parent.HeadHash, actual.Payload.OperationRoot
	expected.Payload.CommittedLogicalTime = actual.Payload.CommittedLogicalTime
	expected.Payload.TransitionContext = json.RawMessage(`{"schema":1,"kind":"ordinary"}`)
	if record.Invite != nil {
		application, err := runtime.applicationBefore(index)
		if err != nil {
			return err
		}
		next, err := application.reduceInvite(*record.Invite, record.Operation.Body, actual.Payload.CommittedLogicalTime)
		if err != nil {
			return err
		}
		hash, err := wire.CertifiedInviteRecordHash(&record.Invite.Record, &application.InvitePolicy)
		if err != nil || !wire.EqualCanonical(record.AdditionalLeaves[0], wire.ControlOperationLeafV1{
			Schema: 1, OperationID: record.Invite.Record.OperationID, ObjectID: hash}) {
			return errors.New("[D104 Invite] record leaf 与认证记录不一致")
		}
		roots, err := next.roots()
		if err != nil {
			return err
		}
		controlApplyRoots(&expected, roots)
	}
	if record.DevicePublication != nil {
		application, err := runtime.applicationBefore(index)
		if err != nil {
			return err
		}
		next, err := application.reduceDevicePublication(*record.DevicePublication, record.Operation.Body, actual.Payload.CommittedLogicalTime)
		if err != nil {
			return err
		}
		roots, err := next.roots()
		if err != nil {
			return err
		}
		controlApplyRoots(&expected, roots)
	}
	if !wire.EqualCanonical(expected, actual) {
		return errors.New("[D104] 管理操作修改了 reducer 不允许修改的 Head 字段")
	}
	return wire.ValidateHeadEntry(&record.Candidate, parent)
}
