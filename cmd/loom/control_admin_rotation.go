package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"loom/internal/publish"
	"loom/internal/wire"
)

const controlAdminRotationKind = "local_admin_certificate_rotation"

var controlAdminRotationSchemas = wire.OperationSchemaRegistry{controlAdminRotationKind: 1}

type controlAdminRotationPayloadV1 struct {
	Schema                int                            `json:"schema"`
	PreviousProfile       wire.AdminCertificateProfileV1 `json:"previous_profile"`
	PreviousAuthorization wire.AdminAuthorizationV1      `json:"previous_authorization"`
	NextProfile           wire.AdminCertificateProfileV1 `json:"next_profile"`
	NextAuthorization     wire.AdminAuthorizationV1      `json:"next_authorization"`
}

type controlAdminRotationV1 struct {
	Payload     controlAdminRotationPayloadV1 `json:"payload"`
	NewKeyProof wire.ControlOperationV1       `json:"new_key_proof"`
}

func lockControlState(dir string) (func(), error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("[admin rotation] state 必须是 owner-only 目录")
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	return publish.AcquireLock(filepath.Join(absolute, "runtime.lock"))
}

func cmdControlRotateAdmin(args []string) error {
	fs := flag.NewFlagSet("control rotate-admin", flag.ContinueOnError)
	dir := fs.String("state-dir", "/var/lib/loom-control", "必须已停止 daemon 的 N=1 控制状态目录")
	adminDir := fs.String("admin-dir", "", "当前管理员完整身份目录")
	out := fs.String("out-dir", "", "新管理员身份目录；不得覆盖原目录")
	reason := fs.String("reason", "", "本机证书轮换的审计理由")
	enableBootstrapAdvertise := fs.Bool("enable-bootstrap-advertise", false,
		"为旧迁移 ACL 仅增加 advertise_bootstrap；新迁移无需使用")
	enableControlMembership := fs.Bool("enable-control-membership", false,
		"为旧迁移 ACL 增加 exact control-membership kind/scope；新迁移无需使用")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *adminDir == "" || *out == "" || *reason == "" || fs.NArg() != 0 {
		return errors.New("control rotate-admin 必须指定 -admin-dir、-out-dir、-reason")
	}
	unlock, err := lockControlState(*dir)
	if err != nil {
		return err
	}
	defer unlock()
	var config controlDiskConfigV1
	if err := readCanonicalFile(filepath.Join(*dir, controlConfigName), 8<<20, &config); err != nil {
		return err
	}
	// 旧 daemon 尚无进程锁；占住全部原 listener 才能进行离线维护，避免双 leader 写盘。
	var listeners []net.Listener
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for _, address := range []string{net.JoinHostPort(config.OverlayIP, fmt.Sprint(config.ControlPort)),
		net.JoinHostPort(controlLoopbackIP, fmt.Sprint(config.ControlPort)),
		net.JoinHostPort(config.OverlayIP, fmt.Sprint(config.RaftPort))} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return errors.New("[admin rotation] 控制 listener 未释放；请先停止 loom-control.service")
		}
		listeners = append(listeners, listener)
	}
	runtime, err := openControlRuntime(*dir, time.Now)
	if err != nil {
		return err
	}
	return runtime.rotateAdminCertificate(*adminDir, *out, *reason,
		*enableBootstrapAdvertise, *enableControlMembership)
}

// 本机 root 维护仪式替换自己的证书，要求旧身份签名与新 key PoP。默认权限
// 完全不变；旧迁移可显式增加 advertise_bootstrap，或成对增加 exact
// control-membership kind/scope。其他 capability、scope、有效期或 operation kind 扩张仍被 reducer 拒绝。
func (runtime *controlRuntime) rotateAdminCertificate(adminDir, outDir, reason string,
	permissionUpgrade ...bool) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(permissionUpgrade) > 2 {
		return errors.New("[admin rotation] ACL 升级选项重复")
	}
	enableAdvertise := len(permissionUpgrade) >= 1 && permissionUpgrade[0]
	enableMembership := len(permissionUpgrade) == 2 && permissionUpgrade[1]
	oldAbs, err := filepath.Abs(adminDir)
	if err != nil {
		return err
	}
	newAbs, err := filepath.Abs(outDir)
	if err != nil {
		return err
	}
	if oldAbs == newAbs {
		return errors.New("[admin rotation] 新旧交付目录不得相同")
	}
	state := runtime.store.Snapshot()
	if len(state.ControlSet.Members) != 1 || state.CertifiedHead == nil || state.CertifiedQC == nil || state.Active != nil {
		return errors.New("[admin rotation] 只允许稳定、已 certified 的 N=1 authority")
	}
	if encoded, err := readOwnerOnlyFile(filepath.Join(outDir, controlAdminCertName), 1<<20); err == nil {
		leaf, err := parseSingleCertificatePEM(encoded)
		if err == nil && runtime.adminCertificateAuthorizedLocked(leaf.Raw) {
			if enableAdvertise && !containsControlValue(runtime.config.Authorizations[0].AllowedOperationKinds,
				controlAdvertiseBootstrapKind) {
				return errors.New("[admin rotation] 已完成的轮换没有请求的 bootstrap advertise 权限")
			}
			if enableMembership && !adminAuthorizationHasMembership(runtime.config.Authorizations[0]) {
				return errors.New("[admin rotation] 已完成的轮换没有请求的 control membership 权限")
			}
			if err := exportAdminPKCS12(outDir, runtime.now().UTC()); err != nil {
				return err
			}
			for _, record := range runtime.journal.Records {
				if record.AdminRotation != nil && record.Result != nil &&
					record.AdminRotation.Payload.NextAuthorization.AdminCertificateDER == base64.RawURLEncoding.EncodeToString(leaf.Raw) {
					return writeCanonicalAtomic(filepath.Join(outDir, "rotation-receipt.json"), record.Result, 0o600)
				}
			}
			return nil
		}
	}
	endpoint, client, err := loadControlAdminClient(adminDir)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	if endpoint.ClusterID != runtime.config.ClusterID || !wire.EqualCanonical(endpoint.Service, runtime.config.ControlService) {
		return errors.New("[admin rotation] 原交付目录不属于当前 authority")
	}
	oldPEM, err := readOwnerOnlyFile(filepath.Join(adminDir, controlAdminCertName), 1<<20)
	if err != nil {
		return err
	}
	oldCertificate, err := parseSingleCertificatePEM(oldPEM)
	if err != nil {
		return err
	}
	if !runtime.adminCertificateAuthorizedLocked(oldCertificate.Raw) {
		return errors.New("[admin rotation] 原证书未获当前 certified ACL 授权")
	}
	oldKeyPEM, err := readOwnerOnlyFile(filepath.Join(adminDir, controlAdminKeyName), 1<<20)
	if err != nil {
		return err
	}
	oldKey, err := parseAdminPrivateKey(oldKeyPEM)
	if err != nil {
		return err
	}
	old := runtime.config.Authorizations[0]
	oldProfile := runtime.config.AdminProfiles[old.CertificateProfileRef.ProfileID]
	now := runtime.now().UTC().Truncate(time.Second)
	var nextLeaf, nextRoot *x509.Certificate
	var nextKeyPEM []byte
	if _, err := os.Lstat(outDir); errors.Is(err, os.ErrNotExist) {
		rootPEM, root, rootKey, err := makeP256AdminCA("Loom P-256 admin CA "+runtime.config.ClusterID,
			now.Add(-5*time.Minute), now.Add(5*365*24*time.Hour))
		if err != nil {
			return err
		}
		leafPEM, keyPEM, der, err := makeAdminCertificate(runtime.config.ClusterID, old.AdminID, root, rootKey, now)
		if err != nil {
			return err
		}
		nextLeaf, err = x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		nextRoot, nextKeyPEM = root, keyPEM
		rootKeyPEM, err := privateKeyPKCS8PEM(rootKey)
		if err != nil {
			return err
		}
		issuerID, _ := wire.AdminKeyID(root.RawSubjectPublicKeyInfo)
		issuerDir := filepath.Join(runtime.dir, "admin-issuers")
		if err := os.MkdirAll(issuerDir, 0o700); err != nil {
			return err
		}
		if err := writeBytesAtomic(filepath.Join(issuerDir, issuerID[7:]+".key"), rootKeyPEM, 0o600); err != nil {
			return err
		}
		internalRoot, err := base64.RawURLEncoding.DecodeString(endpoint.InternalRootDER)
		if err != nil {
			return err
		}
		_, _, browserRoot, err := loadControlBrowserTLS(filepath.Join(runtime.dir, controlBrowserTLSName),
			runtime.config.ClusterID, runtime.config.OverlayIP, now)
		if err != nil {
			return err
		}
		if err := writeAdminDelivery(outDir, runtime.config, internalRoot, browserRoot.Raw, leafPEM, keyPEM, rootPEM, now); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		// 未完成的准备目录保留同一 key；重试不能生成另一份尚未交付的身份。
		if err := exportAdminPKCS12(outDir, now); err != nil {
			return err
		}
		leafPEM, err := readOwnerOnlyFile(filepath.Join(outDir, controlAdminCertName), 1<<20)
		if err != nil {
			return err
		}
		rootPEM, err := readOwnerOnlyFile(filepath.Join(outDir, controlAdminRootName), 1<<20)
		if err != nil {
			return err
		}
		nextLeaf, err = parseSingleCertificatePEM(leafPEM)
		if err != nil {
			return err
		}
		nextRoot, err = parseSingleCertificatePEM(rootPEM)
		if err != nil {
			return err
		}
		nextKeyPEM, err = readOwnerOnlyFile(filepath.Join(outDir, controlAdminKeyName), 1<<20)
		if err != nil {
			return err
		}
	}
	nextKey, err := parseAdminPrivateKey(nextKeyPEM)
	if err != nil {
		return err
	}
	profile, next, err := makeAdminAuthority(runtime.config.ClusterID, nextRoot.Raw, nextLeaf.Raw, nextLeaf.NotBefore.Add(5*time.Minute))
	if err != nil {
		return err
	}
	profile.ProfileID, profile.Generation = oldProfile.ProfileID, oldProfile.Generation+1
	profileHash, err := wire.AdminCertificateProfileHash(&profile)
	if err != nil {
		return err
	}
	next.AuthorizationID, next.Generation, next.AdminID = old.AuthorizationID, old.Generation+1, old.AdminID
	next.PreviousAuthorizationHash, err = wire.AdminAuthorizationHash(&old, &oldProfile)
	if err != nil {
		return err
	}
	next.CertificateProfileRef = wire.AdminCertificateProfileRefV1{ProfileID: profile.ProfileID,
		Generation: profile.Generation, AdminCertificateProfileHash: profileHash}
	next.AllowedOperationKinds = append([]string(nil), old.AllowedOperationKinds...)
	next.Capabilities = append([]string{}, old.Capabilities...)
	next.Scopes = append([]wire.AdminResourceScopeV1(nil), old.Scopes...)
	if enableAdvertise && !containsControlValue(next.AllowedOperationKinds, controlAdvertiseBootstrapKind) {
		next.AllowedOperationKinds = append(append([]string(nil), next.AllowedOperationKinds...), controlAdvertiseBootstrapKind)
		sort.Strings(next.AllowedOperationKinds)
	}
	if enableMembership && !containsControlValue(next.AllowedOperationKinds, controlMembershipKind) {
		next.AllowedOperationKinds = append(next.AllowedOperationKinds, controlMembershipKind)
		sort.Strings(next.AllowedOperationKinds)
	}
	if enableMembership && !adminAuthorizationHasMembershipScope(next) {
		next.Scopes = append(next.Scopes,
			wire.AdminResourceScopeV1{ScopeKind: "control_membership", ControlMembership: &struct{}{}})
		sort.Slice(next.Scopes, func(left, right int) bool {
			leftHash, _ := wire.AdminResourceScopeHash(&next.Scopes[left])
			rightHash, _ := wire.AdminResourceScopeHash(&next.Scopes[right])
			return leftHash < rightHash
		})
	}
	next.NotAfter = old.NotAfter
	// 只有尚未进入任何 Raft log 的末尾准备记录可重建；已提交记录由恢复流程继续完成。
	for i, record := range runtime.journal.Records {

		if record.AdminRotation == nil || record.Result != nil ||
			record.AdminRotation.Payload.NextAuthorization.AdminCertificateDER != next.AdminCertificateDER {
			continue
		}
		if i != len(runtime.journal.Records)-1 {
			return errors.New("[admin rotation] 非末尾的未完成轮换")
		}
		for _, log := range runtime.storage.SnapshotRaft().Log {
			if log.Head != nil && log.Head.HeadHash == record.Candidate.HeadHash {
				return errors.New("[admin rotation] 轮换已进入 Raft；必须先完成原提交恢复")
			}
		}
		runtime.journal.Records = runtime.journal.Records[:i]
		if err := runtime.persistJournalLocked(); err != nil {
			return err
		}
		break
	}
	rotation := &controlAdminRotationV1{Payload: controlAdminRotationPayloadV1{1, oldProfile, old, profile, next}}
	payloadHash, err := wire.HashObject("loom-local-admin-rotation-v1", rotation.Payload)
	if err != nil {
		return err
	}
	parent := *state.CertifiedHead
	body := wire.ControlOperationBodyV1{Schema: 1, ClusterID: runtime.config.ClusterID,
		OperationID: "admin-rotate-" + next.AdminCertificateDigest[7:31], AuthorID: old.AdminID,
		AdminCertDigest: old.AdminCertificateDigest, CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339), BaseRecoveryEpoch: parent.Body.Payload.RecoveryEpoch,
		BaseRecoveryStatementHash: parent.Body.Payload.RecoveryStatementHash, BaseRecoveryPolicyHash: parent.Body.Payload.RecoveryPolicyHash,
		BaseControlEpoch: parent.Body.Payload.ControlEpoch, BaseControlSetHash: parent.Body.Payload.ControlSetHash,
		BaseControlRevision: parent.Body.Payload.ControlRevision, ParentHeadHash: parent.HeadHash,
		Kind: controlAdminRotationKind, PayloadSchema: 1, PayloadHash: payloadHash, Reason: reason}
	operation, err := wire.NewControlOperation(body, oldKey, controlAdminRotationSchemas)
	if err != nil {
		return err
	}
	rotation.NewKeyProof, err = wire.NewControlOperation(body, nextKey, controlAdminRotationSchemas)
	if err != nil {
		return err
	}
	objectID, err := wire.ControlOperationObjectID(&operation, oldCertificate.RawSubjectPublicKeyInfo, now, controlAdminRotationSchemas)
	if err != nil {
		return err
	}
	leaf := wire.ControlOperationLeafV1{Schema: 1, OperationID: body.OperationID, ObjectID: objectID}
	leaves := append(runtime.operationLeaves(len(runtime.journal.Records)), leaf)
	operationRoot, err := wire.ControlOperationRoot(leaves)
	if err != nil {
		return err
	}
	raft := runtime.storage.SnapshotRaft()
	headBody := parent.Body
	headBody.Payload.HeadKind = "ordinary"
	headBody.Payload.RaftTerm, headBody.Payload.RaftIndex = raft.CurrentTerm, int64(len(raft.Log))+1
	headBody.Payload.ControlRevision = headBody.Payload.RaftIndex
	headBody.Payload.PreviousLogEntryHash = raft.Log[len(raft.Log)-1].EntryHash
	headBody.Payload.ParentHeadHash, headBody.Payload.OperationRoot = parent.HeadHash, operationRoot
	headBody.Payload.CommittedLogicalTime = now.Format(time.RFC3339)
	headBody.Payload.TransitionContext = json.RawMessage(`{"schema":1,"kind":"ordinary"}`)
	if err := runtime.applyAdminRotationRoots(&headBody, rotation.Payload, len(runtime.journal.Records)); err != nil {
		return err
	}
	candidate, err := wire.NewHeadEntry(headBody)
	if err != nil {
		return err
	}
	record := controlOperationRecordV1{Schema: 1, Operation: operation, Leaf: leaf, Candidate: candidate, AdminRotation: rotation}
	runtime.journal.Records = append(runtime.journal.Records, record)
	if err := runtime.verifyAdminRotationRecord(len(runtime.journal.Records) - 1); err != nil {
		runtime.journal.Records = runtime.journal.Records[:len(runtime.journal.Records)-1]
		return err
	}
	if err := runtime.persistJournalLocked(); err != nil {
		return err
	}
	if _, err := runtime.replicateHead(context.Background(), candidate); err != nil {
		return err
	}
	if err := runtime.finishCommittedLocked(); err != nil {
		return err
	}
	result := runtime.journal.Records[len(runtime.journal.Records)-1].Result
	if result == nil || !runtime.adminCertificateAuthorizedLocked(nextLeaf.Raw) || runtime.adminCertificateAuthorizedLocked(oldCertificate.Raw) {
		return errors.New("[admin rotation] 新身份尚未取得 exclusive certified authority")
	}
	if err := writeCanonicalAtomic(filepath.Join(outDir, "rotation-receipt.json"), result, 0o600); err != nil {
		return err
	}
	permissionResult := "权限保持原范围"
	if enableAdvertise || enableMembership {
		permissionResult = "旧迁移 ACL 已增加显式请求的受限权限"
	}
	fmt.Printf("✓ 管理员 P-256 证书与完整 PKCS#12 已生成；%s，轮换已 Raft commit/apply/QC\n  admin: %s\n", permissionResult, outDir)
	return nil
}

func (runtime *controlRuntime) adminRotationRoots(payload controlAdminRotationPayloadV1) (string, string, error) {
	acl, err := wire.AdminACLRoot([]wire.AdminAuthorizationV1{payload.NextAuthorization},
		map[string]wire.AdminCertificateProfileV1{payload.NextProfile.ProfileID: payload.NextProfile})
	if err != nil {
		return "", "", err
	}
	if len(runtime.controlTLS.Certificate) != 2 {
		return "", "", errors.New("[admin rotation] native issuer chain 无效")
	}
	root, err := wire.HashObject("loom-runtime-ca-profiles-v1", struct {
		Schema   int    `json:"schema"`
		Internal string `json:"internal"`
		Admin    string `json:"admin"`
	}{1, base64.RawURLEncoding.EncodeToString(runtime.controlTLS.Certificate[1]), payload.NextProfile.IssuerChainDER[0]})
	return acl, root, err
}

func (runtime *controlRuntime) applyAdminRotationRoots(body *wire.HeadEntryBodyV2, payload controlAdminRotationPayloadV1, index int) error {
	application, err := runtime.applicationBefore(index)
	if err != nil {
		return err
	}
	if application == nil {
		body.Payload.AdminACLRoot, body.Payload.CAProfileRoot, err = runtime.adminRotationRoots(payload)
		return err
	}
	next, err := application.reduceAdminRotation(payload)
	if err != nil {
		return err
	}
	roots, err := next.roots()
	if err != nil {
		return err
	}
	controlApplyRoots(body, roots)
	return nil
}

func (runtime *controlRuntime) verifyAdminRotationRecord(index int) error {
	record := runtime.journal.Records[index]
	rotation := record.AdminRotation
	if rotation == nil || record.Activation != nil || record.Enrollment != nil || record.Invite != nil || record.DevicePublication != nil || record.BootstrapAdvertisement != nil || len(record.AdditionalLeaves) != 0 {
		return errors.New("[D104 admin rotation] 缺轮换 preimage")
	}
	p := rotation.Payload
	at, err := wire.ParseTimeZ(record.Candidate.Body.Payload.CommittedLogicalTime)
	if err != nil {
		return err
	}
	if p.Schema != 1 || p.PreviousAuthorization.Status != "active" || p.NextAuthorization.Status != "active" ||
		p.NextProfile.SubjectKeyAlgorithm != "p256" || p.NextProfile.Generation != p.PreviousProfile.Generation+1 ||
		p.NextProfile.ProfileID != p.PreviousProfile.ProfileID || len(p.NextProfile.IssuerChainDER) != 1 ||
		p.NextProfile.ClusterID != p.PreviousProfile.ClusterID ||
		p.NextProfile.MaximumValiditySeconds != p.PreviousProfile.MaximumValiditySeconds ||
		!wire.EqualCanonical(p.NextProfile.RequiredEKUOIDs, p.PreviousProfile.RequiredEKUOIDs) ||
		!wire.EqualCanonical(p.NextProfile.RequiredPolicyOIDs, p.PreviousProfile.RequiredPolicyOIDs) ||
		p.NextAuthorization.Generation != p.PreviousAuthorization.Generation+1 ||
		p.NextAuthorization.AdminID != p.PreviousAuthorization.AdminID ||
		p.NextAuthorization.AuthorizationID != p.PreviousAuthorization.AuthorizationID ||
		p.NextAuthorization.NotAfter != p.PreviousAuthorization.NotAfter {
		return errors.New("[admin rotation] 轮换改变了既有管理员权限/有效期或代际")
	}
	if !validAdminRotationScopes(p.PreviousAuthorization.Scopes, p.NextAuthorization.Scopes) {
		return errors.New("[admin rotation] 轮换含未授权的 scope 变化")
	}
	if !wire.EqualCanonical(p.NextAuthorization.Capabilities, p.PreviousAuthorization.Capabilities) {
		return errors.New("[admin rotation] 轮换改变了 capability")
	}
	if !validAdminRotationOperationKinds(p.PreviousAuthorization.AllowedOperationKinds,
		p.NextAuthorization.AllowedOperationKinds) {
		return errors.New("[admin rotation] 轮换含未授权的 operation kind 变化")
	}
	if containsControlValue(p.NextAuthorization.AllowedOperationKinds, controlMembershipKind) !=
		adminAuthorizationHasMembershipScope(p.NextAuthorization) {
		return errors.New("[admin rotation] control membership kind/scope 必须成对")
	}
	for _, pair := range []struct {
		a wire.AdminAuthorizationV1
		p wire.AdminCertificateProfileV1
	}{
		{p.PreviousAuthorization, p.PreviousProfile}, {p.NextAuthorization, p.NextProfile}} {
		if err := wire.ValidateAdminAuthorizationAt(&pair.a, &pair.p, at); err != nil {
			return err
		}
	}
	oldHash, _ := wire.AdminAuthorizationHash(&p.PreviousAuthorization, &p.PreviousProfile)
	payloadHash, _ := wire.HashObject("loom-local-admin-rotation-v1", p)
	if p.NextAuthorization.PreviousAuthorizationHash != oldHash || record.Operation.Body.PayloadHash != payloadHash ||
		record.Operation.Body.AdminCertDigest != p.PreviousAuthorization.AdminCertificateDigest ||
		record.Operation.Body.AuthorID != p.PreviousAuthorization.AdminID ||
		!wire.EqualCanonical(record.Operation.Body, rotation.NewKeyProof.Body) {
		return errors.New("[admin rotation] 身份/签名 payload 未精确绑定前后代")
	}
	for _, pair := range []struct {
		op  wire.ControlOperationV1
		der string
	}{
		{record.Operation, p.PreviousAuthorization.AdminCertificateDER}, {rotation.NewKeyProof, p.NextAuthorization.AdminCertificateDER}} {
		der, _ := base64.RawURLEncoding.DecodeString(pair.der)
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		if err := wire.VerifyControlOperation(&pair.op, cert.RawSubjectPublicKeyInfo, at, controlAdminRotationSchemas); err != nil {
			return err
		}
	}
	var parent *wire.HeadEntryV2
	for _, log := range runtime.controlRaftLog() {
		if log.Head != nil && log.Head.HeadHash == record.Operation.Body.ParentHeadHash {
			parent = log.Head
			break
		}
	}
	if parent == nil {
		return errors.New("[admin rotation] 原 certified parent 不在持久日志")
	}
	oldRoot, _ := wire.AdminACLRoot([]wire.AdminAuthorizationV1{p.PreviousAuthorization},
		map[string]wire.AdminCertificateProfileV1{p.PreviousProfile.ProfileID: p.PreviousProfile})
	if parent.Body.Payload.AdminACLRoot != oldRoot {
		return errors.New("[admin rotation] 旧身份与 parent ACL 不匹配")
	}
	body, base := record.Operation.Body, parent.Body.Payload
	if body.ClusterID != base.ClusterID || body.BaseRecoveryEpoch != base.RecoveryEpoch ||
		body.BaseRecoveryStatementHash != base.RecoveryStatementHash || body.BaseRecoveryPolicyHash != base.RecoveryPolicyHash ||
		body.BaseControlEpoch != base.ControlEpoch || body.BaseControlSetHash != base.ControlSetHash ||
		body.BaseControlRevision != base.ControlRevision || body.ParentHeadHash != parent.HeadHash {
		return errors.New("[admin rotation] operation 未绑定 exact parent")
	}
	expected := parent.Body
	actual := record.Candidate.Body
	expected.Payload.HeadKind = "ordinary"
	expected.Payload.RaftTerm, expected.Payload.RaftIndex = actual.Payload.RaftTerm, actual.Payload.RaftIndex
	expected.Payload.ControlRevision = actual.Payload.RaftIndex
	expected.Payload.PreviousLogEntryHash = actual.Payload.PreviousLogEntryHash
	expected.Payload.ParentHeadHash, expected.Payload.OperationRoot = parent.HeadHash, actual.Payload.OperationRoot
	expected.Payload.CommittedLogicalTime = at.Format(time.RFC3339)
	expected.Payload.TransitionContext = json.RawMessage(`{"schema":1,"kind":"ordinary"}`)
	if err := runtime.applyAdminRotationRoots(&expected, p, index); err != nil {
		return err
	}
	if !wire.EqualCanonical(expected, actual) {
		return errors.New("[admin rotation] 轮换修改了证书授权之外的 Head 字段")
	}
	oldDER, _ := base64.RawURLEncoding.DecodeString(p.PreviousAuthorization.AdminCertificateDER)
	oldLeaf, _ := x509.ParseCertificate(oldDER)
	objectID, err := wire.ControlOperationObjectID(&record.Operation, oldLeaf.RawSubjectPublicKeyInfo, at, controlAdminRotationSchemas)
	if err != nil || record.Leaf.ObjectID != objectID || record.Leaf.OperationID != record.Operation.Body.OperationID {
		return errors.New("[admin rotation] 操作日志 leaf 与签名对象不一致")
	}
	return nil
}

func validAdminRotationOperationKinds(previous, next []string) bool {
	previousSet := make(map[string]struct{}, len(previous))
	for _, kind := range previous {
		previousSet[kind] = struct{}{}
		if !containsControlValue(next, kind) {
			return false
		}
	}
	for _, kind := range next {
		if _, exists := previousSet[kind]; exists {
			continue
		}
		if kind != controlAdvertiseBootstrapKind && kind != controlMembershipKind {
			return false
		}
	}
	return true
}

func validAdminRotationScopes(previous, next []wire.AdminResourceScopeV1) bool {
	previousSet := make(map[string]struct{}, len(previous))
	for i := range previous {
		hash, err := wire.AdminResourceScopeHash(&previous[i])
		if err != nil {
			return false
		}
		previousSet[hash] = struct{}{}
	}
	for i := range next {
		hash, err := wire.AdminResourceScopeHash(&next[i])
		if err != nil {
			return false
		}
		if _, exists := previousSet[hash]; exists {
			delete(previousSet, hash)
			continue
		}
		if next[i].ScopeKind != "control_membership" || next[i].ControlMembership == nil {
			return false
		}
	}
	return len(previousSet) == 0
}

func adminAuthorizationHasMembershipScope(authorization wire.AdminAuthorizationV1) bool {
	for _, scope := range authorization.Scopes {
		if scope.ScopeKind == "control_membership" && scope.ControlMembership != nil {
			return true
		}
	}
	return false
}

func adminAuthorizationHasMembership(authorization wire.AdminAuthorizationV1) bool {
	return containsControlValue(authorization.AllowedOperationKinds, controlMembershipKind) &&
		adminAuthorizationHasMembershipScope(authorization)
}

func (runtime *controlRuntime) projectAdminRotations() error {
	state := runtime.store.Snapshot()
	if state.CertifiedHead == nil {
		return nil
	}
	var initial controlDiskConfigV1
	if err := readCanonicalFile(filepath.Join(runtime.dir, controlConfigName), 8<<20, &initial); err != nil {
		return err
	}
	profiles, authorizations := initial.AdminProfiles, initial.Authorizations
	for i, record := range runtime.journal.Records {
		if record.Activation != nil && record.Candidate.Body.Payload.RaftIndex <= state.CertifiedHead.Body.Payload.RaftIndex {
			if record.Result == nil {
				return errors.New("[D104 activation] 缺 certified receipt")
			}
			if err := runtime.verifyActivationRecord(i); err != nil {
				return err
			}
			if err := wire.VerifyConfigQCAuthority(record.Candidate.HeadHash, record.Result.ConfigQC,
				&record.Candidate, &state.ControlSet, nil); err != nil {
				return err
			}
			profiles = record.Activation.Application.adminProfiles()
			authorizations = append([]wire.AdminAuthorizationV1(nil), record.Activation.Application.Authorizations...)
			continue
		}
		if record.AdminRotation == nil || record.Candidate.Body.Payload.RaftIndex > state.CertifiedHead.Body.Payload.RaftIndex {
			continue
		}
		if record.Result == nil {
			return errors.New("[admin rotation] 身份投影缺 certified receipt")
		}
		if err := runtime.verifyAdminRotationRecord(i); err != nil {
			return err
		}
		if err := wire.VerifyConfigQCAuthority(record.Candidate.HeadHash, record.Result.ConfigQC,
			&record.Candidate, &state.ControlSet, nil); err != nil {
			return err
		}
		p := record.AdminRotation.Payload
		if len(authorizations) != 1 || !wire.EqualCanonical(authorizations[0], p.PreviousAuthorization) ||
			!wire.EqualCanonical(profiles[p.PreviousProfile.ProfileID], p.PreviousProfile) {
			return errors.New("[admin rotation] 持久轮换历史不是连续的 authority")
		}
		profiles = map[string]wire.AdminCertificateProfileV1{p.NextProfile.ProfileID: p.NextProfile}
		authorizations = []wire.AdminAuthorizationV1{p.NextAuthorization}
	}
	root, err := wire.AdminACLRoot(authorizations, profiles)
	if err != nil || root != state.CertifiedHead.Body.Payload.AdminACLRoot {
		return errors.New("[admin rotation] 当前身份投影与 certified ACL root 不一致")
	}
	runtime.config.AdminProfiles, runtime.config.Authorizations = profiles, authorizations
	return nil
}
