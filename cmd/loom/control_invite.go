package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"loom/internal/controlplane"
	"loom/internal/enrollmentv2"
	"loom/internal/model"
	"loom/internal/wire"
)

const (
	controlCreateInviteKind    = "create_invite"
	controlInvitePayloadDomain = "loom-control-invite-payload-v1"
	controlInviteTokenDomain   = "loom-control-invite-token-artifact-v1"
)

// Token 只通过管理面的私有请求进入独立的 root-only secret artifact；它不进入
// operation journal/application/Raft。签名绑定 Invite 中的 commitment 和 artifact hash。
type controlCreateInvitePayloadV1 struct {
	Schema int                               `json:"schema"`
	Invite controlInviteStateV1              `json:"invite"`
	Token  wire.InviteTokenCommitmentInputV2 `json:"token_artifact"`
}

func controlInvitePayloadHash(invite controlInviteStateV1) (string, error) {
	return wire.HashObject(controlInvitePayloadDomain, struct {
		Schema int                  `json:"schema"`
		Invite controlInviteStateV1 `json:"invite"`
	}{1, invite})
}

func controlInviteRecordOperationID(clusterID, requestID string) (string, error) {
	return wire.HashObject("loom-control-invite-record-operation-id-v1", struct {
		Schema    int    `json:"schema"`
		ClusterID string `json:"cluster_id"`
		RequestID string `json:"request_id"`
	}{1, clusterID, requestID})
}

func decodeControlInvitePayload(raw json.RawMessage, operation wire.ControlOperationV1) (controlCreateInvitePayloadV1, error) {
	var payload controlCreateInvitePayloadV1
	canonical, err := wire.DecodeStrict(raw, 2<<20, &payload)
	if err != nil || !bytes.Equal(raw, canonical) || payload.Schema != 1 || operation.Body.Kind != controlCreateInviteKind {
		return payload, errors.New("[D104 Invite] 缺规范创建邀请 payload")
	}
	hash, err := controlInvitePayloadHash(payload.Invite)
	if err != nil || hash != operation.Body.PayloadHash {
		return payload, errors.New("[D104 Invite] payload 与管理员签名不一致")
	}
	if err := verifyControlInviteToken(payload.Invite.Record, payload.Token); err != nil {
		return payload, err
	}
	return payload, nil
}

func newControlInviteRequest(adminDir string, endpoint controlAdminEndpointV1, status controlStatusResponseV1,
	requestID string, raw json.RawMessage, reason string) (controlOperationRequestV1, error) {
	var payload controlCreateInvitePayloadV1
	canonical, err := wire.DecodeStrict(raw, 2<<20, &payload)
	if err != nil || !bytes.Equal(raw, canonical) || payload.Schema != 1 || payload.Invite.Record.ParentHeadHash != status.Head.HeadHash {
		return controlOperationRequestV1{}, errors.New("[D104 Invite] payload 不是当前 base 的规范创建请求")
	}
	operationID, err := controlInviteRecordOperationID(status.ClusterID, requestID)
	if err != nil || requestID == "" || payload.Invite.Record.OperationID != operationID {
		return controlOperationRequestV1{}, errors.New("[D104 Invite] request ID 不匹配")
	}
	if err := verifyControlInviteToken(payload.Invite.Record, payload.Token); err != nil {
		return controlOperationRequestV1{}, err
	}
	issued, err := wire.ParseTimeZ(payload.Invite.Record.IssuedAt)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	hash, err := controlInvitePayloadHash(payload.Invite)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	request, err := newControlSignedRequest(adminDir, endpoint, status, controlCreateInviteKind, hash, requestID, reason, issued)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	request.Payload = append(json.RawMessage(nil), raw...)
	return request, nil
}

func verifyControlInviteToken(record wire.CertifiedInviteRecordV2, token wire.InviteTokenCommitmentInputV2) error {
	if token.Schema != 2 || token.ClusterID != record.ClusterID || token.InviteID != record.InviteID {
		return errors.New("[D114 Invite] token artifact identity 不一致")
	}
	commitment, err := wire.TokenCommitment(token.ClusterID, token.InviteID, token.Token)
	if err != nil || commitment != record.TokenCommitment {
		return errors.New("[D114 Invite] token artifact commitment 不一致")
	}
	hash, err := wire.HashObject(controlInviteTokenDomain, token)
	if err != nil || hash != record.TokenArtifactBindingHash {
		return errors.New("[D114 Invite] token artifact 未被记录承诺")
	}
	return nil
}

func (runtime *controlRuntime) inviteTokenPath(record wire.CertifiedInviteRecordV2) (string, error) {
	if _, err := wire.ParseHash(record.TokenArtifactBindingHash); err != nil {
		return "", err
	}
	return filepath.Join(runtime.dir, "invite-tokens", strings.TrimPrefix(record.TokenArtifactBindingHash, "sha256:")+".json"), nil
}

func (runtime *controlRuntime) readInviteToken(record wire.CertifiedInviteRecordV2) (wire.InviteTokenCommitmentInputV2, error) {
	var token wire.InviteTokenCommitmentInputV2
	path, err := runtime.inviteTokenPath(record)
	if err != nil {
		return token, err
	}
	raw, err := readOwnerOnlyFile(path, 8192)
	if err != nil {
		return token, errors.New("[D114 Invite] token artifact 暂不可用")
	}
	canonical, err := wire.DecodeStrict(raw, 8192, &token)
	if err != nil || !bytes.Equal(raw, canonical) {
		return token, errors.New("[D114 Invite] token artifact 编码无效")
	}
	return token, verifyControlInviteToken(record, token)
}

func (runtime *controlRuntime) persistInviteToken(payload controlCreateInvitePayloadV1) error {
	if err := verifyControlInviteToken(payload.Invite.Record, payload.Token); err != nil {
		return err
	}
	path, err := runtime.inviteTokenPath(payload.Invite.Record)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		existing, err := runtime.readInviteToken(payload.Invite.Record)
		if err != nil || !wire.EqualCanonical(existing, payload.Token) {
			return errors.New("[D114 Invite] 不可变 token artifact 冲突")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeCanonicalAtomic(path, payload.Token, 0o600)
}

func (application *controlApplicationV1) reduceInvite(invite controlInviteStateV1, operation wire.ControlOperationBodyV1,
	committedAt string) (*controlApplicationV1, error) {
	if application != nil && application.BootstrapInstallation != nil {
		return nil, errors.New("Bootstrap 入口仍为私有安装计划，完成监听与外部验证的认证发布后才能创建邀请")
	}
	if application == nil || invite.Status != "available" || invite.Record.Generation != 1 ||
		operation.Kind != controlCreateInviteKind || operation.ClusterID != application.ClusterID ||
		invite.Record.ClusterID != application.ClusterID || invite.Opening.ClusterID != application.ClusterID ||
		invite.Record.InviteID != invite.Opening.InviteID || invite.Record.ParentHeadHash != operation.ParentHeadHash ||
		invite.Record.IssuedAt != operation.CreatedAt || strings.TrimSpace(invite.DisplayName) != invite.DisplayName ||
		invite.DisplayName == "" || !utf8.ValidString(invite.DisplayName) || utf8.RuneCountInString(invite.DisplayName) > 80 {
		return nil, errors.New("[D114 Invite] 创建请求的身份、状态、名称或 base 不一致")
	}
	payloadHash, err := controlInvitePayloadHash(invite)
	if err != nil || payloadHash != operation.PayloadHash {
		return nil, errors.New("[D104 Invite] 签名没有承诺 exact Invite")
	}
	operationID, err := controlInviteRecordOperationID(application.ClusterID, operation.OperationID)
	if err != nil || invite.Record.OperationID != operationID {
		return nil, errors.New("[D104 Invite] Invite record 未绑定本次管理请求")
	}
	if err := wire.ValidateCertifiedInviteRecord(&invite.Record, &application.InvitePolicy); err != nil {
		return nil, err
	}
	commitment, hash, err := wire.IntentCommitment(&invite.Opening)
	if err != nil || !wire.EqualCanonical(commitment, invite.Commitment) || hash != invite.Record.DeviceEnrollmentIntentCommitmentHash {
		return nil, errors.New("[D114 Invite] intent hiding/opening 不一致")
	}
	encoded, err := wire.MarshalCanonical(invite.Opening)
	if err != nil || int64(len(encoded)) > application.InvitePolicy.MaximumIntentOpeningBytes {
		return nil, errors.New("[D114 Invite] intent opening 超出 policy")
	}
	at, err := wire.ParseTimeZ(committedAt)
	issued, issuedErr := wire.ParseTimeZ(invite.Record.IssuedAt)
	expires, expiresErr := wire.ParseTimeZ(invite.Record.ExpiresAt)
	if err != nil || issuedErr != nil || expiresErr != nil || at.Before(issued) || !at.Before(expires) {
		return nil, errors.New("[D114 Invite] 创建邀请时已经过期或尚未生效")
	}
	serviceHash, err := wire.PrivateEnrollmentServiceRefHash(&application.EnrollmentService)
	if err != nil || serviceHash != invite.Record.EnrollmentServiceRefHash {
		return nil, errors.New("[D131 Invite] 邀请指向非当前 Enrollment service")
	}
	catalogHash, err := wire.BootstrapEndpointCatalogHash(&application.BootstrapCatalog)
	validFrom, fromErr := wire.ParseTimeZ(application.BootstrapCatalog.ValidFrom)
	validUntil, untilErr := wire.ParseTimeZ(application.BootstrapCatalog.ValidUntil)
	if err != nil || catalogHash != invite.Record.BootstrapCatalogHash || fromErr != nil || untilErr != nil ||
		at.Before(validFrom) || !expires.Before(validUntil) && !expires.Equal(validUntil) {
		return nil, errors.New("[D131 Invite] catalog binding/有效期不满足邀请")
	}
	roots, err := application.roots()
	if err != nil || roots.BootstrapIssuerRegistryRoot != invite.Record.BootstrapIssuerRegistryRoot {
		return nil, errors.New("[D115 Invite] issuer root 不是当前 certified registry")
	}
	var issuerValid bool
	for _, issuer := range application.BootstrapIssuers {
		hash, err := wire.BootstrapIssuerAuthorizationHash(&issuer)
		if err != nil || hash != invite.Record.BootstrapIssuerAuthorizationHash || issuer.Active == nil || issuer.Status != "active" {
			continue
		}
		a := issuer.Active
		from, e1 := wire.ParseTimeZ(a.ValidFrom)
		until, e2 := wire.ParseTimeZ(a.ValidUntil)
		issuerValid = e1 == nil && e2 == nil && !at.Before(from) && !expires.After(until) &&
			a.InviteIssuancePolicyHash == invite.Record.InviteIssuancePolicyHash &&
			containsControlValue(a.PermittedIngressSetHashes, application.BootstrapCatalog.BootstrapIngressSetHash) &&
			containsControlValue(a.PermittedServiceIDs, application.EnrollmentService.ServiceID) && containsControlValue(a.PermittedModes, "initial_claim")
	}
	if !issuerValid {
		return nil, errors.New("[D115 Invite] 无当前有效且 scope 匹配的 bootstrap issuer")
	}
	intent := invite.Opening.DeviceEnrollmentIntent
	var profileValid bool
	for _, profile := range application.CARegistry.DeviceProfiles {
		hash, err := wire.DeviceCertificateProfileStateHash(&profile)
		if err == nil && profile.Status == "active" && profile.ProfileID == intent.DeviceCertificateProfileRef.ProfileID &&
			profile.Generation == intent.DeviceCertificateProfileRef.Generation &&
			profile.DeviceCertificateProfileIntentHash == intent.DeviceCertificateProfileRef.DeviceCertificateProfileIntentHash && hash == intent.DeviceCertificateProfileRef.DeviceCertificateProfileStateHash {
			profileValid = containsControlValue(profile.ProfileIntent.AllowedPlatforms, intent.Platform)
			for _, responsibility := range intent.Responsibilities.Values {
				profileValid = profileValid && containsControlValue(profile.ProfileIntent.AllowedResponsibilities, responsibility)
			}
		}
	}
	if !profileValid {
		return nil, errors.New("[D102 Invite] Device certificate profile 未被当前 CA registry 激活")
	}
	for _, prior := range application.Invites {
		if prior.Record.InviteID == invite.Record.InviteID || prior.Record.TokenArtifactBindingHash == invite.Record.TokenArtifactBindingHash ||
			prior.Opening.DeviceEnrollmentIntent.DeviceID == intent.DeviceID {
			return nil, errors.New("[D114 Invite] Invite/Device/artifact 已存在")
		}
	}
	for _, device := range application.Devices {
		if device.View.DeviceID == intent.DeviceID {
			return nil, errors.New("[D114 Invite] 不能以新邀请覆盖已有 Device")
		}
	}
	ssot, err := model.Load([]byte(application.LegacySSOT))
	if err != nil {
		return nil, err
	}
	for _, node := range ssot.Nodes {
		if node.ID == intent.DeviceID {
			return nil, errors.New("[D114 Invite] 新邀请不能替代存量身份迁移")
		}
	}
	for _, grant := range intent.Grants.Values {
		valid := false
		if grant.Kind == "service" {
			for _, service := range ssot.Services {
				valid = valid || service.ID == grant.TargetID
			}
		} else if grant.Kind == "egress" {
			for _, node := range ssot.Nodes {
				valid = valid || node.ID == grant.TargetID && node.Server != nil && node.Server.EgressCapable && !node.Decommission
			}
		}
		if !valid {
			return nil, errors.New("[D123 Invite] destination grant 不属于当前可授权资源")
		}
	}
	next := controlClone(*application)
	next.Invites = append(next.Invites, controlClone(invite))
	sort.Slice(next.Invites, func(i, j int) bool { return next.Invites[i].Record.InviteID < next.Invites[j].Record.InviteID })
	if _, err := next.roots(); err != nil {
		return nil, err
	}
	return &next, nil
}

func containsControlValue(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func (runtime *controlRuntime) commitInviteLocked(ctx context.Context, verified wire.VerifiedAdminOperationV1) (controlplane.CertifiedControlOperationV1, error) {
	operation := verified.Operation()
	payload, err := decodeControlInvitePayload(controlplane.OperationPayload(ctx), operation)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	for index := range runtime.journal.Records {
		record := &runtime.journal.Records[index]
		if record.Leaf.OperationID == operation.Body.OperationID {
			if record.Invite == nil || !wire.EqualCanonical(record.Operation, operation) || !wire.EqualCanonical(*record.Invite, payload.Invite) {
				return controlplane.CertifiedControlOperationV1{}, errors.New("[D104 Invite] request ID 冲突")
			}
			if err := runtime.finishCommittedLocked(); err != nil {
				return controlplane.CertifiedControlOperationV1{}, err
			}
			if record.Result == nil {
				if err := runtime.recoverPendingOperationsLocked(); err != nil {
					return controlplane.CertifiedControlOperationV1{}, err
				}
			}
			return controlplaneResult(record.Result)
		}
	}
	for _, record := range runtime.journal.Records {
		if record.Result == nil {
			return controlplane.CertifiedControlOperationV1{}, errors.New("[D104 Invite] 先恢复已有 pending operation")
		}
	}
	state, raft := runtime.store.Snapshot(), runtime.storage.SnapshotRaft()
	if state.Active != nil || state.CertifiedHead == nil || state.CertifiedQC == nil || state.CertifiedHead.HeadHash != verified.HeadHash() ||
		len(raft.Log) == 0 || raft.LastApplied != raft.CommitIndex || raft.CommitIndex != int64(len(raft.Log)) {
		return controlplane.CertifiedControlOperationV1{}, errors.New("[D104 Invite] base/quorum 不可写")
	}
	application, err := runtime.applicationBefore(len(runtime.journal.Records))
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	logical := runtime.now().UTC().Truncate(time.Second).Format(time.RFC3339)
	if logical < state.CertifiedHead.Body.Payload.CommittedLogicalTime {
		logical = state.CertifiedHead.Body.Payload.CommittedLogicalTime
	}
	next, err := application.reduceInvite(payload.Invite, operation.Body, logical)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	der, err := authorizedAdminCertificate(runtime.config.Authorizations, operation.Body.AdminCertDigest)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	objectID, err := wire.ControlOperationObjectID(&operation, certificate.RawSubjectPublicKeyInfo, runtime.now().UTC(), controlOperationSchemas)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	leaf := wire.ControlOperationLeafV1{Schema: 1, OperationID: operation.Body.OperationID, ObjectID: objectID}
	inviteHash, err := wire.CertifiedInviteRecordHash(&payload.Invite.Record, &application.InvitePolicy)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	inviteLeaf := wire.ControlOperationLeafV1{Schema: 1, OperationID: payload.Invite.Record.OperationID, ObjectID: inviteHash}
	leaves := append(runtime.operationLeaves(len(runtime.journal.Records)), leaf, inviteLeaf)
	root, err := wire.ControlOperationRoot(leaves)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	body := state.CertifiedHead.Body
	body.Payload.HeadKind, body.Payload.ParentHeadHash, body.Payload.OperationRoot = "ordinary", state.CertifiedHead.HeadHash, root
	body.Payload.RaftTerm, body.Payload.RaftIndex = raft.CurrentTerm, int64(len(raft.Log))+1
	body.Payload.PreviousLogEntryHash, body.Payload.ControlRevision = raft.Log[len(raft.Log)-1].EntryHash, body.Payload.RaftIndex
	body.Payload.CommittedLogicalTime, body.Payload.TransitionContext = logical, json.RawMessage(`{"schema":1,"kind":"ordinary"}`)
	roots, err := next.roots()
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	controlApplyRoots(&body, roots)
	candidate, err := wire.NewHeadEntry(body)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	if err := runtime.persistInviteToken(payload); err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	index := len(runtime.journal.Records)
	runtime.journal.Records = append(runtime.journal.Records, controlOperationRecordV1{Schema: 1, Operation: operation,
		Leaf: leaf, AdditionalLeaves: []wire.ControlOperationLeafV1{inviteLeaf}, Candidate: candidate,
		Invite: &payload.Invite, Phases: []controlplane.Phase{controlplane.PhasePending}})
	if err := runtime.verifyPendingHead(ctx, candidate); err != nil {
		runtime.journal.Records = runtime.journal.Records[:index]
		return controlplane.CertifiedControlOperationV1{}, err
	}
	if err := runtime.persistJournalLocked(); err != nil {
		runtime.journal.Records = runtime.journal.Records[:index]
		return controlplane.CertifiedControlOperationV1{}, err
	}
	if runtime.checkpoint != nil {
		if err := runtime.checkpoint(controlplane.PhasePending); err != nil {
			return controlplane.CertifiedControlOperationV1{}, err
		}
	}
	if _, err := runtime.replicateHead(ctx, candidate); err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	if err := runtime.finishCommittedLocked(); err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	return controlplaneResult(runtime.journal.Records[index].Result)
}

func (runtime *controlRuntime) readInviteMaterial(_ context.Context, clusterID, inviteID string) (enrollmentv2.InviteMaterialV2, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.readInviteMaterialLocked(clusterID, inviteID)
}

func (runtime *controlRuntime) readInviteMaterialLocked(clusterID, inviteID string) (enrollmentv2.InviteMaterialV2, error) {
	state := runtime.store.Snapshot()
	if clusterID != runtime.config.ClusterID || state.CertifiedHead == nil || state.CertifiedQC == nil || state.Active != nil {
		return enrollmentv2.InviteMaterialV2{}, errors.New("[D130 Invite] 当前 authority 暂不可读")
	}
	application, err := runtime.certifiedApplicationLocked()
	if err != nil || application == nil {
		return enrollmentv2.InviteMaterialV2{}, errors.New("[D130 Invite] 当前入网状态不可用")
	}
	for _, invite := range application.Invites {
		if invite.Record.InviteID != inviteID {
			continue
		}
		status := invite.Status
		if status == "reserved" || status == "consumed" {
			transaction, found := runtime.enrollmentStore.SnapshotRecord(inviteID)
			matching := false
			for _, certified := range application.Transactions {
				if certified.InviteID == inviteID && wire.EqualCanonical(certified, transaction.State) {
					matching = true
					break
				}
			}
			if !found || !matching || status == "consumed" && transaction.State.Status != "completed" ||
				status == "reserved" && transaction.State.Status != "reserved" && transaction.State.Status != "issued_provisional" {
				return enrollmentv2.InviteMaterialV2{}, errors.New("[D130 Invite] 入网事务与认证投影不一致")
			}
			status = transaction.State.Status
		}
		for index, record := range runtime.journal.Records {
			if record.Invite == nil || record.Result == nil || record.Invite.Record.InviteID != inviteID {
				continue
			}
			parent, _, err := runtime.enrollmentLineage(record.Candidate, state.CertifiedHead.HeadHash)
			if err != nil || parent.HeadHash != state.CertifiedHead.HeadHash {
				return enrollmentv2.InviteMaterialV2{}, errors.New("[D130 Invite] Invite 不属于当前 certified lineage")
			}
			var recordParent wire.HeadEntryV2
			for _, log := range runtime.storage.SnapshotRaft().Log {
				if log.Head != nil && log.Head.HeadHash == record.Candidate.Body.Payload.ParentHeadHash {
					recordParent = *log.Head
					break
				}
			}
			leaf, leafIndex, treeSize, audit, err := wire.ControlOperationInclusionProof(runtime.operationLeaves(index+1), invite.Record.OperationID)
			if err != nil {
				return enrollmentv2.InviteMaterialV2{}, err
			}
			return enrollmentv2.InviteMaterialV2{Status: status, Record: invite.Record, Policy: application.InvitePolicy,
				Commitment: invite.Commitment, Opening: invite.Opening, EnrollmentServiceRef: application.EnrollmentService,
				ParentHead: recordParent, RecordHead: record.Candidate, RecordHeadQC: append(json.RawMessage(nil), record.Result.ConfigQC...),
				ControlSet: controlClone(runtime.config.ControlSet), InviteOperationLeaf: leaf, InviteLeafIndex: leafIndex,
				InviteTreeSize: treeSize, InviteAuditPath: audit}, nil
		}
	}
	return enrollmentv2.InviteMaterialV2{}, errors.New("[D130 Invite] 缺已认证邀请")
}
