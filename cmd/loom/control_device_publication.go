package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"time"

	"loom/internal/controlplane"
	"loom/internal/distribution"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

const controlPublishDeviceKind = "publish_device_config"

// 配置更新只改变现有 Device 的配置代，不创建身份，也不扩大职责和授权。
// 公开配置和证据参与签名与重放；密文另存，秘密明文从不进入控制日志。
type controlDevicePublicationV1 struct {
	Schema           int                                     `json:"schema"`
	DeviceID         string                                  `json:"device_id"`
	PreviousViewHash string                                  `json:"previous_view_hash"`
	Configs          []controlPublishedConfigV1              `json:"configs"`
	Secrets          []enrollmentv2.SealedMaterialEvidenceV1 `json:"secrets"`
	ControlLink      *wire.DeviceControlLinkV1               `json:"control_link,omitempty"`
}

type controlPublishedConfigV1 struct {
	Ref     wire.DeviceConfigArtifactRefV1 `json:"ref"`
	Content json.RawMessage                `json:"content"`
}

type controlPublishDevicePayloadV1 struct {
	Schema      int                           `json:"schema"`
	Publication controlDevicePublicationV1    `json:"publication"`
	Envelopes   []wire.SealedSecretEnvelopeV1 `json:"envelopes"`
}

func controlDevicePublicationHash(publication controlDevicePublicationV1) (string, error) {
	return wire.HashObject("loom-control-device-publication-v1", publication)
}

func decodeControlDevicePublication(raw json.RawMessage, operation wire.ControlOperationV1) (controlPublishDevicePayloadV1, error) {
	var payload controlPublishDevicePayloadV1
	canonical, err := wire.DecodeStrict(raw, 3<<20, &payload)
	if err != nil || !bytes.Equal(canonical, raw) || payload.Schema != 1 || operation.Body.Kind != controlPublishDeviceKind {
		return payload, errors.New("[配置发布] 缺规范的私有发布请求")
	}
	hash, err := controlDevicePublicationHash(payload.Publication)
	if err != nil || hash != operation.Body.PayloadHash || len(payload.Envelopes) != len(payload.Publication.Secrets) {
		return payload, errors.New("[配置发布] 请求与管理签名或秘密数量不一致")
	}
	for i := range payload.Envelopes {
		if err := wire.VerifySealedSecretBinding(&payload.Publication.Secrets[i].Ref, &payload.Envelopes[i]); err != nil {
			return payload, err
		}
	}
	return payload, nil
}

func (application *controlApplicationV1) reduceDevicePublication(publication controlDevicePublicationV1,
	operation wire.ControlOperationBodyV1, committedAt string) (*controlApplicationV1, error) {
	if application == nil || publication.Schema != 1 || operation.Kind != controlPublishDeviceKind ||
		operation.ClusterID != application.ClusterID || len(publication.Configs) == 0 || publication.Secrets == nil {
		return nil, errors.New("[配置发布] 缺当前状态、运行配置或秘密集合")
	}
	for _, plan := range application.EnrollmentPlans {
		if operation.OperationID == plan.OperationID {
			continue
		}
		for _, server := range plan.Servers {
			if server.DeviceID == publication.DeviceID {
				return nil, errors.New("[配置发布] 先完成已签发的入网事务，不能覆盖其服务器配置")
			}
		}
	}
	hash, err := controlDevicePublicationHash(publication)
	if err != nil || hash != operation.PayloadHash {
		return nil, errors.New("[配置发布] 管理签名未承诺本次发布")
	}
	at, err := wire.ParseTimeZ(committedAt)
	if err != nil {
		return nil, err
	}
	index := -1
	for i, device := range application.Devices {
		if device.View.DeviceID == publication.DeviceID {
			index = i
		}
	}
	if index < 0 || application.Devices[index].View.Active == nil || application.Devices[index].View.State != "active" {
		return nil, errors.New("[配置发布] 设备尚未认证或已被撤销")
	}
	prior := application.Devices[index]
	previousHash, err := wire.DeviceViewHash(&prior.View)
	if err != nil || previousHash != publication.PreviousViewHash || prior.View.DeviceGeneration == math.MaxInt64 {
		return nil, errors.New("[配置发布] 设备已变化或配置代已耗尽")
	}
	platform, err := application.devicePlatform(publication.DeviceID)
	if err != nil {
		return nil, err
	}
	refs := make([]wire.DeviceConfigArtifactRefV1, len(publication.Configs))
	for i, config := range publication.Configs {
		if err := wire.ValidateDeviceConfigArtifactRef(&config.Ref); err != nil {
			return nil, err
		}
		canonical, err := wire.CanonicalizeStrict(config.Content)
		digest, hashErr := wire.DeviceConfigArtifactContentHash(config.Content)
		if err != nil || hashErr != nil || !bytes.Equal(canonical, config.Content) || digest != config.Ref.ContentHash ||
			int64(len(config.Content)) != config.Ref.SizeBytes || config.Ref.Platform != platform ||
			i > 0 && publication.Configs[i-1].Ref.ArtifactID >= config.Ref.ArtifactID {
			return nil, errors.New("[配置发布] 制品原文、平台、摘要或排序不一致")
		}
		if err := validateControlRuntimeArtifact(config, application.ClusterID, publication.DeviceID, prior.View.DeviceGeneration+1); err != nil {
			return nil, err
		}
		for _, old := range prior.View.Active.ConfigArtifactRefs {
			if old.ArtifactID == config.Ref.ArtifactID && config.Ref.Generation <= old.Generation {
				return nil, errors.New("[配置发布] 制品 generation 必须递增")
			}
		}
		refs[i] = config.Ref
	}
	if err := validateControlRuntimeSet(publication.Configs, platform, operation.ParentHeadHash); err != nil {
		return nil, err
	}
	secrets := make([]wire.SecretArtifactRefV2, len(publication.Secrets))
	wrappingHash, err := application.deviceWrappingHash(prior)
	if err != nil {
		return nil, err
	}
	for i, evidence := range publication.Secrets {
		ref := evidence.Ref
		if ref.ClusterID != application.ClusterID || ref.Owner.Device == nil || ref.Owner.Device.DeviceID != publication.DeviceID ||
			ref.SealedBlob == nil || (ref.Purpose != "device_credential" && ref.Purpose != "data_plane_credential") {
			return nil, errors.New("[配置发布] 秘密 owner、用途或存储方式不符")
		}
		if len(ref.SealedBlob.RecipientKeyVersions) != 1 {
			return nil, errors.New("[配置发布] 设备凭据只能封装给已认证的设备 wrapping key")
		}
		recipient := ref.SealedBlob.RecipientKeyVersions[0]
		spki, decodeErr := base64.RawURLEncoding.DecodeString(recipient.RecipientPublicKey.PublicKeySPKIDER)
		recipientHash, hashErr := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, spki)
		if decodeErr != nil || hashErr != nil || recipientHash != wrappingHash || recipient.RecipientID != publication.DeviceID {
			return nil, errors.New("[配置发布] 密文 recipient 不是原认证 wrapping key")
		}
		// 完全相同的已认证 ref 可以复用；轮换必须提交当前有效的真实证据。
		retained := false
		for _, old := range prior.SecretArtifactRefs {
			retained = retained || wire.EqualCanonical(old, ref)
		}
		if !retained {
			for _, old := range prior.SecretArtifactRefs {
				if old.SecretID == ref.SecretID && ref.Generation <= old.Generation {
					return nil, errors.New("[配置发布] 秘密 generation 倒退或同代分叉")
				}
			}
			approved := false
			for _, policy := range application.ArtifactPolicies {
				approved = approved || wire.EqualCanonical(policy, evidence.Policy)
			}
			if !approved || ref.ProposalID != operation.OperationID {
				return nil, errors.New("[配置发布] 秘密缺 parent 认证的 policy 或本次 proposal binding")
			}
			if err := wire.VerifySecretArtifactEvidence(&ref, evidence.Proof, &evidence.Policy, evidence.Receipts, at, 0, ref.SealedBlob.CiphertextDigest); err != nil {
				return nil, err
			}
		}
		secrets[i] = ref
	}
	secretRoot, err := wire.SecretArtifactRefsRoot(secrets)
	if err != nil {
		return nil, err
	}
	next := controlClone(*application)
	if err := next.applyDeviceControlPublication(publication, platform); err != nil {
		return nil, err
	}
	device := &next.Devices[index]
	device.PreviousViewHash = previousHash
	device.View.DeviceGeneration++
	device.View.Active.EndpointBundle.DeviceGeneration = device.View.DeviceGeneration
	device.View.Active.EndpointBundleHash, err = wire.DeviceEndpointBundleHash(&device.View.Active.EndpointBundle)
	if err != nil {
		return nil, err
	}
	device.View.Active.ConfigArtifactRefs = refs
	device.View.Active.SecretArtifactRefsRoot, device.SecretArtifactRefs = secretRoot, secrets
	if _, err := next.roots(); err != nil {
		return nil, err
	}
	return &next, nil
}

func (application *controlApplicationV1) deviceWrappingHash(device controlDeviceStateV1) (string, error) {
	for _, migration := range application.DeviceMigrations {
		if migration.DeviceID == device.View.DeviceID {
			return migration.WrappingKeyHash, nil
		}
	}
	for _, transaction := range application.Transactions {
		if transaction.InviteID == device.EnrollmentInviteID && transaction.Status == "completed" {
			return transaction.WrappingKeyHash, nil
		}
	}
	return "", errors.New("[配置发布] 设备没有已认证的 wrapping key")
}

func (application *controlApplicationV1) devicePlatform(deviceID string) (string, error) {
	for _, migration := range application.DeviceMigrations {
		if migration.DeviceID == deviceID {
			return migration.Platform, nil
		}
	}
	for _, invite := range application.Invites {
		if invite.Opening.DeviceEnrollmentIntent.DeviceID == deviceID && invite.Status == "consumed" {
			return invite.Opening.DeviceEnrollmentIntent.Platform, nil
		}
	}
	return "", errors.New("[配置发布] 设备没有已认证的平台身份")
}

func (runtime *controlRuntime) persistDevicePublication(payload controlPublishDevicePayloadV1) error {
	store, err := enrollmentv2.OpenSealedArtifactStore(filepath.Join(runtime.dir, "sealed-artifacts"))
	if err != nil {
		return err
	}
	for i := range payload.Envelopes {
		if err := store.Put(&payload.Publication.Secrets[i].Ref, &payload.Envelopes[i]); err != nil {
			return err
		}
	}
	for _, config := range payload.Publication.Configs {
		ref, _, err := distribution.PublishDeviceConfigArtifact(filepath.Join(runtime.dir, "public"), config.Ref.ArtifactID,
			config.Ref.Platform, config.Ref.MediaType, config.Ref.RenderContractID, config.Ref.Generation, config.Content)
		if err != nil || !wire.EqualCanonical(ref, config.Ref) {
			return errors.New("[配置发布] 不可变配置存储与认证引用不一致")
		}
	}
	return nil
}

func (runtime *controlRuntime) commitDevicePublicationLocked(ctx context.Context, verified wire.VerifiedAdminOperationV1) (controlplane.CertifiedControlOperationV1, error) {
	operation := verified.Operation()
	payload, err := decodeControlDevicePublication(controlplane.OperationPayload(ctx), operation)
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	for index := range runtime.journal.Records {
		record := &runtime.journal.Records[index]
		if record.Leaf.OperationID != operation.Body.OperationID {
			continue
		}
		if record.DevicePublication == nil || !wire.EqualCanonical(record.Operation, operation) || !wire.EqualCanonical(*record.DevicePublication, payload.Publication) {
			return controlplane.CertifiedControlOperationV1{}, errors.New("[配置发布] request ID 已绑定不同发布")
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
	for _, record := range runtime.journal.Records {
		if record.Result == nil {
			return controlplane.CertifiedControlOperationV1{}, errors.New("[配置发布] 先恢复已有 pending operation")
		}
	}
	state, raft := runtime.store.Snapshot(), runtime.storage.SnapshotRaft()
	if state.Active != nil || state.CertifiedHead == nil || state.CertifiedQC == nil || state.CertifiedHead.HeadHash != verified.HeadHash() ||
		len(raft.Log) == 0 || raft.LastApplied != raft.CommitIndex || raft.CommitIndex != int64(len(raft.Log)) {
		return controlplane.CertifiedControlOperationV1{}, errors.New("[配置发布] base/quorum 不可写")
	}
	application, err := runtime.applicationBefore(len(runtime.journal.Records))
	if err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	logical := runtime.now().UTC().Truncate(time.Second).Format(time.RFC3339)
	if logical < state.CertifiedHead.Body.Payload.CommittedLogicalTime {
		logical = state.CertifiedHead.Body.Payload.CommittedLogicalTime
	}
	next, err := application.reduceDevicePublication(payload.Publication, operation.Body, logical)
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
	root, err := wire.ControlOperationRoot(append(runtime.operationLeaves(len(runtime.journal.Records)), leaf))
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
	if err := runtime.persistDevicePublication(payload); err != nil {
		return controlplane.CertifiedControlOperationV1{}, err
	}
	index := len(runtime.journal.Records)
	runtime.journal.Records = append(runtime.journal.Records, controlOperationRecordV1{Schema: 1, Operation: operation,
		Leaf: leaf, Candidate: candidate, DevicePublication: &payload.Publication, Phases: []controlplane.Phase{controlplane.PhasePending}})
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
