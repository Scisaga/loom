package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"loom/internal/enrollmentv2"
	"loom/internal/model"
	"loom/internal/validate"
	"loom/internal/wire"
)

const (
	controlApplicationDomain = "loom-control-application-v1"
	controlEffectiveDomain   = "loom-control-effective-config-v1"
)

// controlApplicationV1 是 daemon 从已签迁移和累计 operation 确定性重放的私有
// 状态。certification 不进 snapshot preimage，避免 Head/QC 自引用（D104）。
// 旧 SSOT 作为明确的迁移输入保留；只有 completion 才将新 Device 加入 effective view。
type controlApplicationV1 struct {
	Schema             int                                     `json:"schema"`
	ClusterID          string                                  `json:"cluster_id"`
	LegacySSOT         string                                  `json:"legacy_ssot"`
	LegacyRegistryHash string                                  `json:"legacy_registry_hash"`
	RecoveryPolicy     wire.RecoveryPolicyV1                   `json:"recovery_policy"`
	RecoveryCustody    wire.RecoveryPrivateCustodyObjectV1     `json:"recovery_custody"`
	Authorizations     []wire.AdminAuthorizationV1             `json:"authorizations"`
	CARegistry         enrollmentv2.CARegistryPreimageV1       `json:"ca_registry"`
	Services           []wire.PrivateControlServiceV1          `json:"services"`
	EnrollmentService  wire.PrivateEnrollmentServiceRefV1      `json:"enrollment_service"`
	InvitePolicy       wire.InviteIssuancePolicyV2             `json:"invite_policy"`
	BootstrapIssuers   []wire.BootstrapIssuerAuthorizationV1   `json:"bootstrap_issuers"`
	DistributionSets   []wire.DistributionEndpointSetV1        `json:"distribution_sets,omitempty"`
	BootstrapCatalog   wire.BootstrapEndpointCatalogV1         `json:"bootstrap_catalog"`
	Mirrors            []wire.DistributionMirrorRefV1          `json:"mirrors"`
	Invites            []controlInviteStateV1                  `json:"invites"`
	Transactions       []enrollmentv2.TransactionStateV2       `json:"transactions"`
	IssuanceRegistry   []wire.EnrollmentIssuanceRegistryLeafV1 `json:"issuance_registry"`
	Devices            []controlDeviceStateV1                  `json:"devices"`
	DeviceMigrations   []wire.RuntimeDeviceMigrationLeafV1     `json:"device_migrations,omitempty"`
	DeferredMigrations []controlDeferredDeviceMigrationV1      `json:"deferred_migrations,omitempty"`
	ArtifactPolicies   []wire.ArtifactAvailabilityPolicyV1     `json:"artifact_policies,omitempty"`
}

// 未在用且尚未提供原 key 迁移请求的历史记录只保留原身份，不能伪造
// wrapping key/floor，也不进入 active Device view 或被当作已完成迁移。
type controlDeferredDeviceMigrationV1 struct {
	DeviceID         string `json:"device_id"`
	Platform         string `json:"platform"`
	IdentitySPKIHash string `json:"identity_spki_hash"`
}

type controlInviteStateV1 struct {
	Status      string                                  `json:"status"`
	DisplayName string                                  `json:"display_name"`
	Record      wire.CertifiedInviteRecordV2            `json:"record"`
	Commitment  wire.DeviceEnrollmentIntentCommitmentV1 `json:"commitment"`
	Opening     wire.DeviceEnrollmentIntentOpeningV1    `json:"opening"`
}

type controlDeviceStateV1 struct {
	View               wire.DeviceViewPayloadV2   `json:"view"`
	PreviousViewHash   string                     `json:"previous_view_hash"`
	SecretArtifactRefs []wire.SecretArtifactRefV2 `json:"secret_artifact_refs"`
	EnrollmentInviteID string                     `json:"enrollment_invite_id"`
}

func controlClone[T any](value T) T {
	encoded, err := wire.MarshalCanonical(value)
	if err != nil {
		panic(err)
	}
	var clone T
	if _, err := wire.DecodeStrict(encoded, 64<<20, &clone); err != nil {
		panic(err)
	}
	return clone
}

func (application *controlApplicationV1) adminProfiles() map[string]wire.AdminCertificateProfileV1 {
	profiles := make(map[string]wire.AdminCertificateProfileV1, len(application.CARegistry.AdminProfiles))
	for _, profile := range application.CARegistry.AdminProfiles {
		profiles[profile.ProfileID] = profile
	}
	return profiles
}

func (application *controlApplicationV1) reduceAdminRotation(payload controlAdminRotationPayloadV1) (*controlApplicationV1, error) {
	if application == nil || len(application.Authorizations) != 1 ||
		!wire.EqualCanonical(application.Authorizations[0], payload.PreviousAuthorization) ||
		!wire.EqualCanonical(application.adminProfiles()[payload.PreviousProfile.ProfileID], payload.PreviousProfile) {
		return nil, errors.New("[D102 application] 管理员轮换 base 与当前状态不一致")
	}
	next := controlClone(*application)
	next.Authorizations[0] = controlClone(payload.NextAuthorization)
	for index := range next.CARegistry.AdminProfiles {
		if next.CARegistry.AdminProfiles[index].ProfileID == payload.PreviousProfile.ProfileID {
			next.CARegistry.AdminProfiles[index] = controlClone(payload.NextProfile)
		}
	}
	return &next, nil
}

func (application *controlApplicationV1) roots() (wire.RuntimeActivationRootsV1, error) {
	if err := application.validate(); err != nil {
		return wire.RuntimeActivationRootsV1{}, err
	}
	snapshot, err := wire.HashObject(controlApplicationDomain, application)
	if err != nil {
		return wire.RuntimeActivationRootsV1{}, err
	}
	// Invitation/reservation/provisional 不授予业务访问；effective config 只含现有
	// 配置与 completion 已激活的 Device projection（D104、D130）。
	effective, err := wire.HashObject(controlEffectiveDomain, struct {
		Schema     int                    `json:"schema"`
		ClusterID  string                 `json:"cluster_id"`
		LegacySSOT string                 `json:"legacy_ssot"`
		Devices    []controlDeviceStateV1 `json:"devices"`
	}{1, application.ClusterID, application.LegacySSOT, application.Devices})
	if err != nil {
		return wire.RuntimeActivationRootsV1{}, err
	}
	_, leaves, err := application.deviceLeaves()
	if err != nil {
		return wire.RuntimeActivationRootsV1{}, err
	}
	acl, err := wire.AdminACLRoot(application.Authorizations, application.adminProfiles())
	if err != nil {
		return wire.RuntimeActivationRootsV1{}, err
	}
	ca, err := wire.CAProfileRoot(application.CARegistry.AdminProfiles, application.CARegistry.DeviceProfiles)
	if err != nil {
		return wire.RuntimeActivationRootsV1{}, err
	}
	_, issuerLeaves, err := application.issuerLeaves()
	if err != nil {
		return wire.RuntimeActivationRootsV1{}, err
	}
	return wire.RuntimeActivationRootsV1{SnapshotHash: snapshot, EffectiveSSOTHash: effective,
		DeviceViewsRoot: fmt.Sprintf("sha256:%x", wire.MerkleRoot(leaves)), AdminACLRoot: acl, CAProfileRoot: ca,
		BootstrapIssuerRegistryRoot: fmt.Sprintf("sha256:%x", wire.MerkleRoot(issuerLeaves)), RenderContractVersion: 2}, nil
}

func (application *controlApplicationV1) validate() error {
	if application == nil || application.Schema != 1 || application.ClusterID == "" ||
		application.Invites == nil || application.Transactions == nil || application.IssuanceRegistry == nil ||
		application.Devices == nil || application.Authorizations == nil || application.CARegistry.AdminProfiles == nil ||
		application.CARegistry.DeviceProfiles == nil || application.BootstrapIssuers == nil {
		return errors.New("[D104 application] 缺完整状态 preimage")
	}
	legacy, err := model.Load([]byte(application.LegacySSOT))
	if err != nil {
		return err
	}
	if findings := validate.Validate(legacy); len(findings) != 0 {
		return errors.New("[D104 application] 保留的 SSOT 不合法")
	}
	if _, err := wire.ParseHash(application.LegacyRegistryHash); err != nil {
		return err
	}
	if err := wire.ValidateRecoveryPolicy(&application.RecoveryPolicy); err != nil {
		return err
	}
	if err := wire.ValidateRecoveryPrivateCustody(&application.RecoveryPolicy, &application.RecoveryCustody); err != nil {
		return err
	}
	for i, policy := range application.ArtifactPolicies {
		if err := wire.ValidateArtifactAvailabilityPolicy(&policy); err != nil {
			return err
		}
		if policy.ClusterID != application.ClusterID || i > 0 && application.ArtifactPolicies[i-1].PolicyID >= policy.PolicyID {
			return errors.New("[配置发布] artifact policy 必须属于本网络且按 ID 唯一排序")
		}
	}
	if application.RecoveryPolicy.ClusterID != application.ClusterID || application.InvitePolicy.ClusterID != application.ClusterID {
		return errors.New("[D104 application] policy cluster 不一致")
	}
	if err := wire.ValidateInviteIssuancePolicy(&application.InvitePolicy); err != nil {
		return err
	}
	if err := wire.ValidatePrivateEnrollmentServiceRef(&application.EnrollmentService); err != nil {
		return err
	}
	roles, tuples := make(map[string]bool), make(map[string]bool)
	for _, service := range application.Services {
		if err := wire.ValidatePrivateControlService(&service); err != nil {
			return err
		}
		tuple := fmt.Sprintf("%s:%d", service.OverlayIP, service.Port)
		if roles[service.Role] || tuples[tuple] {
			return errors.New("[D131 application] 私有服务 role/tuple 重复")
		}
		roles[service.Role], tuples[tuple] = true, true
		if service.Role == "enroll" && (service.ServiceID != application.EnrollmentService.ServiceID ||
			service.OverlayIP != application.EnrollmentService.OverlayIP || service.Port != application.EnrollmentService.TCPPort ||
			!wire.EqualCanonical(service.SPKIPins, application.EnrollmentService.ServerIdentitySPKIPins)) {
			return errors.New("[D131 application] Enrollment service ref 与服务目录不一致")
		}
	}
	for _, role := range []string{"control_api", "enroll", "device_config", "device_report"} {
		if !roles[role] {
			return errors.New("[D131 application] 私有服务目录不完整")
		}
	}
	if err := wire.ValidateBootstrapEndpointCatalog(&application.BootstrapCatalog); err != nil {
		return err
	}
	if application.BootstrapCatalog.ClusterID != application.ClusterID {
		return errors.New("[D131 application] catalog cluster 不一致")
	}
	if err := wire.ValidateDistributionMirrorRefs(application.Mirrors); err != nil {
		return err
	}
	if application.DistributionSets != nil {
		sets := make(map[string]wire.DistributionEndpointSetV1, len(application.DistributionSets))
		for _, set := range application.DistributionSets {
			hash, err := wire.DistributionEndpointSetHash(&set)
			if err != nil || set.ClusterID != application.ClusterID {
				return errors.New("分发 preimage 不属于当前网络或格式无效")
			}
			if _, found := sets[hash]; found {
				return errors.New("重复的分发 preimage")
			}
			sets[hash] = set
		}
		if err := wire.ValidateDistributionMirrorBindings(application.ClusterID, application.Mirrors, sets); err != nil {
			return err
		}
	}
	if int64(len(application.Mirrors)) < application.InvitePolicy.MinimumDistributionMirrors ||
		int64(len(application.Mirrors)) > application.InvitePolicy.MaximumDistributionMirrors {
		return errors.New("[D131 application] distribution mirror 数量不符")
	}
	for i, invite := range application.Invites {
		if invite.Record.ClusterID != application.ClusterID || i > 0 && application.Invites[i-1].Record.InviteID >= invite.Record.InviteID ||
			(invite.Status != "available" && invite.Status != "reserved" && invite.Status != "consumed" && invite.Status != "revoked") {
			return errors.New("[D130 application] Invite 次序/状态/cluster 无效")
		}
		if err := wire.ValidateCertifiedInviteRecord(&invite.Record, &application.InvitePolicy); err != nil {
			return err
		}
		commitment, hash, err := wire.IntentCommitment(&invite.Opening)
		if err != nil || !wire.EqualCanonical(commitment, invite.Commitment) || hash != invite.Record.DeviceEnrollmentIntentCommitmentHash {
			return errors.New("[D130 application] Invite opening/commitment 不一致")
		}
	}
	for i, transaction := range application.Transactions {
		if transaction.ClusterID != application.ClusterID || i > 0 && application.Transactions[i-1].InviteID >= transaction.InviteID {
			return errors.New("[D130 application] transaction 次序/cluster 无效")
		}
		if _, err := enrollmentv2.TransactionHash(transaction); err != nil {
			return err
		}
	}
	if _, err := wire.EnrollmentIssuanceRegistryRoot(application.IssuanceRegistry); err != nil {
		return err
	}
	if _, err := wire.RuntimeDeviceMigrationRoot(application.DeviceMigrations); err != nil {
		return err
	}
	for _, migration := range application.DeviceMigrations {
		if migration.ClusterID != application.ClusterID {
			return errors.New("[设备迁移] 原身份不属于本网络")
		}
		found := false
		for _, device := range application.Devices {
			if device.View.DeviceID != migration.DeviceID {
				continue
			}
			if device.EnrollmentInviteID != "" || device.View.Active != nil &&
				device.View.Active.IdentitySPKIHash != migration.IdentitySPKIHash {
				return errors.New("[设备迁移] 原身份不能伪造新入网或被替换")
			}
			found = true
		}
		if !found {
			return errors.New("[设备迁移] 认证状态丢失原 Device")
		}
	}
	for i, pending := range application.DeferredMigrations {
		node := legacy.NodeByID()[pending.DeviceID]
		if node == nil || node.Access == nil || node.Server != nil ||
			string(node.Access.Platform) != pending.Platform ||
			i > 0 && application.DeferredMigrations[i-1].DeviceID >= pending.DeviceID {
			return errors.New("[设备迁移] 暂存身份必须是原网络的独立客户端并按 ID 唯一排序")
		}
		if _, err := wire.ParseHash(pending.IdentitySPKIHash); err != nil {
			return err
		}
		for _, device := range application.Devices {
			if device.View.DeviceID == pending.DeviceID {
				return errors.New("[设备迁移] 暂存身份不能同时成为 v2 Device")
			}
		}
		for _, invite := range application.Invites {
			if invite.Opening.DeviceEnrollmentIntent.DeviceID == pending.DeviceID {
				return errors.New("[设备迁移] 暂存身份不能被新邀请覆盖")
			}
		}
	}
	return nil
}

func (application *controlApplicationV1) deviceLeaves() ([]wire.DeviceViewLeafV2, [][]byte, error) {
	leaves := make([]wire.DeviceViewLeafV2, len(application.Devices))
	encoded := make([][]byte, len(leaves))
	for i, device := range application.Devices {
		view := device.View
		if view.ClusterID != application.ClusterID || i > 0 && application.Devices[i-1].View.DeviceID >= view.DeviceID {
			return nil, nil, errors.New("[D105 application] Device 次序/cluster 无效")
		}
		viewHash, err := wire.DeviceViewHash(&view)
		if err != nil {
			return nil, nil, err
		}
		if _, err := wire.ParseHash(device.PreviousViewHash); err != nil {
			return nil, nil, err
		}
		endpointHash := wire.EmptyHashV1
		if view.Active != nil {
			root, err := wire.SecretArtifactRefsRoot(device.SecretArtifactRefs)
			if err != nil || root != view.Active.SecretArtifactRefsRoot {
				return nil, nil, errors.New("[D124 application] Device secret refs 不一致")
			}
			endpointHash = view.Active.EndpointBundleHash
		}
		leaves[i] = wire.DeviceViewLeafV2{Schema: 2, ClusterID: view.ClusterID, ViewSchemaVersion: 2,
			DeviceID: view.DeviceID, DeviceGeneration: view.DeviceGeneration, State: view.State,
			PayloadHash: viewHash, PreviousViewHash: device.PreviousViewHash, EndpointSetHash: endpointHash, MinReaderVersion: 2}
		encoded[i], err = wire.MarshalCanonical(leaves[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return leaves, encoded, nil
}

func (application *controlApplicationV1) issuerLeaves() ([]wire.BootstrapIssuerAuthorizationLeafV1, [][]byte, error) {
	leaves := make([]wire.BootstrapIssuerAuthorizationLeafV1, len(application.BootstrapIssuers))
	encoded := make([][]byte, len(leaves))
	for i, issuer := range application.BootstrapIssuers {
		if issuer.ClusterID != application.ClusterID || i > 0 && application.BootstrapIssuers[i-1].AuthorizationID >= issuer.AuthorizationID {
			return nil, nil, errors.New("[D115 application] issuer 次序/cluster 无效")
		}
		hash, err := wire.BootstrapIssuerAuthorizationHash(&issuer)
		if err != nil {
			return nil, nil, err
		}
		leaves[i] = wire.BootstrapIssuerAuthorizationLeafV1{Schema: 1, AuthorizationID: issuer.AuthorizationID, Generation: issuer.Generation, AuthorizationHash: hash}
		encoded[i], err = wire.MarshalCanonical(leaves[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return leaves, encoded, nil
}

func controlApplyRoots(body *wire.HeadEntryBodyV2, roots wire.RuntimeActivationRootsV1) {
	body.Payload.SnapshotHash, body.Payload.EffectiveSSOTHash = roots.SnapshotHash, roots.EffectiveSSOTHash
	body.Payload.DeviceViewsRoot, body.Payload.AdminACLRoot = roots.DeviceViewsRoot, roots.AdminACLRoot
	body.Payload.CAProfileRoot, body.Payload.BootstrapIssuerRegistryRoot = roots.CAProfileRoot, roots.BootstrapIssuerRegistryRoot
	body.Payload.RenderContractVersion = roots.RenderContractVersion
}

func (application *controlApplicationV1) deviceEnvelope(deviceID string, head wire.HeadEntryV2,
	qc json.RawMessage) (wire.DeviceViewEnvelopeV2, error) {
	index := sort.Search(len(application.Devices), func(i int) bool { return application.Devices[i].View.DeviceID >= deviceID })
	if index == len(application.Devices) || application.Devices[index].View.DeviceID != deviceID {
		return wire.DeviceViewEnvelopeV2{}, errors.New("[D105 application] Device 不存在")
	}
	leaves, raw, err := application.deviceLeaves()
	if err != nil {
		return wire.DeviceViewEnvelopeV2{}, err
	}
	if fmt.Sprintf("sha256:%x", wire.MerkleRoot(raw)) != head.Body.Payload.DeviceViewsRoot {
		return wire.DeviceViewEnvelopeV2{}, errors.New("[D105 application] Device tree 与 Head 不一致")
	}
	path, err := wire.MerkleInclusionPath(raw, int64(index))
	if err != nil {
		return wire.DeviceViewEnvelopeV2{}, err
	}
	audit := make([]string, len(path))
	for i, hash := range path {
		audit[i] = fmt.Sprintf("sha256:%x", hash)
	}
	device := application.Devices[index]
	envelope := wire.DeviceViewEnvelopeV2{Schema: 2, Payload: device.View, Leaf: leaves[index],
		LeafIndex: int64(index), TreeSize: int64(len(leaves)), AuditPath: audit,
		SignedCurrent: wire.SignedCurrentV2{Schema: 2, Head: head, QuorumCertificate: qc,
			PublishedAt: head.Body.Payload.CommittedLogicalTime}}
	if device.View.State == "active" {
		envelope.SecretArtifactRefs = make([]json.RawMessage, len(device.SecretArtifactRefs))
		for i, ref := range device.SecretArtifactRefs {
			envelope.SecretArtifactRefs[i], err = wire.MarshalCanonical(ref)
			if err != nil {
				return wire.DeviceViewEnvelopeV2{}, err
			}
		}
	}
	return envelope, nil
}
