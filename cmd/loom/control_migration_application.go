package main

import (
	"errors"
	"math"
	"os"
	"sort"

	"loom/internal/bootstrapaccess"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

// Prepared 输入只携带已有材料的完整 preimage；当前管理员、原 SSOT/registry
// 与 Head 从原网络读取。调用方不能手填迁移后的 ACL、Device view 或证书坐标。
type controlMigrationPreparedV1 struct {
	Schema                int                                             `json:"schema"`
	ClusterID             string                                          `json:"cluster_id"`
	Materials             controlPreparedMigrationMaterialsV1             `json:"materials"`
	Recovery              controlRecoveryMaterialV1                       `json:"recovery"`
	InvitePolicy          wire.InviteIssuancePolicyV2                     `json:"invite_policy"`
	BootstrapCatalog      wire.BootstrapEndpointCatalogV1                 `json:"bootstrap_catalog"`
	BootstrapInstallation *bootstrapaccess.InitialBootstrapInstallationV1 `json:"bootstrap_installation,omitempty"`
	BootstrapIssuers      []wire.BootstrapIssuerAuthorizationV1           `json:"bootstrap_issuers"`
	DistributionSets      []wire.DistributionEndpointSetV1                `json:"distribution_sets"`
	Mirrors               []wire.DistributionMirrorRefV1                  `json:"mirrors"`
	DeferredMigrations    []controlDeferredDeviceMigrationV1              `json:"deferred_migrations,omitempty"`
}

func (runtime *controlRuntime) prepareMigrationApplication(input *controlMigrationInputV1) error {
	if input == nil || input.Prepared == nil || input.Schema != 1 || input.DeviceInputs == nil ||
		!wire.EqualCanonical(input.Application, controlApplicationV1{}) || len(input.RecoveryProofs) != 0 {
		return errors.New("材料迁移须使用逐设备签名请求，不能混用手填 application 或恢复证明")
	}
	prepared := input.Prepared
	materials := &prepared.Materials
	if prepared.Schema != 1 || prepared.ClusterID != runtime.config.ClusterID || materials.Schema != 1 ||
		materials.ClusterID != prepared.ClusterID || materials.DeviceID != runtime.config.DeviceID ||
		materials.PrivateServices.Schema != 1 || materials.PrivateServices.ClusterID != prepared.ClusterID ||
		materials.PrivateServices.DeviceID != runtime.config.DeviceID || materials.RequestID == "" ||
		materials.PrivateServices.ProposalID != materials.RequestID || prepared.Recovery.Schema != 1 ||
		prepared.Recovery.Policy.ClusterID != prepared.ClusterID {
		return errors.New("迁移材料未绑定原网络、控制设备或固定准备请求")
	}
	state := runtime.store.Snapshot()
	if state.CertifiedHead == nil || state.CertifiedQC == nil || state.Active != nil ||
		state.CertifiedHead.Body.Payload.RecoveryEpoch != 1 {
		return errors.New("原网络不处于可迁移的稳定认证状态")
	}
	if len(runtime.config.Authorizations) != 1 {
		return errors.New("当前迁移要求原 N=1 管理员授权")
	}
	previous := runtime.config.Authorizations[0]
	profile, found := runtime.config.AdminProfiles[previous.CertificateProfileRef.ProfileID]
	if !found || previous.Generation == math.MaxInt64 {
		return errors.New("缺原管理员 profile 或授权代已耗尽")
	}
	admin := controlClone(previous)
	admin.PreviousAuthorizationHash, _ = wire.AdminAuthorizationHash(&previous, &profile)
	admin.Generation++
	// 本轮不激活 DNS 操作；原管理员的身份、范围与有效期原样保留。
	admin.AllowedOperationKinds = []string{controlPingKind, controlCreateInviteKind, controlPublishDeviceKind}
	sort.Strings(admin.AllowedOperationKinds)
	source, err := os.ReadFile(input.Source)
	if err != nil {
		return err
	}
	registry, err := readOwnerOnlyFile(input.Registry, 4<<20)
	if err != nil {
		return err
	}
	application := controlApplicationV1{Schema: 1, ClusterID: prepared.ClusterID,
		LegacySSOT: string(source), LegacyRegistryHash: wire.HashRaw("loom-legacy-registry-migration-v1", registry),
		RecoveryPolicy: prepared.Recovery.Policy, RecoveryCustody: prepared.Recovery.Custody,
		Authorizations: []wire.AdminAuthorizationV1{admin}, CARegistry: enrollmentv2.CARegistryPreimageV1{
			AdminProfiles: []wire.AdminCertificateProfileV1{profile}, DeviceProfiles: []wire.DeviceCertificateProfileStateV1{materials.DeviceProfile}},
		Services:     []wire.PrivateControlServiceV1{runtime.config.ControlService},
		InvitePolicy: prepared.InvitePolicy, BootstrapIssuers: prepared.BootstrapIssuers,
		BootstrapCatalog: prepared.BootstrapCatalog, BootstrapInstallation: prepared.BootstrapInstallation, DistributionSets: prepared.DistributionSets, Mirrors: prepared.Mirrors,
		Invites: []controlInviteStateV1{}, Transactions: []enrollmentv2.TransactionStateV2{},
		IssuanceRegistry: []wire.EnrollmentIssuanceRegistryLeafV1{}, Devices: []controlDeviceStateV1{},
		DeferredMigrations: prepared.DeferredMigrations, ArtifactPolicies: []wire.ArtifactAvailabilityPolicyV1{materials.ArtifactPolicy}}
	for _, material := range materials.PrivateServices.Services {
		application.Services = append(application.Services, material.Service)
		if material.Service.Role == "enroll" {
			application.EnrollmentService = wire.PrivateEnrollmentServiceRefV1{Schema: 1, ServiceID: material.Service.ServiceID,
				OverlayIP: material.Service.OverlayIP, TCPPort: material.Service.Port,
				InternalCAProfileRef:   material.Service.CertificateProfileRef,
				ServerIdentitySPKIPins: material.Service.SPKIPins, ServiceGeneration: 1}
		}
	}
	if err := application.validate(); err != nil {
		return err
	}
	if err := wire.VerifyConfigQCAuthority(application.BootstrapCatalog.ParentHeadHash,
		application.BootstrapCatalog.BootstrapIngressSet.ConfigQC, state.CertifiedHead, &state.ControlSet, nil); err != nil {
		return errors.New("bootstrap 安装计划未绑定原认证 Head/QC")
	}
	sets := make(map[string]wire.DistributionEndpointSetV1, len(application.DistributionSets))
	for _, set := range application.DistributionSets {
		hash, err := wire.DistributionEndpointSetHash(&set)
		if err != nil {
			return err
		}
		if _, duplicate := sets[hash]; duplicate {
			return errors.New("迁移重复提供相同 distribution preimage")
		}
		if err := wire.VerifyConfigQCAuthority(set.ParentHeadHash, set.ConfigQC,
			state.CertifiedHead, &state.ControlSet, nil); err != nil {
			return errors.New("distribution 安装计划未绑定原认证 Head/QC")
		}
		sets[hash] = set
	}
	if err := wire.ValidateDistributionMirrorBindings(application.ClusterID, application.Mirrors, sets); err != nil {
		return err
	}
	// 不只验公开摘要：必须能回读原来准备的真实 CA/TLS 私钥和 issuer key。
	issuer, err := runtime.loadDeviceIssuer(materials.DeviceProfile)
	if err != nil {
		return err
	}
	clearControlSigner(issuer)
	certificates, err := runtime.loadPrivateServiceCertificates(&application)
	if err != nil {
		return err
	}
	clearPrivateRuntimeCertificates(certificates)
	material, err := openControlSoftwareMaterial(runtime.dir, runtime.config.DeviceID, false)
	if err != nil {
		return err
	}
	policy, err := material.availabilityPolicy(application.ClusterID)
	material.Close()
	if err != nil || !wire.EqualCanonical(policy, materials.ArtifactPolicy) {
		return errors.New("迁移 artifact policy 不属于实际封装材料存储")
	}
	if len(application.BootstrapIssuers) == 0 {
		return errors.New("迁移缺 bootstrap issuer")
	}
	policyHash, _ := wire.InviteIssuancePolicyHash(&application.InvitePolicy)
	for _, authorization := range application.BootstrapIssuers {
		if authorization.Status != "active" || authorization.Active == nil ||
			authorization.ParentHeadHash != state.CertifiedHead.HeadHash ||
			authorization.Active.InviteIssuancePolicyHash != policyHash ||
			!wire.EqualCanonical(authorization.Active.PermittedIngressSetHashes, []string{application.BootstrapCatalog.BootstrapIngressSetHash}) ||
			!wire.EqualCanonical(authorization.Active.PermittedServiceIDs, []string{application.EnrollmentService.ServiceID}) {
			return errors.New("bootstrap issuer 授权必须绑定本次 policy、入口集合和独立 Enrollment 服务")
		}
		key, err := runtime.bootstrapIssuerKey(authorization)
		if err != nil {
			return err
		}
		clear(key)
	}
	input.Application = controlClone(application)
	input.RecoveryProofs = controlClone(prepared.Recovery.Proofs)
	return nil
}
