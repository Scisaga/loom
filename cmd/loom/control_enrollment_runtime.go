package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"loom/internal/enrollmentv2"
	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/ssotedit"
	"loom/internal/wire"
)

// 首份配置与接纳它的服务器配置在同一个 completion 中生效。provisional
// 只预留 exact 结果，不提前给新设备授权，也不在现网 SSOT 上做旁路写入。
type controlEnrollmentRuntimePlanV1 struct {
	Schema         int                                     `json:"schema"`
	InviteID       string                                  `json:"invite_id"`
	OperationID    string                                  `json:"operation_id"`
	Parent         wire.CertifiedHeadV1                    `json:"parent"`
	NetworkHash    string                                  `json:"network_hash"`
	Network        string                                  `json:"network"`
	ControlLink    wire.DeviceControlLinkV1                `json:"control_link"`
	ClientConfigs  []controlPublishedConfigV1              `json:"client_configs"`
	ClientSecrets  []enrollmentv2.SealedMaterialEvidenceV1 `json:"client_secrets"`
	Servers        []controlDevicePublicationV1            `json:"servers"`
	SingBoxVersion string                                  `json:"sing_box_version"`
	PreparedAt     string                                  `json:"prepared_at"`
}

func enrollmentNetwork(application *controlApplicationV1, invite controlInviteStateV1) (ssotedit.ClientPlan, error) {
	intent := invite.Opening.DeviceEnrollmentIntent
	if !wire.EqualCanonical(intent.Responsibilities.Values, []string{"use_loom"}) {
		return ssotedit.ClientPlan{}, errors.New("[首次配置] forward 安装需独立的 listener 准备计划，不能降级为 use_loom")
	}
	source, err := model.Load([]byte(application.LegacySSOT))
	if err != nil {
		return ssotedit.ClientPlan{}, err
	}
	allowed := map[string]bool{}
	for _, grant := range intent.Grants.Values {
		for _, declaration := range source.Declarations {
			if grant.Kind == "egress" && declaration.AddressFromRequest() && (declaration.PinnedEgress() == "" || declaration.PinnedEgress() == grant.TargetID) {
				allowed[declaration.ID] = true
			}
		}
		if grant.Kind == "service" {
			for _, service := range source.Services {
				if service.ID == grant.TargetID {
					allowed[service.Declaration] = true
				}
			}
		}
	}
	declarations := make([]string, 0, len(allowed))
	for id := range allowed {
		declarations = append(declarations, id)
	}
	sort.Strings(declarations)
	if len(declarations) == 0 {
		return ssotedit.ClientPlan{}, errors.New("[首次配置] 邀请授权没有可生成的服务或出口策略")
	}
	return ssotedit.AddAccessClient([]byte(application.LegacySSOT), ssotedit.ClientInput{ID: intent.DeviceID,
		Name: invite.DisplayName, Platform: model.Platform(intent.Platform), DestinationGrants: declarations})
}

func enrollmentInitialView(record enrollmentv2.DurableRecord, configs []controlPublishedConfigV1,
	secrets []wire.SecretArtifactRefV2) (wire.DeviceViewPayloadV2, error) {
	intent := record.ClaimEvidence.Opening.DeviceEnrollmentIntent
	view := wire.DeviceViewPayloadV2{Schema: 2, ClusterID: intent.ClusterID, DeviceID: intent.DeviceID, DeviceGeneration: 1, State: "active",
		Active: &wire.DeviceActiveViewV1{IdentitySPKIHash: record.State.IdentityKeyHash, Membership: intent.Membership,
			Responsibilities: intent.Responsibilities, Grants: intent.Grants}}
	active := view.Active
	active.MembershipHash, _ = wire.HashObject("loom-enrollment-membership-v1", active.Membership)
	active.ResponsibilitiesHash, _ = wire.HashObject("loom-enrollment-responsibilities-v1", active.Responsibilities)
	active.GrantsHash, _ = wire.HashObject("loom-enrollment-destination-grants-v1", active.Grants)
	active.EndpointBundle = wire.DeviceEndpointBundleV1{Schema: 1, ClusterID: intent.ClusterID, DeviceID: intent.DeviceID,
		DeviceGeneration: 1, DataIngressSets: []wire.DeviceDataIngressBindingV1{}}
	active.EndpointBundleHash, _ = wire.DeviceEndpointBundleHash(&active.EndpointBundle)
	var err error
	active.SecretArtifactRefsRoot, err = wire.SecretArtifactRefsRoot(secrets)
	if err != nil {
		return view, err
	}
	for _, config := range configs {
		active.ConfigArtifactRefs = append(active.ConfigArtifactRefs, config.Ref)
	}
	return view, wire.ValidateDeviceViewPayload(&view)
}

func enrollmentConfigViews(application *controlApplicationV1, intent wire.DeviceEnrollmentIntentV1) map[string]wire.DeviceViewPayloadV2 {
	views := make(map[string]wire.DeviceViewPayloadV2, len(application.Devices)+1)
	for _, device := range application.Devices {
		views[device.View.DeviceID] = device.View
	}
	views[intent.DeviceID] = wire.DeviceViewPayloadV2{Schema: 2, ClusterID: intent.ClusterID, DeviceID: intent.DeviceID, DeviceGeneration: 1,
		State: "active", Active: &wire.DeviceActiveViewV1{Membership: intent.Membership, Responsibilities: intent.Responsibilities, Grants: intent.Grants}}
	return views
}

func renderEnrollmentClient(application *controlApplicationV1, invite controlInviteStateV1, plan controlEnrollmentRuntimePlanV1) ([]controlPublishedConfigV1, []string, error) {
	intent := invite.Opening.DeviceEnrollmentIntent
	source, err := model.Load([]byte(plan.Network))
	if err != nil {
		return nil, nil, err
	}
	var runtime render.ClientRuntimeV2
	configs := []controlPublishedConfigV1{}
	if intent.Platform == "linux-server" {
		views := enrollmentConfigViews(application, intent)
		delete(views, intent.DeviceID)
		linux, err := render.RenderInitialLinuxRuntimeV2(render.LinuxRuntimeV2Input{SSOT: source, Views: views, Authority: plan.Parent,
			DeviceID: intent.DeviceID, DeviceGeneration: 1, ArtifactGeneration: 1, DeviceControlLinks: []wire.DeviceControlLinkV1{plan.ControlLink}}, intent)
		if err != nil {
			return nil, nil, err
		}
		runtime = linux.Runtime
		configs = append(configs, controlPublishedConfigV1{Ref: linux.Links.Ref, Content: linux.Links.Content})
	} else {
		r := plan.ControlLink.Resource
		tunnel := render.ClientControlTunnelV2{PeerDeviceID: r.ListenerDeviceID, PeerTunnelPrefix: r.ListenerTunnelPrefix,
			Address: []string{r.DialerTunnelPrefix}, PrivateKeyRef: wire.LocalWireGuardKeySecretID,
			PeerAddress: r.EndpointAddress, PeerPort: int(r.EndpointPort), PeerPublicKey: r.ListenerPublicKey, MTU: 1280}
		for _, service := range plan.ControlLink.Services {
			prefix := service.OverlayIP + "/32"
			if strings.Contains(service.OverlayIP, ":") {
				prefix = service.OverlayIP + "/128"
			}
			if !containsControlValue(tunnel.AllowedIPs, prefix) {
				tunnel.AllowedIPs = append(tunnel.AllowedIPs, prefix)
			}
		}
		sort.Strings(tunnel.AllowedIPs)
		// 控制隧道使用独立、限路由的 HY2 身份，不借用业务目标授权。
		runtime, err = render.RenderClientRuntimeV2(render.ClientRuntimeV2Input{SSOT: source, Grants: &intent.Grants,
			ClusterID: application.ClusterID, DeviceID: intent.DeviceID, DeviceGeneration: 1, ArtifactGeneration: 1,
			SingBoxVersion: plan.SingBoxVersion, ObservationCA: application.ObservationCAPEM, ControlTunnel: tunnel,
			ControlCarrier: plan.ControlLink.Carrier})
		if err != nil {
			return nil, nil, err
		}
	}
	if len(runtime.Skipped) != 0 {
		return nil, nil, errors.New("[首次配置] 路由策略包含未实现的运行项")
	}
	configs = append(configs, controlPublishedConfigV1{Ref: runtime.Ref, Content: runtime.Content})
	sort.Slice(configs, func(i, j int) bool { return configs[i].Ref.ArtifactID < configs[j].Ref.ArtifactID })
	refs := []string{}
	for _, id := range runtime.CredentialRefs {
		if id != wire.LocalWireGuardKeySecretID {
			refs = append(refs, id)
		}
	}
	return configs, refs, nil
}

func renderEnrollmentServer(application *controlApplicationV1, invite controlInviteStateV1, plan controlEnrollmentRuntimePlanV1,
	device controlDeviceStateV1) ([]controlPublishedConfigV1, []string, error) {
	source, err := model.Load([]byte(plan.Network))
	if err != nil {
		return nil, nil, err
	}
	links := append(application.deviceControlLinksFor(device.View.DeviceID), plan.ControlLink)
	if plan.ControlLink.Resource.ListenerDeviceID != device.View.DeviceID {
		links = application.deviceControlLinksFor(device.View.DeviceID)
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Resource.ResourceID < links[j].Resource.ResourceID })
	generation := int64(1)
	for _, ref := range device.View.Active.ConfigArtifactRefs {
		if ref.Generation >= generation {
			generation = ref.Generation + 1
		}
	}
	runtime, err := render.RenderLinuxRuntimeV2(render.LinuxRuntimeV2Input{SSOT: source, Views: enrollmentConfigViews(application, invite.Opening.DeviceEnrollmentIntent),
		Authority: plan.Parent, DeviceID: device.View.DeviceID, DeviceGeneration: device.View.DeviceGeneration + 1, ArtifactGeneration: generation, DeviceControlLinks: links})
	if err != nil {
		return nil, nil, err
	}
	if len(runtime.Runtime.Skipped) != 0 {
		return nil, nil, errors.New("[首次配置] 服务器配置包含未实现的运行项")
	}
	configs := []controlPublishedConfigV1{{Ref: runtime.Links.Ref, Content: runtime.Links.Content}, {Ref: runtime.Runtime.Ref, Content: runtime.Runtime.Content}}
	sort.Slice(configs, func(i, j int) bool { return configs[i].Ref.ArtifactID < configs[j].Ref.ArtifactID })
	return configs, runtime.Runtime.CredentialRefs, nil
}

func decodeEnrollmentRuntimePlan(raw json.RawMessage) (controlEnrollmentRuntimePlanV1, error) {
	var plan controlEnrollmentRuntimePlanV1
	canonical, err := wire.DecodeStrict(raw, 32<<20, &plan)
	if err != nil || !bytes.Equal(canonical, raw) || plan.Schema != 1 {
		return plan, errors.New("[首次配置] 缺规范的运行计划")
	}
	return plan, nil
}

func enrollmentWireGuardPublicValid(encoded string) bool {
	public, err := base64.StdEncoding.Strict().DecodeString(encoded)
	return err == nil && len(public) == 32 && base64.StdEncoding.EncodeToString(public) == encoded
}

func (application *controlApplicationV1) applyEnrollmentRuntimePlan(plan controlEnrollmentRuntimePlanV1, record enrollmentv2.DurableRecord,
	view wire.DeviceViewPayloadV2, at string) (*controlApplicationV1, error) {
	if plan.Schema != 1 || plan.InviteID != record.InviteID || plan.NetworkHash != wire.HashRaw("loom-enrollment-network-v1", []byte(application.LegacySSOT)) ||
		plan.Parent.Head.Body.Payload.ClusterID != application.ClusterID || plan.PreparedAt == "" || at < plan.PreparedAt {
		return nil, errors.New("[首次配置] 运行计划与原网络、事务或认证时间不一致")
	}
	operationID, err := enrollmentv2.ProvisionalOperationID(&record)
	if record.ProvisionalOperation != nil && record.State.Status == "issued_provisional" {
		operationID, err = record.ProvisionalOperation.OperationID, nil
	}
	if err != nil || operationID != plan.OperationID {
		return nil, errors.New("[首次配置] 计划不属于原签发操作")
	}
	var invite controlInviteStateV1
	inviteIndex := -1
	for i, current := range application.Invites {
		if current.Record.InviteID == plan.InviteID {
			invite = current
			inviteIndex = i
		}
	}
	if inviteIndex < 0 || !wire.EqualCanonical(invite.Opening, record.ClaimEvidence.Opening) {
		return nil, errors.New("[首次配置] 邀请 intent 已变化")
	}
	network, err := enrollmentNetwork(application, invite)
	if err != nil {
		return nil, err
	}
	if string(network.Content) != plan.Network || plan.ControlLink.Resource.DialerDeviceID != view.DeviceID || plan.ControlLink.Resource.ListenerGeneration != 1 ||
		!enrollmentWireGuardPublicValid(plan.ControlLink.Resource.DialerPublicKey) || plan.ControlLink.Carrier == nil ||
		plan.ControlLink.Resource.DialerPublicKey != record.ClaimOperation.WireGuardPublicKey {
		return nil, errors.New("[首次配置] 网络变更超出邀请授权或控制链路无效")
	}
	allocation, err := allocateEnrollmentControlLink(application, plan.ControlLink.Resource.ListenerDeviceID, view.DeviceID, plan.ControlLink.Resource.DialerPublicKey)
	if err != nil {
		return nil, err
	}
	if !wire.EqualCanonical(allocation, plan.ControlLink) {
		return nil, errors.New("[首次配置] 控制链路不是本次认证状态的确定性分配")
	}
	configs, ids, err := renderEnrollmentClient(application, invite, plan)
	if err != nil {
		return nil, err
	}
	if !wire.EqualCanonical(configs, plan.ClientConfigs) {
		return nil, errors.New("[首次配置] 首份运行配置未通过同源重算")
	}
	ids = append(ids, wire.DevicePrivateControlCredentialSecretIDV1, wire.DeviceObservationCASecretIDV1)
	if err := validateEnrollmentSecretIDs(plan.ClientSecrets, ids); err != nil {
		return nil, err
	}
	recipient, err := enrollmentRecipient(record)
	if err != nil {
		return nil, err
	}
	refs := make([]wire.SecretArtifactRefV2, len(plan.ClientSecrets))
	preparedAt, err := wire.ParseTimeZ(plan.PreparedAt)
	if err != nil {
		return nil, err
	}
	for i, evidence := range plan.ClientSecrets {
		ref := evidence.Ref
		if ref.Owner.Device == nil || ref.Owner.Device.DeviceID != view.DeviceID || ref.ProposalID != operationID || ref.ClusterID != application.ClusterID ||
			ref.Generation != 1 || ref.SealedBlob == nil || !wire.EqualCanonical(ref.SealedBlob.RecipientKeyVersions, []wire.SealedBlobRecipientKeyRefV1{recipient}) {
			return nil, errors.New("[首次配置] 首份秘密没有绑定设备、操作与 wrapping key")
		}
		approved := false
		for _, policy := range application.ArtifactPolicies {
			approved = approved || wire.EqualCanonical(policy, evidence.Policy)
		}
		if !approved {
			return nil, errors.New("[首次配置] 秘密没有认证的可用性策略")
		}
		if err := wire.VerifySecretArtifactEvidence(&ref, evidence.Proof, &evidence.Policy, evidence.Receipts, preparedAt, 0, ref.SealedBlob.CiphertextDigest); err != nil {
			return nil, err
		}
		refs[i] = ref
	}
	expected, err := enrollmentInitialView(record, configs, refs)
	if err != nil {
		return nil, err
	}
	if !wire.EqualCanonical(expected, view) {
		return nil, errors.New("[首次配置] CA result 与认证运行计划不一致")
	}
	cloned := controlClone(*application)
	next := &cloned
	next.LegacySSOT = plan.Network
	next.Invites[inviteIndex].Status = "consumed"
	for _, device := range next.Devices {
		if device.View.DeviceID == view.DeviceID {
			return nil, errors.New("[首次配置] 不得覆盖原设备")
		}
	}
	next.Devices = append(next.Devices, controlDeviceStateV1{View: view, PreviousViewHash: wire.EmptyHashV1, SecretArtifactRefs: refs, EnrollmentInviteID: record.InviteID})
	sort.Slice(next.Devices, func(i, j int) bool { return next.Devices[i].View.DeviceID < next.Devices[j].View.DeviceID })
	if err := next.replaceDeviceControlLink(plan.ControlLink); err != nil {
		return nil, err
	}
	serverIndex := 0
	for _, device := range application.Devices {
		if device.View.State != "active" || device.View.Active == nil || !containsControlValue(device.View.Active.Responsibilities.Values, "forward") {
			continue
		}
		if serverIndex >= len(plan.Servers) || plan.Servers[serverIndex].DeviceID != device.View.DeviceID {
			return nil, errors.New("[首次配置] 缺服务器接纳配置或次序不一致")
		}
		publication := plan.Servers[serverIndex]
		serverIndex++
		configs, ids, err := renderEnrollmentServer(application, invite, plan, device)
		if err != nil {
			return nil, err
		}
		if !wire.EqualCanonical(configs, publication.Configs) || publication.ControlLink != nil {
			return nil, errors.New("[首次配置] 服务器配置超出同源渲染结果")
		}
		ids = append(ids, wire.DevicePrivateControlCredentialSecretIDV1, wire.DeviceObservationCASecretIDV1)
		if err := validateEnrollmentSecretIDs(publication.Secrets, ids); err != nil {
			return nil, err
		}
		hash, err := controlDevicePublicationHash(publication)
		if err != nil {
			return nil, err
		}
		next, err = next.reduceDevicePublication(publication, wire.ControlOperationBodyV1{ClusterID: application.ClusterID, Kind: controlPublishDeviceKind,
			OperationID: operationID, ParentHeadHash: plan.Parent.Head.HeadHash, PayloadHash: hash}, plan.PreparedAt)
		if err != nil {
			return nil, err
		}
	}
	if serverIndex != len(plan.Servers) {
		return nil, errors.New("[首次配置] 包含未授权的额外服务器变更")
	}
	return next, nil
}

func validateEnrollmentSecretIDs(secrets []enrollmentv2.SealedMaterialEvidenceV1, ids []string) error {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	for _, evidence := range secrets {
		id := evidence.Ref.SecretID
		if !want[id] || id == wire.LocalWireGuardKeySecretID {
			return errors.New("[首次配置] 秘密缺失、重复或包含客户端本地私钥")
		}
		delete(want, id)
	}
	if len(want) != 0 {
		return errors.New("[首次配置] 运行配置所需秘密没有完整交付")
	}
	return nil
}
