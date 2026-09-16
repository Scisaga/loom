package render

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"loom/internal/agent"
	"loom/internal/model"
	"loom/internal/secret"
	"loom/internal/wire"
)

type LinuxRuntimeV2Input struct {
	SSOT               *model.SSOT
	Views              map[string]wire.DeviceViewPayloadV2
	Authority          wire.CertifiedHeadV1
	DeviceID           string
	DeviceGeneration   int64
	ArtifactGeneration int64
	DeviceControlLinks []wire.DeviceControlLinkV1
}

type LinuxRuntimeV2 struct {
	Links   ClientRuntimeV2
	Runtime ClientRuntimeV2
}

// 配置与 LinkIntent 从同一个 certified application 生成。旧网络声明只提供
// 拓扑和路由策略；当前职责、撤权与 destination grants 来自 Device view。
func RenderLinuxRuntimeV2(input LinuxRuntimeV2Input) (LinuxRuntimeV2, error) {
	var result LinuxRuntimeV2
	view, found := input.Views[input.DeviceID]
	if input.SSOT == nil || !found || view.State != "active" || view.Active == nil ||
		input.DeviceGeneration <= view.DeviceGeneration || input.ArtifactGeneration < 1 ||
		view.ClusterID != input.Authority.Head.Body.Payload.ClusterID {
		return result, errors.New("[Linux 配置] 缺当前认证 Device、authority 或新配置代")
	}
	// 深拷贝后投影权限，渲染不得修改调用方的认证状态。
	raw, err := json.Marshal(input.SSOT)
	if err != nil {
		return result, err
	}
	var source model.SSOT
	if err := json.Unmarshal(raw, &source); err != nil {
		return result, err
	}
	scopes := map[string]*clientAccessScope{}
	for i := range source.Nodes {
		node := &source.Nodes[i]
		current, found := input.Views[node.ID]
		if !found || current.ClusterID != view.ClusterID || current.State != "active" || current.Active == nil {
			node.Decommission, node.Paused = true, true
			continue
		}
		roles := current.Active.Responsibilities.Values
		if !hasLinuxRole(roles, "use_loom") {
			node.Access = nil
		}
		if !hasLinuxRole(roles, "forward") {
			node.Server = nil
		}
		if node.Server != nil {
			node.Server.EgressCapable = hasLinuxRole(roles, "internet_egress")
		}
		if node.Access != nil {
			scope, err := newClientAccessScope(&source, &current.Active.Grants)
			if err != nil {
				return result, err
			}
			scopes[node.ID] = scope
		}
	}
	nodes := source.NodeByID()
	tunnels := source.Tunnels[:0]
	for _, tunnel := range source.Tunnels {
		from, to := nodes[tunnel.From], nodes[tunnel.To]
		if from != nil && to != nil && !from.Decommission && !to.Decommission && from.Server != nil && to.Server != nil {
			tunnels = append(tunnels, tunnel)
		}
	}
	source.Tunnels = tunnels
	node := nodes[input.DeviceID]
	if node == nil || node.Decommission || node.Paused || node.Access != nil && node.Access.Platform != model.LinuxServer {
		return result, errors.New("[Linux 配置] 当前设备不是活动 Linux 节点")
	}
	wg := LinuxWireGuardProjectionV2{Files: []wire.LinuxRuntimeFileV1{}, Bindings: []wire.LinuxRuntimeBindingV1{},
		LinkIntents: []wire.LinkIntentV1{}, InterfaceNames: map[string]string{}}
	if node.Server != nil {
		wg, err = ProjectExistingLinuxWireGuardV2(&source, view.ClusterID, input.DeviceID, input.Authority.Head.HeadHash)
		if err != nil {
			return result, err
		}
	}
	if err := addLinuxDeviceControlLinks(&wg, &source, input, view.ClusterID); err != nil {
		return result, err
	}
	links := wire.LinuxLinkIntentArtifactV1{Schema: 1, ClusterID: view.ClusterID, DeviceID: input.DeviceID,
		DeviceGeneration: input.DeviceGeneration, Generation: input.ArtifactGeneration, RenderContractID: wire.LinuxLinkIntentRenderContract,
		AuthorityHeadHash: input.Authority.Head.HeadHash, Authority: input.Authority, LinkIntents: wg.LinkIntents,
		WireGuardResources: wg.Resources, LocalWireGuardKey: wg.LocalKey,
		LocalRuntime: &wire.LinuxLocalRuntimeV1{AccessMode: "none", CredentialRefs: []string{}, Listeners: []wire.LinuxLocalListenerV1{}}}
	links.LocalRuntime.DeviceControlLinks = input.DeviceControlLinks
	file, skips, err := renderSingBoxWithScopes(&source, node, scopes[input.DeviceID], scopes)
	if err != nil {
		return result, err
	}
	result.Runtime.Skipped = append(result.Runtime.Skipped, skips...)
	var config sbConfig
	if err := json.Unmarshal([]byte(file.Content), &config); err != nil {
		return result, err
	}
	if err := addLinuxDeviceControlEndpoints(&config, input.DeviceControlLinks); err != nil {
		return result, err
	}
	for _, inbound := range config.Inbounds {
		if inbound.Type == "tun" {
			links.LocalRuntime.AccessMode = "tun"
		}
		if inbound.Type == "mixed" && !strings.HasPrefix(inbound.Tag, "hy2-link-") && inbound.Tag != "probe-in" {
			if links.LocalRuntime.AccessMode == "tun" {
				links.LocalRuntime.AccessMode = "mixed_tun"
			} else {
				links.LocalRuntime.AccessMode = "mixed"
			}
		}
		if inbound.Type == "hysteria2" || inbound.Type == "trojan" {
			links.LocalRuntime.Listeners = append(links.LocalRuntime.Listeners, wire.LinuxLocalListenerV1{
				Tag: inbound.Tag, Transport: linuxTransportName(inbound.Type), Address: inbound.Listen, Port: int64(inbound.ListenPort)})
		}
	}
	bindings := wg.Bindings
	resourceIndex := map[string]int{}
	for i := range config.Outbounds {
		outbound := &config.Outbounds[i]
		if outbound.BindInterface != "" {
			name, found := wg.InterfaceNames[outbound.BindInterface]
			if !found {
				return result, errors.New("[Linux 配置] 数据出站引用缺失的原 WireGuard 边")
			}
			outbound.BindInterface = name
		}
		if outbound.Type != "hysteria2" && outbound.Type != "trojan" {
			continue
		}
		var peer *model.Node
		for j := range source.Nodes {
			candidate := &source.Nodes[j]
			if candidate.Server != nil && !candidate.Decommission && outbound.TLS != nil && outbound.TLS.ServerName == serverName(candidate) {
				peer = candidate
			}
		}
		if peer == nil || peer.ID == input.DeviceID || outbound.ServerPort != peer.Server.InboundPort || outbound.TLS.CertificatePath != tlsCAPath {
			return result, errors.New("[Linux 配置] 传输出站没有 exact 原节点身份、端口与 CA")
		}
		resource := wire.LinuxPeerTransportV1{ListenerDeviceID: peer.ID, ListenerGeneration: input.ArtifactGeneration,
			Transport: linuxTransportName(outbound.Type), Address: outbound.Server, Port: int64(outbound.ServerPort), TLSServerName: outbound.TLS.ServerName}
		// 地址可能是第一跳公网 tuple，也可能是 detour 后的对端隧道地址；
		// 只认证 renderer 已从同源策略算出的实际目的，不由节点自报。
		hash, err := wire.HashObject("loom-linux-peer-transport-id-v1", struct {
			From, To, Address, Transport string
			Port                         int64
		}{
			input.DeviceID, peer.ID, resource.Address, resource.Transport, resource.Port})
		if err != nil {
			return result, err
		}
		resource.ResourceID = "peer-" + strings.TrimPrefix(hash, "sha256:")[:24]
		resource.LinkID = resource.ResourceID
		refs := secret.Refs(outbound.Password)
		if len(refs) != 1 {
			return result, errors.New("[Linux 配置] 传输凭据不是唯一 secret ref")
		}
		index, found := resourceIndex[resource.ResourceID]
		if !found {
			index = len(links.LinkIntents)
			resourceIndex[resource.ResourceID] = index
			links.PeerTransports = append(links.PeerTransports, resource)
			links.LinkIntents = append(links.LinkIntents, wire.LinkIntentV1{Schema: 1, ClusterID: view.ClusterID, LinkID: resource.LinkID,
				FromDeviceID: input.DeviceID, To: wire.LinkIntentDestinationV1{DeviceID: peer.ID}, Purpose: "data_forward", Initiator: "from",
				AllowedTransports: []string{resource.Transport}, ListenerResourceRefs: []string{resource.ResourceID}, CredentialRefs: []string{},
				RouteScope: "device-data", Generation: input.ArtifactGeneration, ParentHeadHash: links.AuthorityHeadHash})
		}
		intent := &links.LinkIntents[index]
		if !hasLinuxRole(intent.CredentialRefs, refs[0]) {
			intent.CredentialRefs = append(intent.CredentialRefs, refs[0])
			sort.Strings(intent.CredentialRefs)
		}
		bindings = append(bindings, wire.LinuxRuntimeBindingV1{LinkID: resource.LinkID, LinkGeneration: input.ArtifactGeneration,
			Mode: "dial", Transport: resource.Transport, EndpointID: resource.ResourceID, ListenerGeneration: resource.ListenerGeneration,
			ConfigPath: "sing-box/v2/config.json", RuntimeTag: outbound.Tag})
	}
	runtime := wire.LinuxRuntimeArtifactV1{Schema: 1, ClusterID: view.ClusterID, DeviceID: input.DeviceID,
		DeviceGeneration: input.DeviceGeneration, Generation: input.ArtifactGeneration, LinkIntentGeneration: links.Generation,
		Bindings: bindings, Files: wg.Files}
	encoded, err := json.Marshal(config)
	if err != nil {
		return result, err
	}
	canonical, err := wire.NormalizeRuntimeJSON(encoded)
	if err != nil {
		return result, err
	}
	runtime.Files = append(runtime.Files, wire.LinuxRuntimeFileV1{Path: "sing-box/v2/config.json", Content: string(canonical)})
	if node.Access != nil {
		agentFiles, skips := renderAgentPlanScoped(&source, node, scopes[node.ID])
		result.Runtime.Skipped = append(result.Runtime.Skipped, skips...)
		if len(agentFiles) != 1 {
			return result, errors.New("[Linux 配置] use_loom 缺可运行 Agent 计划")
		}
		var plan agent.Config
		if err := json.Unmarshal([]byte(agentFiles[0].Content), &plan); err != nil {
			return result, err
		}
		plan.Peers, plan.SelfReport, plan.PeerPeriod = nil, "", ""
		encoded, err := json.Marshal(plan)
		if err != nil {
			return result, err
		}
		canonical, err := wire.NormalizeRuntimeJSON(encoded)
		if err != nil {
			return result, err
		}
		runtime.Files = append(runtime.Files, wire.LinuxRuntimeFileV1{Path: "agent/v2/config.json", Content: string(canonical)})
	}
	allRefs, linkedRefs := map[string]bool{}, map[string]bool{}
	for _, intent := range links.LinkIntents {
		for _, ref := range intent.CredentialRefs {
			linkedRefs[ref] = true
		}
	}
	for _, file := range runtime.Files {
		for _, ref := range secret.Refs(file.Content) {
			allRefs[ref] = true
		}
	}
	for ref := range allRefs {
		if !linkedRefs[ref] {
			links.LocalRuntime.CredentialRefs = append(links.LocalRuntime.CredentialRefs, ref)
		}
		if links.LocalWireGuardKey == nil || ref != links.LocalWireGuardKey.SecretID {
			result.Runtime.CredentialRefs = append(result.Runtime.CredentialRefs, ref)
		}
	}
	sort.Strings(links.LocalRuntime.CredentialRefs)
	sort.Strings(result.Runtime.CredentialRefs)
	sort.Slice(links.LocalRuntime.Listeners, func(i, j int) bool { return links.LocalRuntime.Listeners[i].Tag < links.LocalRuntime.Listeners[j].Tag })
	sort.Slice(links.LinkIntents, func(i, j int) bool { return links.LinkIntents[i].LinkID < links.LinkIntents[j].LinkID })
	sort.Slice(links.PeerTransports, func(i, j int) bool { return links.PeerTransports[i].ResourceID < links.PeerTransports[j].ResourceID })
	sort.Slice(runtime.Files, func(i, j int) bool { return runtime.Files[i].Path < runtime.Files[j].Path })
	sort.Slice(runtime.Bindings, func(i, j int) bool {
		a, b := runtime.Bindings[i], runtime.Bindings[j]
		if a.LinkID != b.LinkID {
			return a.LinkID < b.LinkID
		}
		return a.RuntimeTag < b.RuntimeTag
	})
	if err := wire.ValidateLinuxLinkIntentArtifact(&links); err != nil {
		return result, err
	}
	result.Links, err = linuxConfigArtifact(links, wire.LinuxLinkIntentArtifactID, wire.LinuxLinkIntentRenderContract, input.ArtifactGeneration)
	if err != nil {
		return result, err
	}
	runtime.LinkIntentContentHash = result.Links.Ref.ContentHash
	if err := wire.ValidateLinuxRuntimeRedaction(&runtime, &links); err != nil {
		return result, err
	}
	artifact, err := linuxConfigArtifact(runtime, wire.LinuxRuntimeArtifactID, wire.LinuxRuntimeRenderContract, input.ArtifactGeneration)
	if err != nil {
		return result, err
	}
	artifact.CredentialRefs, artifact.Skipped = result.Runtime.CredentialRefs, result.Runtime.Skipped
	result.Runtime = artifact
	return result, nil
}

func linuxConfigArtifact(value any, id, contract string, generation int64) (ClientRuntimeV2, error) {
	result := ClientRuntimeV2{Ref: wire.DeviceConfigArtifactRefV1{ArtifactID: id, Generation: generation, Platform: "linux-server",
		MediaType: "application/vnd.loom.config+json", RenderContractID: contract}}
	var err error
	result.Content, err = wire.MarshalCanonical(value)
	if err != nil {
		return result, err
	}
	result.Ref.SizeBytes = int64(len(result.Content))
	result.Ref.ContentHash, err = wire.DeviceConfigArtifactContentHash(result.Content)
	if err != nil {
		return result, err
	}
	return result, wire.ValidateDeviceConfigArtifactRef(&result.Ref)
}

func hasLinuxRole(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func linuxTransportName(value string) string {
	if value == "trojan" {
		return "trojan_tls"
	}
	return value
}
