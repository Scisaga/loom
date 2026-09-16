package render

import (
	"errors"
	"sort"

	"loom/internal/model"
	"loom/internal/wire"
)

func addLinuxDeviceControlLinks(projection *LinuxWireGuardProjectionV2, source *model.SSOT, input LinuxRuntimeV2Input, cluster string) error {
	if len(input.DeviceControlLinks) == 0 {
		return nil
	}
	node := source.NodeByID()[input.DeviceID]
	if node == nil || node.Server == nil {
		return errors.New("[设备控制链路] 承载设备缺 forward 运行身份")
	}
	used := map[string]bool{}
	ports := map[int64]bool{}
	for _, resource := range projection.Resources {
		used[resource.ResourceID] = true
		if resource.ListenerDeviceID == input.DeviceID {
			ports[resource.EndpointPort] = true
		}
	}
	for i, link := range input.DeviceControlLinks {
		if err := wire.ValidateDeviceControlLink(&link); err != nil {
			return err
		}
		r := link.Resource
		client, found := input.Views[r.DialerDeviceID]
		if r.ListenerDeviceID != input.DeviceID || r.ListenerPublicKey != node.Server.WGPublicKey ||
			!found || client.State != "active" || client.Active == nil || !hasLinuxRole(client.Active.Responsibilities.Values, "use_loom") ||
			used[r.ResourceID] || ports[r.EndpointPort] || int64(node.Server.InboundPort) == r.EndpointPort ||
			i > 0 && input.DeviceControlLinks[i-1].Resource.ResourceID >= r.ResourceID {
			return errors.New("[设备控制链路] 当前身份、原公钥、端口或资源分配冲突")
		}
		used[r.ResourceID], ports[r.EndpointPort] = true, true
		projection.Resources = append(projection.Resources, r)
		projection.LinkIntents = append(projection.LinkIntents, wire.DeviceControlLinkIntent(cluster, r, input.Authority.Head.HeadHash, LocalWireGuardSecretIDV2))
		projection.Bindings = append(projection.Bindings, wire.LinuxRuntimeBindingV1{LinkID: r.LinkID, LinkGeneration: r.ListenerGeneration,
			Mode: "listen", Transport: "wireguard", EndpointID: r.ResourceID, ConfigPath: "sing-box/v2/config.json", RuntimeTag: wire.DeviceControlEndpointTag(link)})
	}
	projection.LocalKey = &wire.LinuxLocalWireGuardKeyV1{SecretID: LocalWireGuardSecretIDV2, PublicKey: node.Server.WGPublicKey}
	sort.Slice(projection.Resources, func(i, j int) bool { return projection.Resources[i].ResourceID < projection.Resources[j].ResourceID })
	sort.Slice(projection.LinkIntents, func(i, j int) bool { return projection.LinkIntents[i].LinkID < projection.LinkIntents[j].LinkID })
	sort.Slice(projection.Bindings, func(i, j int) bool { return projection.Bindings[i].LinkID < projection.Bindings[j].LinkID })
	return nil
}

func addLinuxDeviceControlEndpoints(config *sbConfig, links []wire.DeviceControlLinkV1) error {
	if len(links) == 0 {
		return nil
	}
	if len(config.Endpoints) != 0 {
		return errors.New("[设备控制链路] 不覆盖已有 endpoint")
	}
	for _, outbound := range config.Outbounds {
		if outbound.Tag == wire.DeviceControlDirectTag || outbound.Tag == wire.DeviceControlBlockTag {
			return errors.New("[设备控制链路] 保留出站名称冲突")
		}
	}
	for _, link := range links {
		config.Endpoints = append(config.Endpoints, wire.DeviceControlEndpoint(link, secretRef(LocalWireGuardSecretIDV2)))
	}
	config.Outbounds = append(config.Outbounds, sbOutbound{Type: "direct", Tag: wire.DeviceControlDirectTag}, sbOutbound{Type: "block", Tag: wire.DeviceControlBlockTag})
	var prefix []sbRule
	for _, rule := range wire.DeviceControlRoutes(links) {
		ports := make([]int, len(rule.Port))
		for i, p := range rule.Port {
			ports[i] = int(p)
		}
		prefix = append(prefix, sbRule{Inbound: rule.Inbound, IPCIDR: rule.IPCIDR, Port: ports, Outbound: rule.Outbound})
	}
	config.Route.Rules = append(prefix, config.Route.Rules...)
	return nil
}
