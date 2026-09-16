package render

import (
	"encoding/json"
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
	if node == nil {
		return errors.New("[设备控制链路] 缺本机运行身份")
	}
	localPublic := ""
	if node.Server != nil {
		localPublic = node.Server.WGPublicKey
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
		dial := r.DialerDeviceID == input.DeviceID
		public := r.ListenerPublicKey
		if dial {
			public = r.DialerPublicKey
		}
		if !dial && (r.ListenerDeviceID != input.DeviceID || node.Server == nil) || localPublic != "" && public != localPublic ||
			!found || client.State != "active" || client.Active == nil ||
			!hasLinuxRole(client.Active.Responsibilities.Values, "use_loom") && !(link.Carrier != nil && hasLinuxRole(client.Active.Responsibilities.Values, "forward")) ||
			used[r.ResourceID] || !dial && (ports[r.EndpointPort] || node.Server != nil && int64(node.Server.InboundPort) == r.EndpointPort) || dial && link.Carrier == nil ||
			i > 0 && input.DeviceControlLinks[i-1].Resource.ResourceID >= r.ResourceID {
			return errors.New("[设备控制链路] 当前身份、原公钥、端口或资源分配冲突")
		}
		localPublic = public
		used[r.ResourceID] = true
		if !dial {
			ports[r.EndpointPort] = true
		}
		projection.Resources = append(projection.Resources, r)
		projection.LinkIntents = append(projection.LinkIntents, wire.DeviceControlLinkIntent(cluster, r, input.Authority.Head.HeadHash, LocalWireGuardSecretIDV2))
		mode, generation := "listen", int64(0)
		if dial {
			mode, generation = "dial", r.ListenerGeneration
		}
		projection.Bindings = append(projection.Bindings, wire.LinuxRuntimeBindingV1{LinkID: r.LinkID, LinkGeneration: r.ListenerGeneration,
			Mode: mode, ListenerGeneration: generation, Transport: "wireguard", EndpointID: r.ResourceID, ConfigPath: "sing-box/v2/config.json", RuntimeTag: wire.DeviceControlEndpointTag(link)})
	}
	projection.LocalKey = &wire.LinuxLocalWireGuardKeyV1{SecretID: LocalWireGuardSecretIDV2, PublicKey: localPublic}
	sort.Slice(projection.Resources, func(i, j int) bool { return projection.Resources[i].ResourceID < projection.Resources[j].ResourceID })
	sort.Slice(projection.LinkIntents, func(i, j int) bool { return projection.LinkIntents[i].LinkID < projection.LinkIntents[j].LinkID })
	sort.Slice(projection.Bindings, func(i, j int) bool { return projection.Bindings[i].LinkID < projection.Bindings[j].LinkID })
	return nil
}

func addLinuxDeviceControlEndpoints(config *sbConfig, links []wire.DeviceControlLinkV1, device string) error {
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
		config.Endpoints = append(config.Endpoints, wire.DeviceControlEndpointForDevice(link, device, secretRef(LocalWireGuardSecretIDV2)))
		if carrier := link.Carrier; carrier != nil {
			if link.Resource.DialerDeviceID == device {
				for _, inbound := range config.Inbounds {
					if inbound.Tag == wire.DeviceControlLocalTag || inbound.ListenPort == wire.DeviceControlLocalPort {
						return errors.New("[设备控制链路] 本机代理名称或端口冲突")
					}
				}
				config.Inbounds = append(config.Inbounds, sbInbound{Type: "mixed", Tag: wire.DeviceControlLocalTag,
					Listen: "127.0.0.1", ListenPort: wire.DeviceControlLocalPort,
					Users: []sbMixedUser{{Username: link.Resource.ResourceID, Password: secretRef(carrier.CredentialRef)}}})
				config.Outbounds = append(config.Outbounds, sbOutbound{Type: "hysteria2", Tag: wire.DeviceControlCarrierTag(link),
					Server: carrier.Address, ServerPort: int(carrier.Port), Password: secretRef(carrier.CredentialRef), TLS: clientTLS(carrier.TLSServerName, tlsCAPath)})
			} else {
				found := false
				for i := range config.Inbounds {
					inbound := &config.Inbounds[i]
					if inbound.Tag != "in" {
						continue
					}
					if inbound.Type != "hysteria2" || int64(inbound.ListenPort) != carrier.Port {
						return errors.New("[设备控制链路] 认证承载与现有 HY2 listener 不同")
					}
					// 解码后的 Users 为 JSON array；使用同一类型重建后追加专用身份。
					var users []sbUser
					raw, err := json.Marshal(inbound.Users)
					if err != nil || json.Unmarshal(raw, &users) != nil {
						return errors.New("[设备控制链路] HY2 用户列表无效")
					}
					for _, user := range users {
						if user.Name == link.Resource.ResourceID {
							return errors.New("[设备控制链路] HY2 专用身份重复")
						}
					}
					inbound.Users = append(users, sbUser{Name: link.Resource.ResourceID, Password: secretRef(carrier.CredentialRef)})
					found = true
				}
				if !found {
					return errors.New("[设备控制链路] 缺现有 HY2 承载 listener")
				}
			}
		}
	}
	config.Outbounds = append(config.Outbounds, sbOutbound{Type: "direct", Tag: wire.DeviceControlDirectTag}, sbOutbound{Type: "block", Tag: wire.DeviceControlBlockTag})
	var prefix []sbRule
	for _, rule := range wire.DeviceControlRoutesForDevice(links, device) {
		ports := make([]int, len(rule.Port))
		for i, p := range rule.Port {
			ports[i] = int(p)
		}
		prefix = append(prefix, sbRule{Inbound: rule.Inbound, AuthUser: rule.AuthUser, IPCIDR: rule.IPCIDR, Port: ports, Outbound: rule.Outbound})
	}
	config.Route.Rules = append(prefix, config.Route.Rules...)
	return nil
}
