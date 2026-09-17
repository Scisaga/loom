package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/secret"
	"loom/internal/wire"
)

func (application *controlApplicationV1) prepareDeviceControlLink(input controlClientConfigInputV1, generation int64) (wire.DeviceControlLinkV1, error) {
	var link wire.DeviceControlLinkV1
	tunnel := input.ControlTunnel
	ip, err := netip.ParseAddr(tunnel.PeerAddress)
	if err != nil || !ip.IsPrivate() || tunnel.PeerDeviceID == "" || len(tunnel.Address) != 1 || tunnel.MTU != 1280 {
		return link, errors.New("[设备控制链路] 缺承载 Device、私网地址、唯一客户端主机前缀或规定 MTU")
	}
	public, err := application.deviceControlDialerPublicKey(input)
	if err != nil {
		return link, err
	}
	hash, err := wire.HashObject("loom-device-control-link-id-v1", struct{ Cluster, Device string }{application.ClusterID, input.DeviceID})
	if err != nil {
		return link, err
	}
	id := "device-control-" + strings.TrimPrefix(hash, "sha256:")[:24]
	link.Resource = wire.LinuxWireGuardResourceV1{ResourceID: id, LinkID: id, ListenerDeviceID: tunnel.PeerDeviceID, DialerDeviceID: input.DeviceID,
		ListenerGeneration: generation, EndpointAddress: tunnel.PeerAddress, EndpointPort: int64(tunnel.PeerPort), ListenerPublicKey: tunnel.PeerPublicKey,
		DialerPublicKey: public, ListenerTunnelPrefix: tunnel.PeerTunnelPrefix, DialerTunnelPrefix: tunnel.Address[0]}
	platform, err := application.devicePlatform(input.DeviceID)
	if err != nil {
		return link, err
	}
	if platform == "linux-server" {
		if tunnel.Detour != "" || len(tunnel.AllowedIPs) != 0 {
			return link, errors.New("[设备控制链路] Linux 承载和内层目的必须从认证网络生成")
		}
		source, err := model.Load([]byte(application.LegacySSOT))
		if err != nil {
			return link, err
		}
		server := source.NodeByID()[tunnel.PeerDeviceID]
		if server == nil || server.Server == nil || server.Server.InboundProtocol.Or() != model.Hysteria2 || server.PublicEndpoint == "" {
			return link, errors.New("[设备控制链路] Linux 私有通道缺现有 HY2 承载")
		}
		link.Carrier = &wire.DeviceControlCarrierV1{Address: server.PublicEndpoint, Port: int64(server.Server.InboundPort),
			TLSServerName: server.ID + ".node.internal", CredentialRef: wire.DeviceControlCarrierCredentialRef(link)}
	}
	for _, service := range application.Services {
		if service.Role == "device_config" || service.Role == "device_report" {
			link.Services = append(link.Services, service)
		}
	}
	sort.Slice(link.Services, func(i, j int) bool { return link.Services[i].ServiceID < link.Services[j].ServiceID })
	return link, application.validateDeviceControlLink(link)
}

func (application *controlApplicationV1) deviceControlDialerPublicKey(input controlClientConfigInputV1) (string, error) {
	platform, err := application.devicePlatform(input.DeviceID)
	if err != nil {
		return "", err
	}
	if platform == "linux-server" {
		source, err := model.Load([]byte(application.LegacySSOT))
		if err != nil {
			return "", err
		}
		node := source.NodeByID()[input.DeviceID]
		if input.ControlTunnel.PrivateKeyRef != render.LocalWireGuardSecretIDV2 {
			return "", errors.New("[设备控制链路] Linux 节点必须沿用本机认证 WireGuard 身份")
		}
		if node != nil && node.Server != nil {
			return node.Server.WGPublicKey, nil
		}
		// fresh forward 在 public access preparing 阶段没有 v1 server 块；其
		// 本机 WG 公钥已由 Enrollment claim 和认证控制链路共同固定。
		for _, link := range application.DeviceControlLinks {
			if link.Resource.DialerDeviceID == input.DeviceID {
				return link.Resource.DialerPublicKey, nil
			}
		}
		return "", errors.New("[设备控制链路] Linux 节点缺已认证 WireGuard 身份")
	}
	keyBytes, err := base64.StdEncoding.Strict().DecodeString(input.Credentials[input.ControlTunnel.PrivateKeyRef])
	if err != nil || len(keyBytes) != 32 {
		return "", errors.New("[设备控制链路] 客户端 WireGuard 私钥无效")
	}
	defer clear(keyBytes)
	key, err := ecdh.X25519().NewPrivateKey(keyBytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func (application *controlApplicationV1) validateDeviceControlLink(link wire.DeviceControlLinkV1) error {
	if err := wire.ValidateDeviceControlLink(&link); err != nil {
		return err
	}
	source, err := model.Load([]byte(application.LegacySSOT))
	if err != nil {
		return err
	}
	r := link.Resource
	server := source.NodeByID()[r.ListenerDeviceID]
	if server == nil || server.Server == nil || server.Server.WGPublicKey != r.ListenerPublicKey || int64(server.Server.InboundPort) == r.EndpointPort {
		return errors.New("[设备控制链路] listener 与原服务器公钥或数据端口冲突")
	}
	active := map[string]wire.DeviceActiveViewV1{}
	for _, device := range application.Devices {
		if device.View.State == "active" && device.View.Active != nil {
			active[device.View.DeviceID] = *device.View.Active
		}
	}
	if !containsControlValue(active[r.ListenerDeviceID].Responsibilities.Values, "forward") ||
		!containsControlValue(active[r.DialerDeviceID].Responsibilities.Values, "use_loom") && !(link.Carrier != nil && containsControlValue(active[r.DialerDeviceID].Responsibilities.Values, "forward")) {
		return errors.New("[设备控制链路] 两端没有当前认证的职责")
	}
	if carrier := link.Carrier; carrier != nil {
		dialer := source.NodeByID()[r.DialerDeviceID]
		dialerMismatch := dialer != nil && (dialer.Server != nil && dialer.Server.WGPublicKey != r.DialerPublicKey ||
			dialer.Server == nil && dialer.Access == nil)
		if dialerMismatch || dialer == nil && !containsControlValue(active[r.DialerDeviceID].Responsibilities.Values, "forward") ||
			server.Server.InboundProtocol.Or() != model.Hysteria2 || carrier.Address != server.PublicEndpoint || carrier.Port != int64(server.Server.InboundPort) || carrier.TLSServerName != server.ID+".node.internal" {
			return errors.New("[设备控制链路] 专用承载偏离原网络身份或现有 HY2 listener")
		}
	}
	for _, service := range link.Services {
		found := false
		for _, current := range application.Services {
			found = found || wire.EqualCanonical(current, service)
		}
		if !found {
			return errors.New("[设备控制链路] 私有目的不是当前认证服务")
		}
	}
	tunnels, err := source.ResolveAll()
	if err != nil {
		return err
	}
	for _, tunnel := range tunnels {
		if tunnel.Acceptor.ID == r.ListenerDeviceID && int64(tunnel.ListenPort) == r.EndpointPort {
			return errors.New("[设备控制链路] listener 占用了原 WireGuard 端口")
		}
	}
	return nil
}

func (application *controlApplicationV1) validateDeviceControlLinks() error {
	devices, addresses, keys, tuples := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, link := range application.DeviceControlLinks {
		if err := application.validateDeviceControlLink(link); err != nil {
			return err
		}
		r := link.Resource
		tuple := r.ListenerDeviceID + "/" + strconv.FormatInt(r.EndpointPort, 10)
		if devices[r.DialerDeviceID] || addresses[r.DialerTunnelPrefix] || keys[r.DialerPublicKey] || tuples[tuple] || i > 0 && application.DeviceControlLinks[i-1].Resource.ResourceID >= r.ResourceID {
			return errors.New("[设备控制链路] 设备、地址、公钥、端口或排序冲突")
		}
		devices[r.DialerDeviceID], addresses[r.DialerTunnelPrefix], keys[r.DialerPublicKey], tuples[tuple] = true, true, true, true
	}
	return nil
}

func (application *controlApplicationV1) deviceControlLinksFor(device string) []wire.DeviceControlLinkV1 {
	var result []wire.DeviceControlLinkV1
	for _, link := range application.DeviceControlLinks {
		if link.Resource.ListenerDeviceID == device || link.Resource.DialerDeviceID == device {
			result = append(result, controlClone(link))
		}
	}
	return result
}

func (application *controlApplicationV1) applyDeviceControlPublication(publication controlDevicePublicationV1, platform string) error {
	link := publication.ControlLink
	if link != nil {
		if link.Resource.DialerDeviceID != publication.DeviceID {
			return errors.New("[设备控制链路] 发布不能改动另一设备的分配")
		}
		if err := application.validateDeviceControlLink(*link); err != nil {
			return err
		}
		for _, device := range application.Devices {
			if device.View.DeviceID == publication.DeviceID && link.Resource.ListenerGeneration != device.View.DeviceGeneration+1 {
				return errors.New("[设备控制链路] 分配未绑定本次配置代")
			}
		}
		if platform != "linux-server" {
			if err := validatePublishedClientControlLink(publication, *link); err != nil {
				return err
			}
		} else if link.Carrier == nil {
			return errors.New("[设备控制链路] Linux 发起端缺受限承载")
		}
		if err := application.replaceDeviceControlLink(*link); err != nil {
			return err
		}
	} else if platform != "linux-server" {
		return errors.New("[设备控制链路] 客户端发布缺承载侧分配")
	}
	if platform == "linux-server" {
		for _, config := range publication.Configs {
			if config.Ref.ArtifactID != wire.LinuxLinkIntentArtifactID {
				continue
			}
			var links wire.LinuxLinkIntentArtifactV1
			if err := json.Unmarshal(config.Content, &links); err != nil {
				return err
			}
			var proposed []wire.DeviceControlLinkV1
			if links.LocalRuntime != nil {
				proposed = links.LocalRuntime.DeviceControlLinks
			}
			if !wire.EqualCanonical(proposed, application.deviceControlLinksFor(publication.DeviceID)) {
				return errors.New("[设备控制链路] Linux 两端配置不匹配当前认证分配")
			}
		}
	}
	return nil
}

func (application *controlApplicationV1) replaceDeviceControlLink(link wire.DeviceControlLinkV1) error {
	var next []wire.DeviceControlLinkV1
	for _, old := range application.DeviceControlLinks {
		if old.Resource.DialerDeviceID != link.Resource.DialerDeviceID {
			next = append(next, old)
			continue
		}
		if old.Resource.ResourceID != link.Resource.ResourceID || old.Resource.ListenerGeneration >= link.Resource.ListenerGeneration {
			return errors.New("[设备控制链路] 分配代倒退或资源身份改变")
		}
	}
	next = append(next, link)
	sort.Slice(next, func(i, j int) bool { return next[i].Resource.ResourceID < next[j].Resource.ResourceID })
	application.DeviceControlLinks = next
	return application.validateDeviceControlLinks()
}

func validatePublishedClientControlLink(publication controlDevicePublicationV1, link wire.DeviceControlLinkV1) error {
	var body string
	for _, config := range publication.Configs {
		if config.Ref.Platform == "android" {
			var bundle struct {
				Files map[string]string `json:"files"`
			}
			if err := json.Unmarshal(config.Content, &bundle); err != nil {
				return err
			}
			body = bundle.Files["sing-box/config.json"]
		} else if config.Ref.Platform == "windows-desktop" {
			var artifact wire.WindowsRuntimeArtifactV1
			if err := json.Unmarshal(config.Content, &artifact); err != nil {
				return err
			}
			for _, file := range artifact.Files {
				if file.Path == "sing-box/config.json" {
					body = file.Content
				}
			}
		}
	}
	var config struct {
		Endpoints []struct {
			Type       string   `json:"type"`
			Tag        string   `json:"tag"`
			System     bool     `json:"system"`
			MTU        int      `json:"mtu"`
			Address    []string `json:"address"`
			PrivateKey string   `json:"private_key"`
			Peers      []struct {
				Address    string   `json:"address"`
				Port       int64    `json:"port"`
				PublicKey  string   `json:"public_key"`
				AllowedIPs []string `json:"allowed_ips"`
			} `json:"peers"`
		} `json:"endpoints"`
	}
	if json.Unmarshal([]byte(body), &config) != nil || len(config.Endpoints) != 1 {
		return errors.New("[设备控制链路] 发布缺唯一客户端 WireGuard endpoint")
	}
	ep := config.Endpoints[0]
	r := link.Resource
	if ep.Type != "wireguard" || ep.Tag != "private-control-wg" || ep.System || ep.MTU != 1280 || !wire.EqualCanonical(ep.Address, []string{r.DialerTunnelPrefix}) || len(ep.Peers) != 1 || len(secret.Refs(ep.PrivateKey)) != 1 {
		return errors.New("[设备控制链路] 客户端 endpoint 与承载分配不同")
	}
	peer := ep.Peers[0]
	want := []string{}
	seen := map[string]bool{}
	for _, service := range link.Services {
		ip, _ := netip.ParseAddr(service.OverlayIP)
		prefix := netip.PrefixFrom(ip, ip.BitLen()).String()
		if !seen[prefix] {
			want = append(want, prefix)
			seen[prefix] = true
		}
	}
	sort.Strings(want)
	if peer.Address != r.EndpointAddress || peer.Port != r.EndpointPort || peer.PublicKey != r.ListenerPublicKey || !wire.EqualCanonical(peer.AllowedIPs, want) {
		return errors.New("[设备控制链路] 客户端 peer、目的或公钥与承载分配不同")
	}
	return nil
}
