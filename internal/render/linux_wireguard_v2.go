package render

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"loom/internal/model"
	"loom/internal/wire"
)

const LocalWireGuardSecretIDV2 = "local-wireguard-key"

type LinuxWireGuardProjectionV2 struct {
	LinkIntents    []wire.LinkIntentV1
	Resources      []wire.LinuxWireGuardResourceV1
	LocalKey       *wire.LinuxLocalWireGuardKeyV1
	Files          []wire.LinuxRuntimeFileV1
	Bindings       []wire.LinuxRuntimeBindingV1
	InterfaceNames map[string]string
}

// 原网络迁移只在这里解析旧 direction；交付的是逐边固定的 initiator、
// listener tuple、公钥和地址。Linux reader 不再接收节点级 direction。
// WireGuard 私钥继续保存在原节点，不回收至控制面或复制进公开 artifact。
func ProjectExistingLinuxWireGuardV2(source *model.SSOT, clusterID, deviceID, parentHash string) (LinuxWireGuardProjectionV2, error) {
	result := LinuxWireGuardProjectionV2{LinkIntents: []wire.LinkIntentV1{}, Resources: []wire.LinuxWireGuardResourceV1{},
		Files: []wire.LinuxRuntimeFileV1{}, Bindings: []wire.LinuxRuntimeBindingV1{}, InterfaceNames: map[string]string{}}
	if source == nil || clusterID == "" {
		return result, errors.New("[Linux 迁移] 缺原网络或 cluster")
	}
	if _, err := wire.ParseHash(parentHash); err != nil {
		return result, err
	}
	node := source.NodeByID()[deviceID]
	if node == nil || node.Server == nil || node.Decommission || node.Paused {
		return result, errors.New("[Linux 迁移] 本机不是原活动服务器")
	}
	tunnels, err := source.ResolveAll()
	if err != nil {
		return result, err
	}
	usedInterfaces := make(map[string]bool)
	for _, tunnel := range tunnels {
		if tunnel.Initiator.ID != deviceID && tunnel.Acceptor.ID != deviceID || tunnel.Initiator.Decommission || tunnel.Acceptor.Decommission {
			continue
		}
		if tunnel.Protocol != model.WG || tunnel.Obfuscation != "" {
			return result, errors.New("[Linux 迁移] 当前只可投影标准 WireGuard，不能静默改变其他协议")
		}
		pair := []string{tunnel.Initiator.ID, tunnel.Acceptor.ID}
		sort.Strings(pair)
		digest, err := wire.HashObject("loom-wireguard-link-id-v2", struct {
			ClusterID string   `json:"cluster_id"`
			Devices   []string `json:"devices"`
		}{clusterID, pair})
		if err != nil {
			return result, err
		}
		suffix := strings.TrimPrefix(digest, "sha256:")
		linkID, resourceID := "wg-"+suffix[:24], "wg-listener-"+suffix[:24]
		resource := wire.LinuxWireGuardResourceV1{ResourceID: resourceID, LinkID: linkID, ListenerDeviceID: tunnel.Acceptor.ID,
			DialerDeviceID: tunnel.Initiator.ID, ListenerGeneration: 1, EndpointAddress: tunnel.Acceptor.PublicEndpoint,
			EndpointPort: int64(tunnel.ListenPort), ListenerPublicKey: tunnel.Acceptor.Server.WGPublicKey, DialerPublicKey: tunnel.Initiator.Server.WGPublicKey,
			ListenerTunnelPrefix: tunnel.AcceptorAddr, DialerTunnelPrefix: tunnel.InitiatorAddr}
		intent := wire.LinkIntentV1{Schema: 1, ClusterID: clusterID, LinkID: linkID, FromDeviceID: tunnel.Initiator.ID,
			To: wire.LinkIntentDestinationV1{DeviceID: tunnel.Acceptor.ID}, Purpose: "data_forward", Initiator: "from",
			AllowedTransports: []string{"wireguard"}, ListenerResourceRefs: []string{resourceID}, CredentialRefs: []string{LocalWireGuardSecretIDV2},
			RouteScope: "server-mesh", Generation: 1, ParentHeadHash: parentHash}
		peerID := tunnel.Initiator.ID
		mode, generation := "listen", int64(0)
		if deviceID == tunnel.Initiator.ID {
			peerID, mode, generation = tunnel.Acceptor.ID, "dial", 1
		}
		// 迁移认证与业务协议无关；保留接口身份，原流量签名和历史索引才能接续。
		iface := model.IfaceName(peerID)
		if len(iface) > 15 || usedInterfaces[iface] {
			return result, errors.New("[Linux 迁移] 原网络接口名越界或重复")
		}
		usedInterfaces[iface] = true
		result.InterfaceNames[model.IfaceName(peerID)] = iface
		file := wire.LinuxRuntimeFileV1{Path: "wireguard/" + iface + ".conf", Content: renderLinuxPeerWireGuardV2(deviceID, resource, LocalWireGuardSecretIDV2)}
		result.Files = append(result.Files, file)
		result.LinkIntents = append(result.LinkIntents, intent)
		result.Resources = append(result.Resources, resource)
		result.Bindings = append(result.Bindings, wire.LinuxRuntimeBindingV1{LinkID: linkID, LinkGeneration: 1, Mode: mode, Transport: "wireguard",
			EndpointID: resourceID, ListenerGeneration: generation, ConfigPath: file.Path})
	}
	if len(result.Resources) > 0 {
		result.LocalKey = &wire.LinuxLocalWireGuardKeyV1{SecretID: LocalWireGuardSecretIDV2, PublicKey: node.Server.WGPublicKey}
	}
	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].Path < result.Files[j].Path })
	sort.Slice(result.Bindings, func(i, j int) bool { return result.Bindings[i].LinkID < result.Bindings[j].LinkID })
	sort.Slice(result.LinkIntents, func(i, j int) bool { return result.LinkIntents[i].LinkID < result.LinkIntents[j].LinkID })
	sort.Slice(result.Resources, func(i, j int) bool { return result.Resources[i].ResourceID < result.Resources[j].ResourceID })
	for _, intent := range result.LinkIntents {
		if err := wire.ValidateLinkIntent(&intent); err != nil {
			return result, err
		}
	}
	if err := wire.ValidateLinuxWireGuardResources(&wire.LinuxLinkIntentArtifactV1{DeviceID: deviceID, LinkIntents: result.LinkIntents,
		WireGuardResources: result.Resources, LocalWireGuardKey: result.LocalKey}); err != nil {
		return result, err
	}
	return result, nil
}

func renderLinuxPeerWireGuardV2(device string, resource wire.LinuxWireGuardResourceV1, keyRef string) string {
	var out strings.Builder
	out.WriteString("# 由认证 LinkIntent 生成；私钥由原节点本地材料填充。\n[Interface]\n")
	address, peer, allowed := resource.ListenerTunnelPrefix, resource.DialerPublicKey, resource.DialerTunnelPrefix
	dial := device == resource.DialerDeviceID
	if dial {
		address, peer, allowed = resource.DialerTunnelPrefix, resource.ListenerPublicKey, resource.ListenerTunnelPrefix
	}
	fmt.Fprintf(&out, "Address = %s\nPrivateKey = %s\n", address, secretRef(keyRef))
	if !dial {
		fmt.Fprintf(&out, "ListenPort = %d\n", resource.EndpointPort)
	}
	fmt.Fprintf(&out, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", peer, allowed)
	if dial {
		fmt.Fprintf(&out, "Endpoint = %s\nPersistentKeepalive = 25\n", net.JoinHostPort(resource.EndpointAddress, strconv.FormatInt(resource.EndpointPort, 10)))
	}
	return out.String()
}
