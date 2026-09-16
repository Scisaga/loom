package render

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"

	"loom/internal/model"
	"loom/internal/secret"
	"loom/internal/wire"
)

// ClientControlTunnelV2 由认证的设备分配与服务目录生成；只含公开参数和
// secret 引用。它不是客户端自报地址，也不会增加入口探测。
type ClientControlTunnelV2 struct {
	PeerDeviceID     string   `json:"peer_device_id,omitempty"`
	PeerTunnelPrefix string   `json:"peer_tunnel_prefix,omitempty"`
	Address          []string `json:"address"`
	PrivateKeyRef    string   `json:"private_key_ref"`
	PeerAddress      string   `json:"peer_address"`
	PeerPort         int      `json:"peer_port"`
	PeerPublicKey    string   `json:"peer_public_key"`
	AllowedIPs       []string `json:"allowed_ips"`
	Detour           string   `json:"detour,omitempty"`
	MTU              int      `json:"mtu"`
}

type ClientRuntimeV2Input struct {
	SSOT               *model.SSOT
	Grants             *wire.EnrollmentDestinationGrantsV1
	ClusterID          string
	DeviceID           string
	DeviceGeneration   int64
	ArtifactGeneration int64
	SingBoxVersion     string
	ObservationCA      string
	ControlTunnel      ClientControlTunnelV2
}

type ClientRuntimeV2 struct {
	Ref            wire.DeviceConfigArtifactRefV1
	Content        json.RawMessage
	CredentialRefs []string
	Skipped        []Skip
}

// RenderClientRuntimeV2 沿用同一数据面和选路模型，直接生成客户端消费的
// v2 artifact；旧 report/pull、systemd 与公开 Enrollment 不参与生成。
func RenderClientRuntimeV2(input ClientRuntimeV2Input) (ClientRuntimeV2, error) {
	var result ClientRuntimeV2
	if input.SSOT == nil || input.ClusterID == "" || input.DeviceGeneration < 1 || input.ArtifactGeneration < 1 {
		return result, errors.New("[v2 客户端配置] 缺认证网络、设备或配置代")
	}
	node := input.SSOT.NodeByID()[input.DeviceID]
	if node == nil || !node.IsAccess() || node.Decommission || node.Server != nil ||
		(node.Access.Platform != model.Android && node.Access.Platform != model.WindowsDesktop) {
		return result, errors.New("[v2 客户端配置] 要求有效的 Android/Windows use_loom 设备")
	}
	scope, err := newClientAccessScope(input.SSOT, input.Grants)
	if err != nil {
		return result, err
	}
	singbox, skips, err := renderSingBoxScoped(input.SSOT, node, scope)
	if err != nil {
		return result, err
	}
	agentFiles, agentSkips := renderAgentPlanScoped(input.SSOT, node, scope)
	if len(agentFiles) != 1 || agentFiles[0].Path != "agent/config.json" {
		return result, errors.New("[v2 客户端配置] 缺同源的客户端选路计划")
	}
	result.Skipped = append(skips, agentSkips...)
	sort.Slice(result.Skipped, func(i, j int) bool { return result.Skipped[i].Where < result.Skipped[j].Where })
	singbox.Content, err = addClientControlTunnel(singbox.Content, input.ControlTunnel)
	if err != nil {
		return result, err
	}
	files := []File{agentFiles[0], singbox}
	references := map[string]bool{}
	for i := range files {
		canonical, err := wire.NormalizeRuntimeJSON([]byte(files[i].Content))
		if err != nil {
			return result, err
		}
		files[i].Content = string(canonical)
		if err := wire.ValidatePublicRuntimeJSON(canonical); err != nil {
			return result, err
		}
		for _, ref := range secret.Refs(files[i].Content) {
			references[ref] = true
		}
	}
	result.CredentialRefs = make([]string, 0, len(references))
	for ref := range references {
		result.CredentialRefs = append(result.CredentialRefs, ref)
	}
	sort.Strings(result.CredentialRefs)
	result.Ref = wire.DeviceConfigArtifactRefV1{Generation: input.ArtifactGeneration,
		Platform: string(node.Access.Platform), MediaType: "application/vnd.loom.config+json"}
	if node.Access.Platform == model.Android {
		result.Ref.ArtifactID, result.Ref.RenderContractID = "android-runtime", "android-runtime-v1"
		result.Content, err = wire.MarshalCanonical(struct {
			Owner string            `json:"owner"`
			Files map[string]string `json:"files"`
		}{input.DeviceID, map[string]string{files[0].Path: files[0].Content, files[1].Path: files[1].Content}})
	} else {
		result.Ref.ArtifactID, result.Ref.RenderContractID = wire.WindowsRuntimeArtifactID, wire.WindowsRuntimeRenderContract
		artifact := wire.WindowsRuntimeArtifactV1{Schema: 1, ClusterID: input.ClusterID, DeviceID: input.DeviceID,
			DeviceGeneration: input.DeviceGeneration, Generation: input.ArtifactGeneration, SingBoxVersion: input.SingBoxVersion,
			CABundlePEM: input.ObservationCA, CredentialRefs: result.CredentialRefs,
			Files: []wire.WindowsRuntimeFileV1{{Path: files[0].Path, Content: files[0].Content}, {Path: files[1].Path, Content: files[1].Content}}}
		if err := wire.ValidateWindowsRuntimeArtifact(&artifact); err != nil {
			return result, err
		}
		result.Content, err = wire.MarshalCanonical(artifact)
	}
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

func addClientControlTunnel(content string, tunnel ClientControlTunnelV2) (string, error) {
	const tag = "private-control-wg"
	key, err := base64.StdEncoding.DecodeString(tunnel.PeerPublicKey)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != tunnel.PeerPublicKey ||
		tunnel.PrivateKeyRef == "" || tunnel.PeerAddress == "" || strings.TrimSpace(tunnel.PeerAddress) != tunnel.PeerAddress ||
		tunnel.PeerPort < 1 || tunnel.PeerPort > 65535 || tunnel.MTU < 576 || tunnel.MTU > 9000 ||
		len(tunnel.Address) == 0 || len(tunnel.Address) > 8 || len(tunnel.AllowedIPs) == 0 || len(tunnel.AllowedIPs) > 32 ||
		len(secret.Refs(secretRef(tunnel.PrivateKeyRef))) != 1 {
		return "", errors.New("[v2 客户端配置] 私有控制 WireGuard 参数或 secret 引用无效")
	}
	for _, list := range [][]string{tunnel.Address, tunnel.AllowedIPs} {
		for i, raw := range list {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.String() != raw || !prefix.Addr().IsPrivate() || !prefix.Masked().Addr().IsPrivate() || i > 0 && list[i-1] >= raw {
				return "", errors.New("[v2 客户端配置] WireGuard 地址必须是唯一排序的规范私网前缀")
			}
		}
	}
	var config struct {
		Outbounds []sbOutbound `json:"outbounds"`
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &config); err != nil {
		return "", err
	}
	if err := json.Unmarshal([]byte(content), &document); err != nil {
		return "", err
	}
	if _, found := document["endpoints"]; found {
		return "", errors.New("[v2 客户端配置] 不覆盖已有 endpoint")
	}
	detourFound := tunnel.Detour == ""
	for _, outbound := range config.Outbounds {
		if outbound.Tag == tag {
			return "", errors.New("[v2 客户端配置] 私有控制 tag 与业务出站冲突")
		}
		if outbound.Tag == tunnel.Detour {
			detourFound = outbound.Type == "hysteria2" || outbound.Type == "trojan"
		}
	}
	if !detourFound {
		return "", errors.New("[v2 客户端配置] 私有控制 detour 不是已授权的数据入口")
	}
	endpoint := struct {
		Type       string   `json:"type"`
		Tag        string   `json:"tag"`
		System     bool     `json:"system"`
		MTU        int      `json:"mtu"`
		Address    []string `json:"address"`
		PrivateKey string   `json:"private_key"`
		Detour     string   `json:"detour,omitempty"`
		Peers      []struct {
			Address                     string   `json:"address"`
			Port                        int      `json:"port"`
			PublicKey                   string   `json:"public_key"`
			AllowedIPs                  []string `json:"allowed_ips"`
			PersistentKeepaliveInterval int      `json:"persistent_keepalive_interval"`
		} `json:"peers"`
	}{Type: "wireguard", Tag: tag, MTU: tunnel.MTU, Address: tunnel.Address, PrivateKey: secretRef(tunnel.PrivateKeyRef), Detour: tunnel.Detour}
	peer := struct {
		Address                     string   `json:"address"`
		Port                        int      `json:"port"`
		PublicKey                   string   `json:"public_key"`
		AllowedIPs                  []string `json:"allowed_ips"`
		PersistentKeepaliveInterval int      `json:"persistent_keepalive_interval"`
	}{tunnel.PeerAddress, tunnel.PeerPort, tunnel.PeerPublicKey, tunnel.AllowedIPs, 25}
	endpoint.Peers = append(endpoint.Peers, peer)
	document["endpoints"], err = wire.MarshalCanonical([]any{endpoint})
	if err != nil {
		return "", err
	}
	var route sbRoute
	if err := json.Unmarshal(document["route"], &route); err != nil {
		return "", err
	}
	// 私有目的在业务 selector 前匹配，Direct/指定出口只改变业务路径。
	route.Rules = append([]sbRule{{IPCIDR: tunnel.AllowedIPs, Outbound: tag}}, route.Rules...)
	document["route"], err = wire.MarshalCanonical(route)
	if err != nil {
		return "", err
	}
	encoded, err := wire.MarshalCanonical(document)
	return string(encoded), err
}
