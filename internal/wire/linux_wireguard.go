package wire

import (
	"encoding/base64"
	"errors"
	"net/netip"
)

// 节点间 WireGuard 是逐边私有资源，不能伪装成公开 DataIngressEndpoint。
// 迁移时保留原地址、公钥和方向；新 Device view 对完整资源和 intent 一起承诺。
type LinuxWireGuardResourceV1 struct {
	ResourceID           string `json:"resource_id"`
	LinkID               string `json:"link_id"`
	ListenerDeviceID     string `json:"listener_device_id"`
	DialerDeviceID       string `json:"dialer_device_id"`
	ListenerGeneration   int64  `json:"listener_generation"`
	EndpointAddress      string `json:"endpoint_address"`
	EndpointPort         int64  `json:"endpoint_port"`
	ListenerPublicKey    string `json:"listener_public_key"`
	DialerPublicKey      string `json:"dialer_public_key"`
	ListenerTunnelPrefix string `json:"listener_tunnel_prefix"`
	DialerTunnelPrefix   string `json:"dialer_tunnel_prefix"`
}

// 只能引用节点既有的固定 WireGuard key 文件，artifact 不提供任意文件路径。
// PublicKey 用于本机读取后的匹配，不能把另一把本地 key 装进认证隧道。
type LinuxLocalWireGuardKeyV1 struct {
	SecretID  string `json:"secret_id"`
	PublicKey string `json:"public_key"`
}

func ValidateLinuxWireGuardResources(artifact *LinuxLinkIntentArtifactV1) error {
	if artifact == nil {
		return errors.New("[Linux WireGuard] 缺 LinkIntent artifact")
	}
	resources := make(map[string]LinuxWireGuardResourceV1, len(artifact.WireGuardResources))
	for i, resource := range artifact.WireGuardResources {
		if err := ValidateLinuxWireGuardResource(resource); err != nil {
			return err
		}
		if i > 0 && artifact.WireGuardResources[i-1].ResourceID >= resource.ResourceID {
			return errors.New("[Linux WireGuard] peer 资源顺序无效")
		}
		resources[resource.ResourceID] = resource
	}
	local := artifact.LocalWireGuardKey
	if local != nil && (!validIdentifier(local.SecretID, 128) || !validWireGuardPublicKey(local.PublicKey) || len(resources) == 0) {
		return errors.New("[Linux WireGuard] 本地密钥引用缺完整 peer 资源")
	}
	used := make(map[string]bool)
	for _, intent := range artifact.LinkIntents {
		for _, ref := range intent.ListenerResourceRefs {
			resource, found := resources[ref]
			if !found {
				continue
			}
			listener, dialer := intent.To.DeviceID, intent.FromDeviceID
			if intent.Initiator == "to" {
				listener, dialer = dialer, listener
			}
			if intent.LinkID != resource.LinkID || intent.To.DeviceID == "" || listener != resource.ListenerDeviceID || dialer != resource.DialerDeviceID ||
				len(intent.AllowedTransports) != 1 || intent.AllowedTransports[0] != "wireguard" || len(intent.ListenerResourceRefs) != 1 || used[ref] {
				return errors.New("[Linux WireGuard] 资源未 exact 绑定同一 intent 的两端、方向与 transport")
			}
			if local != nil {
				public := resource.ListenerPublicKey
				if artifact.DeviceID == dialer {
					public = resource.DialerPublicKey
				}
				if public != local.PublicKey || !contains(intent.CredentialRefs, local.SecretID) {
					return errors.New("[Linux WireGuard] 本地密钥引用与原 peer 公钥不匹配")
				}
			}
			used[ref] = true
		}
	}
	if len(used) != len(resources) {
		return errors.New("[Linux WireGuard] artifact 含未获本机 intent 授权的 peer 资源")
	}
	return nil
}

func validWireGuardPublicKey(value string) bool {
	key, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != value {
		return false
	}
	var combined byte
	for _, item := range key {
		combined |= item
	}
	return combined != 0
}

func ValidateLinuxWireGuardResource(resource LinuxWireGuardResourceV1) error {
	if !validIdentifier(resource.ResourceID, 128) || !validIdentifier(resource.LinkID, 128) ||
		!validIdentifier(resource.ListenerDeviceID, 128) || !validIdentifier(resource.DialerDeviceID, 128) ||
		resource.ListenerDeviceID == resource.DialerDeviceID || resource.ListenerGeneration < 1 ||
		resource.EndpointPort < 1 || resource.EndpointPort > 65535 ||
		!validWireGuardPublicKey(resource.ListenerPublicKey) || !validWireGuardPublicKey(resource.DialerPublicKey) {
		return errors.New("[Linux WireGuard] peer 资源身份、端口、公钥或顺序无效")
	}
	address, err := netip.ParseAddr(resource.EndpointAddress)
	if err != nil {
		if !ValidFQDN(resource.EndpointAddress) {
			return errors.New("[Linux WireGuard] peer endpoint 不是明确的 IP 或域名")
		}
	} else if address.String() != resource.EndpointAddress || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return errors.New("[Linux WireGuard] peer endpoint 地址无效")
	}
	listener, err := netip.ParsePrefix(resource.ListenerTunnelPrefix)
	dialer, dialErr := netip.ParsePrefix(resource.DialerTunnelPrefix)
	if err != nil || dialErr != nil || listener.String() != resource.ListenerTunnelPrefix || dialer.String() != resource.DialerTunnelPrefix ||
		!listener.Addr().IsPrivate() || !dialer.Addr().IsPrivate() || listener.Addr().Is4() != dialer.Addr().Is4() ||
		listener.Bits() != listener.Addr().BitLen() || dialer.Bits() != dialer.Addr().BitLen() || listener == dialer {
		return errors.New("[Linux WireGuard] 隧道两端必须是不同的同地址族私网主机前缀")
	}
	return nil
}
