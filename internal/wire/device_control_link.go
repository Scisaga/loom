package wire

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
)

// DeviceControlLinkV1 是普通 Device 到私有服务的受限数据链路，不授予
// ControlSet membership。客户端和承载节点的配置均由同一认证分配生成。
type DeviceControlLinkV1 struct {
	Resource LinuxWireGuardResourceV1  `json:"resource"`
	Services []PrivateControlServiceV1 `json:"services"`
	Carrier  *DeviceControlCarrierV1   `json:"carrier,omitempty"`
}

// Carrier 复用承载节点已有 HY2 listener，只授权该设备的私网 WireGuard
// tuple。它不授予业务转发或探测权限，也不新增公网 listener。
type DeviceControlCarrierV1 struct {
	Address       string `json:"address"`
	Port          int64  `json:"port"`
	TLSServerName string `json:"tls_server_name"`
	CredentialRef string `json:"credential_ref"`
}

func ValidateDeviceControlLink(link *DeviceControlLinkV1) error {
	if link == nil || len(link.Services) != 2 {
		return errors.New("[设备控制链路] 缺配置与报告的独立私有服务")
	}
	r := link.Resource
	address, err := netip.ParseAddr(r.EndpointAddress)
	if err != nil || !address.IsPrivate() || address.String() != r.EndpointAddress {
		return errors.New("[设备控制链路] WireGuard 必须经明确的私网地址连接")
	}
	if err := ValidateLinuxWireGuardResource(r); err != nil {
		return err
	}
	if carrier := link.Carrier; carrier != nil {
		ip, err := netip.ParseAddr(carrier.Address)
		if err != nil && !ValidFQDN(carrier.Address) || err == nil && (ip.String() != carrier.Address || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Is4In6()) ||
			carrier.Port < 1 || carrier.Port > 65535 || !ValidFQDN(carrier.TLSServerName) || carrier.CredentialRef != DeviceControlCarrierCredentialRef(*link) {
			return errors.New("[设备控制链路] 外层承载 tuple、TLS 身份或设备专用凭据无效")
		}
	}
	listener, _ := netip.ParsePrefix(r.ListenerTunnelPrefix)
	if r.ResourceID != r.LinkID || !strings.HasPrefix(r.ResourceID, "device-control-") {
		return errors.New("[设备控制链路] listener 地址或资源身份不一致")
	}
	roles := map[string]bool{}
	for i, service := range link.Services {
		if err := ValidatePrivateControlService(&service); err != nil {
			return err
		}
		ip, err := netip.ParseAddr(service.OverlayIP)
		if err != nil || !ip.IsPrivate() || service.Role != "device_config" && service.Role != "device_report" || roles[service.Role] ||
			i > 0 && link.Services[i-1].ServiceID >= service.ServiceID {
			return errors.New("[设备控制链路] 仅允许排序后的私有配置与报告服务")
		}
		// sing-box 会将 endpoint 本身地址映射到本机 loopback；服务地址必须
		// 独立，防止改变已认证的 overlay tuple 或错误命中拒绝规则。
		client, _ := netip.ParsePrefix(r.DialerTunnelPrefix)
		if ip.Is4() != listener.Addr().Is4() || listener.Contains(ip) || client.Contains(ip) {
			return errors.New("[设备控制链路] 隧道地址不能占用私有服务地址")
		}
		roles[service.Role] = true
	}
	return nil
}

func DeviceControlLinkIntent(cluster string, r LinuxWireGuardResourceV1, parent, keyRef string) LinkIntentV1 {
	return LinkIntentV1{Schema: 1, ClusterID: cluster, LinkID: r.LinkID,
		FromDeviceID: r.DialerDeviceID, To: LinkIntentDestinationV1{DeviceID: r.ListenerDeviceID},
		Purpose: "data_forward", Initiator: "from", AllowedTransports: []string{"wireguard"},
		ListenerResourceRefs: []string{r.ResourceID}, CredentialRefs: []string{keyRef},
		RouteScope: "device-private-services", Generation: r.ListenerGeneration, ParentHeadHash: parent}
}

func DeviceControlEndpointTag(link DeviceControlLinkV1) string { return link.Resource.ResourceID }

// 下列结构同时用于确定性生成与消费者逐字段比较，不能通过多余的 endpoint
// 字段、direct override 或靠后的宽泛规则扩大私有服务访问。
type DeviceControlEndpointV1 struct {
	Type       string                        `json:"type"`
	Tag        string                        `json:"tag"`
	System     bool                          `json:"system"`
	MTU        int                           `json:"mtu"`
	Address    []string                      `json:"address"`
	PrivateKey string                        `json:"private_key"`
	ListenPort int64                         `json:"listen_port,omitempty"`
	Detour     string                        `json:"detour,omitempty"`
	Peers      []DeviceControlEndpointPeerV1 `json:"peers"`
}
type DeviceControlEndpointPeerV1 struct {
	Address    string   `json:"address,omitempty"`
	Port       int64    `json:"port,omitempty"`
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
}
type DeviceControlRouteV1 struct {
	Inbound  []string `json:"inbound"`
	AuthUser []string `json:"auth_user,omitempty"`
	IPCIDR   []string `json:"ip_cidr,omitempty"`
	Port     []int64  `json:"port,omitempty"`
	Outbound string   `json:"outbound"`
}

const DeviceControlDirectTag = "device-control-direct"
const DeviceControlBlockTag = "device-control-block"
const DeviceControlLocalTag = "device-control-local"
const DeviceControlLocalPort = 61805

func DeviceControlCarrierTag(link DeviceControlLinkV1) string {
	return link.Resource.ResourceID + "-carrier"
}
func DeviceControlCarrierCredentialRef(link DeviceControlLinkV1) string {
	return DeviceControlCarrierTag(link)
}

func DeviceControlEndpoint(link DeviceControlLinkV1, key string) DeviceControlEndpointV1 {
	r := link.Resource
	return DeviceControlEndpointV1{Type: "wireguard", Tag: DeviceControlEndpointTag(link), System: false,
		MTU: 1280, Address: []string{r.ListenerTunnelPrefix}, PrivateKey: key, ListenPort: r.EndpointPort,
		Peers: []DeviceControlEndpointPeerV1{{PublicKey: r.DialerPublicKey, AllowedIPs: []string{r.DialerTunnelPrefix}}}}
}

func DeviceControlRoutes(links []DeviceControlLinkV1) []DeviceControlRouteV1 {
	var routes []DeviceControlRouteV1
	for _, link := range links {
		tag := DeviceControlEndpointTag(link)
		for _, service := range link.Services {
			ip, _ := netip.ParseAddr(service.OverlayIP)
			routes = append(routes, DeviceControlRouteV1{Inbound: []string{tag}, IPCIDR: []string{netip.PrefixFrom(ip, ip.BitLen()).String()}, Port: []int64{service.Port}, Outbound: DeviceControlDirectTag})
		}
		routes = append(routes, DeviceControlRouteV1{Inbound: []string{tag}, Outbound: DeviceControlBlockTag})
	}
	return routes
}

func DeviceControlEndpointForDevice(link DeviceControlLinkV1, device, key string) DeviceControlEndpointV1 {
	if device == link.Resource.ListenerDeviceID {
		return DeviceControlEndpoint(link, key)
	}
	addresses := map[string]bool{}
	for _, service := range link.Services {
		ip, _ := netip.ParseAddr(service.OverlayIP)
		addresses[netip.PrefixFrom(ip, ip.BitLen()).String()] = true
	}
	allowed := make([]string, 0, len(addresses))
	for address := range addresses {
		allowed = append(allowed, address)
	}
	sort.Strings(allowed)
	r := link.Resource
	return DeviceControlEndpointV1{Type: "wireguard", Tag: DeviceControlEndpointTag(link), System: false, MTU: 1280,
		Address: []string{r.DialerTunnelPrefix}, PrivateKey: key, Detour: DeviceControlCarrierTag(link),
		Peers: []DeviceControlEndpointPeerV1{{Address: r.EndpointAddress, Port: r.EndpointPort, PublicKey: r.ListenerPublicKey, AllowedIPs: allowed}}}
}

func DeviceControlRoutesForDevice(links []DeviceControlLinkV1, device string) []DeviceControlRouteV1 {
	var routes []DeviceControlRouteV1
	for _, link := range links {
		if link.Resource.ListenerDeviceID == device {
			if link.Carrier != nil {
				ip, _ := netip.ParseAddr(link.Resource.EndpointAddress)
				routes = append(routes,
					DeviceControlRouteV1{Inbound: []string{"in"}, AuthUser: []string{link.Resource.ResourceID}, IPCIDR: []string{netip.PrefixFrom(ip, ip.BitLen()).String()}, Port: []int64{link.Resource.EndpointPort}, Outbound: DeviceControlDirectTag},
					DeviceControlRouteV1{Inbound: []string{"in"}, AuthUser: []string{link.Resource.ResourceID}, Outbound: DeviceControlBlockTag})
			}
			routes = append(routes, DeviceControlRoutes([]DeviceControlLinkV1{link})...)
			continue
		}
		for _, service := range link.Services {
			ip, _ := netip.ParseAddr(service.OverlayIP)
			routes = append(routes, DeviceControlRouteV1{Inbound: []string{DeviceControlLocalTag}, IPCIDR: []string{netip.PrefixFrom(ip, ip.BitLen()).String()}, Port: []int64{service.Port}, Outbound: DeviceControlEndpointTag(link)})
		}
		routes = append(routes, DeviceControlRouteV1{Inbound: []string{DeviceControlLocalTag}, Outbound: DeviceControlBlockTag})
	}
	return routes
}
