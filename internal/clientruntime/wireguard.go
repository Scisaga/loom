package clientruntime

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
)

// 同一 sing-box 承载业务代理和私有控制 WireGuard。结构化派生必须保留
// endpoint；忽略未知字段会让 portable-mixed 意外丢失私有控制路由。
type singBoxWireGuardEndpoint struct {
	Type       string                 `json:"type"`
	Tag        string                 `json:"tag"`
	System     bool                   `json:"system"`
	MTU        int                    `json:"mtu"`
	Address    []string               `json:"address"`
	PrivateKey string                 `json:"private_key"`
	Detour     string                 `json:"detour,omitempty"`
	Peers      []singBoxWireGuardPeer `json:"peers"`
}

type singBoxWireGuardPeer struct {
	Address                     string   `json:"address"`
	Port                        int      `json:"port"`
	PublicKey                   string   `json:"public_key"`
	AllowedIPs                  []string `json:"allowed_ips"`
	PersistentKeepaliveInterval int      `json:"persistent_keepalive_interval,omitempty"`
}

func validateWindowsWireGuardEndpoints(endpoints []singBoxWireGuardEndpoint, outbounds []singBoxOutbound,
	rules []singBoxRule) (map[string]bool, error) {
	tags := make(map[string]bool, len(endpoints))
	if len(endpoints) > 8 {
		return nil, errors.New("[Windows control] WireGuard generation 数量超限")
	}
	proxyTypes := make(map[string]string, len(outbounds))
	for _, outbound := range outbounds {
		proxyTypes[outbound.Tag] = outbound.Type
	}
	for _, endpoint := range endpoints {
		if endpoint.Type != "wireguard" || endpoint.Tag == "" || tags[endpoint.Tag] || proxyTypes[endpoint.Tag] != "" ||
			endpoint.System || endpoint.MTU < 576 || endpoint.MTU > 9000 || !canonicalWireGuardKey(endpoint.PrivateKey) ||
			len(endpoint.Address) == 0 || len(endpoint.Address) > 8 || len(endpoint.Peers) == 0 || len(endpoint.Peers) > 8 {
			return nil, errors.New("[Windows control] userspace WireGuard endpoint 形状无效")
		}
		if endpoint.Detour != "" && proxyTypes[endpoint.Detour] != "hysteria2" && proxyTypes[endpoint.Detour] != "trojan" {
			return nil, errors.New("[Windows control] WireGuard detour 必须是已授权的独立数据入口")
		}
		tags[endpoint.Tag] = true
		for _, address := range endpoint.Address {
			if _, err := privateWireGuardPrefix(address); err != nil {
				return nil, err
			}
		}
		var allowed []netip.Prefix
		for _, peer := range endpoint.Peers {
			if peer.Address == "" || strings.TrimSpace(peer.Address) != peer.Address || strings.ContainsAny(peer.Address, "/\\\x00\r\n") ||
				peer.Port < 1 || peer.Port > 65535 || !canonicalWireGuardKey(peer.PublicKey) || len(peer.AllowedIPs) == 0 ||
				len(peer.AllowedIPs) > 32 || peer.PersistentKeepaliveInterval < 0 || peer.PersistentKeepaliveInterval > 65535 {
				return nil, errors.New("[Windows control] WireGuard peer 形状无效")
			}
			for _, raw := range peer.AllowedIPs {
				prefix, err := privateWireGuardPrefix(raw)
				if err != nil {
					return nil, err
				}
				allowed = append(allowed, prefix)
			}
		}
		routed := false
		for _, rule := range rules {
			if rule.Outbound != endpoint.Tag {
				continue
			}
			// 私有控制需要同宿主 mixed 路由，不能依赖被 portable 形态删除的 TUN。
			if len(rule.IPCIDR) == 0 || len(rule.Inbound) != 0 || len(rule.AuthUser) != 0 || len(rule.Domain) != 0 ||
				len(rule.DomainSuffix) != 0 || rule.Action != "" || rule.Type != "" || rule.Invert || len(rule.Rules) != 0 {
				return nil, errors.New("[Windows control] WireGuard 控制路由必须限定私网前缀且独立于 TUN")
			}
			for _, raw := range rule.IPCIDR {
				prefix, err := privateWireGuardPrefix(raw)
				covered := false
				for _, candidate := range allowed {
					covered = covered || candidate.Addr().BitLen() == prefix.Addr().BitLen() && candidate.Bits() <= prefix.Bits() && candidate.Contains(prefix.Addr())
				}
				if err != nil || !covered {
					return nil, errors.New("[Windows control] 控制路由超出 WireGuard peer AllowedIPs")
				}
			}
			routed = true
		}
		if !routed {
			return nil, errors.New("[Windows control] WireGuard endpoint 缺私有控制路由")
		}
	}
	return tags, nil
}

func privateWireGuardPrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.String() != value || !prefix.Addr().IsPrivate() || !prefix.Masked().Addr().IsPrivate() {
		return netip.Prefix{}, errors.New("[Windows control] WireGuard 前缀不是规范私网地址")
	}
	return prefix, nil
}

func canonicalWireGuardKey(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.StdEncoding.EncodeToString(decoded) == value
}
