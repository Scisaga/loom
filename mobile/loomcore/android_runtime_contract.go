package loomcore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"path"
	"strings"
)

// validateAndroidV2RuntimeHost pins the platform-owned parts of
// android-runtime-v1. The artifact itself is certified, so deployment values
// such as MTU and overlay prefixes remain data; this only requires the one
// libbox process to own TUN, persistent FakeIP and userspace WireGuard.
func validateAndroidV2RuntimeHost(singBox []byte) error {
	var config androidSingBox
	if err := json.Unmarshal(singBox, &config); err != nil {
		return errors.New("[D131 Android runtime] sing-box config 无法投影平台契约")
	}
	if !config.Route.AutoDetectInterface {
		return errors.New("[D131 Android runtime] libbox socket 未启用 Android protect/underlay 回调")
	}
	if err := validateAndroidV2TUN(config.Inbounds); err != nil {
		return err
	}
	if err := validateAndroidV2FakeIP(config.DNS, config.Experimental); err != nil {
		return err
	}
	return validateAndroidV2WireGuard(config.Endpoints, config.Route.Rules)
}

func validateAndroidV2TUN(inbounds []androidInbound) error {
	count, has4, has6 := 0, false, false
	for _, inbound := range inbounds {
		if inbound.Type != "tun" {
			continue
		}
		count++
		if inbound.Tag != "tun-in" || !inbound.AutoRoute || inbound.Stack != "system" ||
			inbound.MTU < 576 || inbound.MTU > 9000 {
			return errors.New("[D131 Android runtime] TUN tag/route/stack/签名 MTU 无效")
		}
		for _, raw := range inbound.Address {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.String() != raw {
				return errors.New("[D131 Android runtime] TUN address 不是规范前缀")
			}
			has4 = has4 || prefix.Addr().Is4()
			has6 = has6 || prefix.Addr().Is6()
		}
	}
	if count != 1 || !has4 || !has6 {
		return errors.New("[D131 Android runtime] 必须由单个双栈 TUN 承载正式运行面")
	}
	return nil
}

func validateAndroidV2FakeIP(dns *androidRuntimeDNS, experimental *androidExperiment) error {
	if dns == nil || !dns.ReverseMapping || !dns.IndependentCache || dns.FakeIP == nil ||
		!dns.FakeIP.Enabled {
		return errors.New("[D131 Android runtime] dual-stack FakeIP/FQDN 恢复未启用")
	}
	v4, err4 := netip.ParsePrefix(dns.FakeIP.Inet4Range)
	v6, err6 := netip.ParsePrefix(dns.FakeIP.Inet6Range)
	if err4 != nil || err6 != nil || !v4.Addr().Is4() || !v6.Addr().Is6() ||
		v4.String() != dns.FakeIP.Inet4Range || v6.String() != dns.FakeIP.Inet6Range {
		return errors.New("[D131 Android runtime] FakeIP 地址池不是规范双栈前缀")
	}
	fakeServer := ""
	for _, rule := range dns.Rules {
		if containsAndroidString(rule.Inbound, "tun-in") &&
			containsAndroidString(rule.QueryType, "A") && containsAndroidString(rule.QueryType, "AAAA") {
			fakeServer = rule.Server
		}
	}
	var cache *androidCacheFile
	if experimental != nil {
		cache = experimental.CacheFile
	}
	if fakeServer == "" || cache == nil || !cache.Enabled || !cache.StoreFakeIP ||
		!validAndroidPrivateRelativePath(cache.Path) {
		return errors.New("[D131 Android runtime] TUN A/AAAA FakeIP 规则或持久缓存无效")
	}
	return nil
}

func validateAndroidV2WireGuard(endpoints []androidEndpoint, rules []androidRule) error {
	tags := map[string]bool{}
	allowed := map[string][]netip.Prefix{}
	for _, endpoint := range endpoints {
		if endpoint.Type != "wireguard" {
			continue
		}
		if endpoint.Tag == "" || tags[endpoint.Tag] || endpoint.System || endpoint.MTU < 576 ||
			endpoint.MTU > 9000 || !canonicalCurve25519Key(endpoint.PrivateKey) || len(endpoint.Peers) == 0 {
			return errors.New("[D131 Android runtime] userspace WireGuard endpoint 形状无效")
		}
		tags[endpoint.Tag] = true
		for _, address := range endpoint.Address {
			prefix, err := netip.ParsePrefix(address)
			if err != nil || prefix.String() != address || !prefix.Addr().IsPrivate() {
				return errors.New("[D131 Android runtime] WireGuard 本地地址不是规范私网前缀")
			}
		}
		if len(endpoint.Address) == 0 {
			return errors.New("[D131 Android runtime] WireGuard endpoint 缺本地地址")
		}
		for _, peer := range endpoint.Peers {
			if strings.TrimSpace(peer.Address) == "" || peer.Port < 1 || peer.Port > 65535 ||
				!canonicalCurve25519Key(peer.PublicKey) || len(peer.AllowedIP) == 0 {
				return errors.New("[D131 Android runtime] WireGuard peer 形状无效")
			}
			for _, raw := range peer.AllowedIP {
				prefix, err := netip.ParsePrefix(raw)
				if err != nil || prefix.String() != raw || !prefix.Addr().IsPrivate() {
					return errors.New("[D131 Android runtime] WireGuard AllowedIPs 不是规范私网前缀")
				}
				allowed[endpoint.Tag] = append(allowed[endpoint.Tag], prefix)
			}
		}
	}
	if len(tags) == 0 || len(tags) > 8 {
		return errors.New("[D131 Android runtime] 正式运行面缺少有界 userspace WireGuard generation")
	}
	for _, rule := range rules {
		if !tags[rule.Outbound] || len(rule.IPCIDR) == 0 {
			continue
		}
		for _, raw := range rule.IPCIDR {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.String() != raw || !prefix.Addr().IsPrivate() ||
				!coveredByAndroidWG(prefix, allowed[rule.Outbound]) {
				return errors.New("[D131 Android runtime] WireGuard 私网路由超出 peer AllowedIPs")
			}
		}
		return nil
	}
	return errors.New("[D131 Android runtime] private control/L3 overlay 未路由到同宿主 WireGuard")
}

func coveredByAndroidWG(prefix netip.Prefix, allowed []netip.Prefix) bool {
	for _, candidate := range allowed {
		if candidate.Addr().BitLen() == prefix.Addr().BitLen() && candidate.Bits() <= prefix.Bits() &&
			candidate.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func canonicalCurve25519Key(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.StdEncoding.EncodeToString(decoded) == value
}

func validAndroidPrivateRelativePath(value string) bool {
	clean := path.Clean(value)
	return value != "" && clean == value && clean != "." && clean != ".." &&
		!strings.HasPrefix(clean, "../") && !strings.HasPrefix(clean, "/") &&
		!strings.ContainsAny(clean, "\\:\x00\r\n")
}
