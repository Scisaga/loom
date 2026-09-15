package loomcore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"path"
	"strings"
)

// ValidateAndroidV2RuntimeHost 暴露 PrepareAndroidV2Runtime 使用的同一份
// 平台契约，使 instrumentation 直接验收已打包的 Go reader，而不是在 Kotlin
// 重写 DNS/TUN/WG 语义。
func ValidateAndroidV2RuntimeHost(singBox []byte) error {
	return validateAndroidV2RuntimeHost(singBox)
}

// validateAndroidV2RuntimeHost pins the platform-owned parts of
// android-runtime-v1. The artifact itself is certified, so deployment values
// such as MTU and overlay prefixes remain data; this only requires the one
// libbox process to own TUN, persistent FakeIP and userspace WireGuard.
func validateAndroidV2RuntimeHost(singBox []byte) error {
	var config androidSingBox
	if err := json.Unmarshal(singBox, &config); err != nil {
		return errors.New("[Android runtime] sing-box config 无法投影平台契约")
	}
	if !config.Route.AutoDetectInterface {
		return errors.New("[Android runtime] libbox socket 未启用 Android protect/underlay 回调")
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
			return errors.New("[Android runtime] TUN tag/route/stack/签名 MTU 无效")
		}
		for _, raw := range inbound.Address {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.String() != raw {
				return errors.New("[Android runtime] TUN address 不是规范前缀")
			}
			has4 = has4 || prefix.Addr().Is4()
			has6 = has6 || prefix.Addr().Is6()
		}
	}
	if count != 1 || !has4 || !has6 {
		return errors.New("[Android runtime] 必须由单个双栈 TUN 承载正式运行面")
	}
	return nil
}

func validateAndroidV2FakeIP(dns *androidRuntimeDNS, experimental *androidExperiment) error {
	if dns == nil || !dns.ReverseMapping || !dns.IndependentCache || dns.FakeIP == nil ||
		!dns.FakeIP.Enabled {
		return errors.New("[Android runtime] dual-stack FakeIP/FQDN 恢复未启用")
	}
	if len(dns.Servers) < 2 || dns.Servers[0].Tag == "" || dns.Servers[0].Address == "" ||
		dns.Servers[0].Address == "fakeip" {
		return errors.New("[Android runtime] bootstrap 默认 DNS 必须独立于 FakeIP")
	}
	serverAddresses := make(map[string]string, len(dns.Servers))
	for _, server := range dns.Servers {
		if server.Tag == "" || server.Address == "" {
			return errors.New("[Android runtime] DNS server tag/address 不能为空")
		}
		if _, exists := serverAddresses[server.Tag]; exists {
			return errors.New("[Android runtime] DNS server tag 重复")
		}
		serverAddresses[server.Tag] = server.Address
	}
	v4, err4 := netip.ParsePrefix(dns.FakeIP.Inet4Range)
	v6, err6 := netip.ParsePrefix(dns.FakeIP.Inet6Range)
	if err4 != nil || err6 != nil || !v4.Addr().Is4() || !v6.Addr().Is6() ||
		v4.String() != dns.FakeIP.Inet4Range || v6.String() != dns.FakeIP.Inet6Range {
		return errors.New("[Android runtime] FakeIP 地址池不是规范双栈前缀")
	}
	var fakeRule androidRuntimeDNSRule
	if len(dns.Rules) == 0 || decodeStrictJSON(dns.Rules[0], maxBundleBytes, &fakeRule) != nil ||
		len(fakeRule.Inbound) != 1 || fakeRule.Inbound[0] != "tun-in" ||
		len(fakeRule.QueryType) != 2 || !containsAndroidString(fakeRule.QueryType, "A") ||
		!containsAndroidString(fakeRule.QueryType, "AAAA") {
		return errors.New("[Android runtime] 首条 DNS 规则必须只把 TUN A/AAAA 交给 FakeIP")
	}
	fakeServer := fakeRule.Server
	var cache *androidCacheFile
	if experimental != nil {
		cache = experimental.CacheFile
	}
	if fakeServer == "" || serverAddresses[fakeServer] != "fakeip" || dns.Final == fakeServer ||
		cache == nil || !cache.Enabled || !cache.StoreFakeIP ||
		!validAndroidPrivateRelativePath(cache.Path) {
		return errors.New("[Android runtime] TUN FakeIP server 绑定、默认 DNS 或持久缓存无效")
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
			return errors.New("[Android runtime] userspace WireGuard endpoint 形状无效")
		}
		tags[endpoint.Tag] = true
		for _, address := range endpoint.Address {
			prefix, err := netip.ParsePrefix(address)
			if err != nil || prefix.String() != address || !prefix.Addr().IsPrivate() {
				return errors.New("[Android runtime] WireGuard 本地地址不是规范私网前缀")
			}
		}
		if len(endpoint.Address) == 0 {
			return errors.New("[Android runtime] WireGuard endpoint 缺本地地址")
		}
		for _, peer := range endpoint.Peers {
			if strings.TrimSpace(peer.Address) == "" || peer.Port < 1 || peer.Port > 65535 ||
				!canonicalCurve25519Key(peer.PublicKey) || len(peer.AllowedIP) == 0 {
				return errors.New("[Android runtime] WireGuard peer 形状无效")
			}
			for _, raw := range peer.AllowedIP {
				prefix, err := netip.ParsePrefix(raw)
				if err != nil || prefix.String() != raw || !prefix.Addr().IsPrivate() {
					return errors.New("[Android runtime] WireGuard AllowedIPs 不是规范私网前缀")
				}
				allowed[endpoint.Tag] = append(allowed[endpoint.Tag], prefix)
			}
		}
	}
	if len(tags) == 0 || len(tags) > 8 {
		return errors.New("[Android runtime] 正式运行面缺少有界 userspace WireGuard generation")
	}
	for _, rule := range rules {
		if !tags[rule.Outbound] || len(rule.IPCIDR) == 0 {
			continue
		}
		for _, raw := range rule.IPCIDR {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.String() != raw || !prefix.Addr().IsPrivate() ||
				!coveredByAndroidWG(prefix, allowed[rule.Outbound]) {
				return errors.New("[Android runtime] WireGuard 私网路由超出 peer AllowedIPs")
			}
		}
		return nil
	}
	return errors.New("[Android runtime] private control/L3 overlay 未路由到同宿主 WireGuard")
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
