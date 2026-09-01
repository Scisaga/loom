// Package netx 造一个**不依赖机器全局设置**的 HTTP 客户端。
//
// 两处显式覆盖,都是被真实故障逼出来的:
//
//   - **Proxy 置空。** 节点上设了 HTTP_PROXY 时,默认 Transport 会把请求
//     交给那个代理 —— 包括发往隧道内地址和回环的请求。
//   - **自带 DNS。** access-a 上有个与 Loom 无关的 WireGuard 接口声明了
//     `DNS Domain: ~.`,把**所有**域名劫到 8.8.8.8;在境内等于解析不了任何
//     国内域名。那是别人的配置,Loom 不该改它,但也不该依赖它。每个节点
//     该用哪个解析器,SSOT 里本来就声明了(§7.3.2)。
package netx

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode"
)

var nonPublicGlobalPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// IsPublicGlobalUnicast is the shared literal-IP trust boundary for SSH and
// invitation Enrollment. netip.IsGlobalUnicast intentionally includes several
// documentation, benchmark and reserved ranges; those are not usable public
// endpoints and must not be promoted into SSOT.
func IsPublicGlobalUnicast(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range nonPublicGlobalPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// NormalizePublicEndpoint validates an endpoint with no scheme or port and
// returns a stable representation for exact replay comparisons. DNS names are
// ASCII-lowercased; IP literals use netip's canonical spelling.
func NormalizePublicEndpoint(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 || strings.IndexFunc(value, unicode.IsSpace) >= 0 ||
		strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", false
	}
	if address, err := netip.ParseAddr(value); err == nil {
		if !IsPublicGlobalUnicast(address) {
			return "", false
		}
		return address.Unmap().String(), true
	}
	if strings.ContainsAny(value, "/:@[]") || !strings.Contains(value, ".") ||
		strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return "", false
	}
	value = strings.ToLower(value)
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", false
			}
		}
	}
	return value, true
}

// Client 返回一个 HTTP 客户端。dnsServer 为空时用系统解析器。
func Client(dnsServer string, timeout time.Duration) *http.Client {
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	if dnsServer != "" {
		if !strings.Contains(dnsServer, ":") {
			dnsServer += ":53"
		}
		d := &net.Dialer{Timeout: 10 * time.Second}
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, dnsServer)
			},
		}
		tr.DialContext = (&net.Dialer{Timeout: 15 * time.Second, Resolver: r}).DialContext
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}
