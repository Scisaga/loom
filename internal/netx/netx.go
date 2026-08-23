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
	"strings"
	"time"
)

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
