package clientruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
)

// WindowsHealthPlan 按 §7.2.1 / §16.1 从已验签配置派生代表性目标；不保存秘密或历史结果。
type WindowsHealthPlan struct {
	target  string
	profile WindowsRuntimeProfile
}

func BuildWindowsHealthPlan(body []byte, profile WindowsRuntimeProfile, caPath string) (*WindowsHealthPlan, error) {
	if err := ValidateWindowsRuntimeConfig(body, profile, caPath); err != nil {
		return nil, err
	}
	var config singBoxConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, err
	}
	inbound := "tun-in"
	if profile == WindowsPortableMixedProfile {
		inbound = "in-1080"
	}
	var targets []string
	for _, rule := range config.Route.Rules {
		if !slices.Contains(rule.Inbound, inbound) || !strings.HasPrefix(rule.Outbound, "svc:") ||
			rule.Action != "" || len(rule.AuthUser) != 0 || len(rule.IPCIDR) != 0 || (len(rule.Port) != 0 && !slices.Contains(rule.Port, 443)) {
			continue
		}
		for _, domain := range rule.Domain {
			// §4.5：渲染器会将后缀的根域名也放入 domain，不能把它误当明确的业务目标。
			suffixRoot := slices.ContainsFunc(rule.DomainSuffix, func(s string) bool { return strings.EqualFold(strings.TrimPrefix(s, "."), domain) })
			if suffixRoot || !healthHostname(domain) {
				continue
			}
			targets = append(targets, "https://"+strings.ToLower(domain)+"/")
		}
	}
	slices.Sort(targets)
	plan := &WindowsHealthPlan{profile: profile}
	if len(targets) != 0 {
		plan.target = targets[0]
	}
	return plan, nil
}

func healthHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (plan *WindowsHealthPlan) check(ctx context.Context, transport *http.Transport) []string {
	if plan == nil || plan.target == "" {
		return []string{"已激活配置缺少可探测的具体服务地址"}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, plan.target, nil)
	if err != nil {
		return []string{"健康探测目标无效"}
	}
	// §16.1：只记录失败环节与已验证目标，不把含凭证的底层错误写入 self_check。
	var phase atomic.Value
	phase.Store("连接")
	trace := &httptrace.ClientTrace{
		DNSStart:     func(httptrace.DNSStartInfo) { phase.Store("DNS 解析") },
		ConnectStart: func(string, string) { phase.Store("TCP 连接") },
		ConnectDone: func(_, _ string, err error) {
			if err == nil && transport.Proxy != nil {
				phase.Store("本地代理隧道")
			}
		},
		TLSHandshakeStart: func() { phase.Store("TLS 握手") },
		GotConn:           func(httptrace.GotConnInfo) { phase.Store("HTTP 响应") },
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	response, err := client.Do(request)
	if err != nil {
		return []string{plan.probeProblem(err, phase.Load().(string))}
	}
	defer response.Body.Close()
	// §16.2：沿用现有 Agent 的可达性口径，收到目标 HTTP 响应且非 5xx；不跟随重定向。
	// 这不是业务授权或内容正确性的断言，正文也不进入日志或签名报告。
	if response.StatusCode >= 500 || response.StatusCode == http.StatusProxyAuthRequired {
		return []string{plan.probeLabel() + fmt.Sprintf("：HTTP 响应返回 %d", response.StatusCode)}
	}
	return nil
}

var errTUNCapture = errors.New("TUN 接管未生效")

// §16.1：已有 self_check 字符串承载单目标事实，不引入新的设备健康模型。
func (plan *WindowsHealthPlan) probeLabel() string {
	u, err := url.Parse(plan.target)
	if err != nil || u.Host == "" || len(u.Host) > 260 || strings.ContainsAny(u.Host, "\r\n") {
		return "单目标探测"
	}
	return "单目标探测 " + u.Scheme + "://" + u.Host + "/"
}

func (plan *WindowsHealthPlan) probeProblem(err error, phase string) string {
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	result := "失败"
	switch {
	case errors.Is(err, errTUNCapture):
		return plan.probeLabel() + "：TUN 接管未生效"
	case errors.As(err, &cert), errors.As(err, &unknown), errors.As(err, &host):
		return plan.probeLabel() + "：TLS 证书验证失败"
	case errors.As(err, &dns):
		phase = "DNS 解析"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		result = "超时"
	} else if errors.Is(err, context.Canceled) {
		result = "已取消"
	}
	return plan.probeLabel() + "：" + phase + result
}

func mixedHealthTransport() *http.Transport {
	return &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1080"}),
		DisableKeepAlives: true,
	}
}
