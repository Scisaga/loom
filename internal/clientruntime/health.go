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
	"net/url"
	"slices"
	"strings"
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
	response, err := client.Do(request)
	if err != nil {
		return []string{healthProbeProblem(err)}
	}
	defer response.Body.Close()
	// §16.2：沿用现有 Agent 的可达性口径，收到目标 HTTP 响应且非 5xx；不跟随重定向。
	// 这不是业务授权或内容正确性的断言，正文也不进入日志或签名报告。
	if response.StatusCode >= 500 || response.StatusCode == http.StatusProxyAuthRequired {
		return []string{fmt.Sprintf("端到端探测返回 HTTP %d", response.StatusCode)}
	}
	return nil
}

var errTUNCapture = errors.New("TUN 接管未生效")

func healthProbeProblem(err error) string {
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	switch {
	case errors.Is(err, errTUNCapture):
		return errTUNCapture.Error()
	case errors.As(err, &dns):
		return "端到端探测 DNS 解析失败"
	case errors.As(err, &cert), errors.As(err, &unknown), errors.As(err, &host):
		return "端到端探测 TLS 证书验证失败"
	case errors.Is(err, context.DeadlineExceeded):
		return "端到端探测超时"
	case errors.Is(err, context.Canceled):
		return "端到端探测已取消"
	default:
		return "端到端探测连接或 TLS 握手失败"
	}
}

func mixedHealthTransport() *http.Transport {
	return &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1080"}),
		DisableKeepAlives: true,
	}
}
