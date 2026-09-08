package clientruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func healthConfig(t *testing.T, profile WindowsRuntimeProfile, domains, suffixes []string) []byte {
	t.Helper()
	source := strings.NewReplacer("${secret:vault:cred/win01}", "fixture-password", "${secret:api/win01}", "fixture-api").Replace(validWindowsConfig("warn"))
	var config singBoxConfig
	if err := json.Unmarshal([]byte(source), &config); err != nil {
		t.Fatal(err)
	}
	config.Outbounds = append(config.Outbounds, singBoxOutbound{Type: "selector", Tag: "svc:demo-service", Outbounds: []string{"cand:auto:edge"}, Default: "cand:auto:edge"})
	config.Route.Rules = append([]singBoxRule{{Inbound: []string{"tun-in", "in-1080"}, Domain: domains, DomainSuffix: suffixes, Outbound: "svc:demo-service"}}, config.Route.Rules...)
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := DeriveWindowsRuntimeConfig(body, profile, WindowsInstalledCAPath)
	if err != nil {
		t.Fatal(err)
	}
	return derived
}

func TestWindowsHealthTargetFromActiveServiceAddresses(t *testing.T) {
	for _, profile := range []WindowsRuntimeProfile{WindowsInstalledProfile, WindowsPortableMixedProfile, WindowsPortableTUNProfile} {
		body := healthConfig(t, profile, []string{"z.example", "A.example", "suffix.example"}, []string{".suffix.example"})
		plan, err := BuildWindowsHealthPlan(body, profile, WindowsInstalledCAPath)
		if err != nil || plan.target != "https://a.example/" || plan.profile != profile {
			t.Fatalf("target=%+v, err=%v", plan, err)
		}
	}
	for _, domains := range [][]string{nil, {"suffix.example"}, {"192.0.2.1", "user@host.example", "bad.example/path", "host.example:443", "bad..example"}} {
		body := healthConfig(t, WindowsPortableMixedProfile, domains, []string{".suffix.example"})
		plan, err := BuildWindowsHealthPlan(body, WindowsPortableMixedProfile, WindowsInstalledCAPath)
		if err != nil || plan.target != "" {
			t.Fatalf("fabricated target: %+v, %v", plan, err)
		}
		if len(plan.check(context.Background(), &http.Transport{})) == 0 {
			t.Fatal("missing target appeared healthy")
		}
	}
	body := healthConfig(t, WindowsPortableMixedProfile, []string{"a.example"}, nil)
	var c singBoxConfig
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatal(err)
	}
	c.Route.Rules[0].Inbound = []string{"probe-in"}
	c.Inbounds = append(c.Inbounds, singBoxInbound{Type: "mixed", Tag: "probe-in", Listen: "127.0.0.1", ListenPort: 61801})
	body, _ = json.Marshal(c)
	plan, err := BuildWindowsHealthPlan(body, WindowsPortableMixedProfile, WindowsInstalledCAPath)
	if err != nil || plan.target != "" {
		t.Fatal("candidate probe route was treated as the user entry")
	}
}

func TestWindowsHealthHTTPSFailureAndRecovery(t *testing.T) {
	status := http.StatusOK
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer server.Close()
	plan := &WindowsHealthPlan{target: server.URL}
	transport := server.Client().Transport.(*http.Transport).Clone()
	for _, code := range []int{200, 503, 200, 403, 407} {
		status = code
		problems := plan.check(context.Background(), transport)
		if (len(problems) == 0) != (code < 500 && code != 407) {
			t.Fatalf("status %d: %v", code, problems)
		}
	}
	if got := plan.check(context.Background(), &http.Transport{}); len(got) != 1 || got[0] != "单目标探测 "+server.URL+"/：TLS 证书验证失败" {
		t.Fatalf("untrusted TLS: %v", got)
	}
}

func TestWindowsHealthDoesNotFollowRedirectOrEnvironmentProxy(t *testing.T) {
	reached := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer other.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) }))
	defer server.Close()
	t.Setenv("HTTP_PROXY", other.URL)
	t.Setenv("HTTPS_PROXY", other.URL)
	transport := mixedHealthTransport()
	proxy, err := transport.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "target.example"}})
	if err != nil || proxy.String() != "http://127.0.0.1:1080" {
		t.Fatal("Mixed read an environment proxy")
	}
	plan := &WindowsHealthPlan{target: server.URL}
	if got := plan.check(context.Background(), server.Client().Transport.(*http.Transport).Clone()); len(got) != 0 || reached {
		t.Fatalf("redirect followed: %v, %v", got, reached)
	}
}

func TestWindowsHealthTimeoutAndRedaction(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	plan := &WindowsHealthPlan{target: server.URL}
	got := plan.check(ctx, server.Client().Transport.(*http.Transport).Clone())
	if len(got) != 1 || got[0] != "单目标探测 "+server.URL+"/：HTTP 响应超时" {
		t.Fatalf("timeout: %v", got)
	}
	for _, err := range []error{&net.DNSError{Err: "secret-host-and-token", Name: "secret.example"}, errors.New("https://secret.example/token"), fmtWrappedTUNError()} {
		if got := plan.probeProblem(err, "连接"); strings.Contains(got, "secret") {
			t.Fatalf("leaked error: %s", got)
		}
	}
}

func fmtWrappedTUNError() error {
	return &net.DNSError{Err: "TUN unavailable", UnwrapErr: errTUNCapture}
}

// §16.1：真实传输失败必须保留目标和环节，路径可达与该目标的失败可同时成立。
func TestWindowsHealthDistinguishesTCPAndTLS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	plan := &WindowsHealthPlan{target: strings.Replace(plain.URL, "http:", "https:", 1)}
	got := plan.check(context.Background(), &http.Transport{})
	if len(got) != 1 || got[0] != "单目标探测 "+plan.target+"/：TLS 握手失败" {
		t.Fatalf("TLS phase missing: %v", got)
	}
	plain.Close()
	got = plan.check(context.Background(), &http.Transport{})
	if len(got) != 1 || got[0] != "单目标探测 "+plan.target+"/：TCP 连接失败" {
		t.Fatalf("TCP phase missing: %v", got)
	}
	target := &url.URL{Scheme: "https", Host: "demo.example", User: url.UserPassword("demo-user", "demo-token"), Path: "/private", RawQuery: "key=demo-secret", Fragment: "fragment"}
	plan.target = target.String()
	got = []string{plan.probeProblem(errors.New("sensitive transport details"), "TLS 握手")}
	if got[0] != "单目标探测 https://demo.example/：TLS 握手失败" {
		t.Fatalf("target metadata leaked: %v", got)
	}
}
