//go:build windows

package clientruntime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/agent"
	"loom/internal/clientcore"
	"loom/internal/measure"
)

// §5.5、§7.3.3：使用官方数据面的真实 TLS 两跳，覆盖模拟 Clash API 无法证明的路径执行。
// 测试只绑定回环地址，不创建 TUN、改系统路由或读取已加入身份。
func TestOfficialWindowsAgentSwitchesCompleteFixedExitPaths(t *testing.T) {
	executable := os.Getenv("LOOM_SING_BOX_EXECUTABLE")
	if executable == "" {
		t.Skip("set LOOM_SING_BOX_EXECUTABLE for the native shared Agent path test")
	}
	for _, address := range []string{"127.0.0.1:1080", "127.0.0.1:61800", "127.0.0.1:61801"} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Skipf("managed loopback listener is already occupied: %s", address)
		}
		_ = listener.Close()
	}
	root := t.TempDir()
	caPath, keyPath := nativeAgentTLS(t, root)
	firstHop, lastHop := nativeAgentProxyServer(t, executable, root, caPath, keyPath)
	slow, slowCount, _ := nativeAgentBridge(t, firstHop, 200*time.Millisecond)
	fast, fastCount, failFast := nativeAgentBridge(t, firstHop, 0)
	exit, exitCount, _ := nativeAgentBridge(t, lastHop, 0)
	var targetRequests atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/service" {
			t.Error("probe did not use the declared Service target")
		}
		targetRequests.Add(1)
		_, _ = io.WriteString(w, "demo full path response")
	}))
	defer target.Close()
	otherTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "demo second service response")
	}))
	defer otherTarget.Close()

	body, planBody := pathPlanFixture(t)
	var sb singBoxConfig
	var cfg agent.Config
	if err := json.Unmarshal(body, &sb); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(planBody, &cfg); err != nil {
		t.Fatal(err)
	}
	// §7.3：两条原本独立的 Service 规则故意指向不可达候选，统一路径必须覆盖实际请求。
	for i, targetURL := range []string{target.URL, otherTarget.URL} {
		u, _ := url.Parse(targetURL)
		port, _ := strconv.Atoi(u.Port())
		name := "demo-service-" + strconv.Itoa(i)
		candidate := agent.Cand{Tag: "opaque:" + name, Chain: []string{"demo-other"}, ProbeUser: name + "-probe"}
		d := cfg.Declarations[0]
		d.ID, d.Selector, d.Targets, d.Candidates = name, "opaque:selector-"+name, []string{targetURL + "/service"}, []agent.Cand{candidate}
		cfg.Declarations = append(cfg.Declarations, d)
		outbound := sb.Outbounds[3]
		outbound.Tag = candidate.Tag
		sb.Outbounds = append(sb.Outbounds, outbound, singBoxOutbound{Type: "selector", Tag: d.Selector, Default: candidate.Tag, Outbounds: []string{candidate.Tag}})
		sb.Inbounds[0].Users = append(sb.Inbounds[0].Users, singBoxUser{Username: candidate.ProbeUser, Password: cfg.ProbeSecret})
		sb.Route.Rules = append([]singBoxRule{
			{Inbound: []string{"probe-in"}, AuthUser: []string{candidate.ProbeUser}, Outbound: candidate.Tag},
			{Inbound: []string{"tun-in", "in-1080"}, Domain: []string{u.Hostname()}, Port: []int{port}, Outbound: d.Selector},
		}, sb.Route.Rules...)
	}
	proxy := func(tag, address, detour string) singBoxOutbound {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatal(err)
		}
		n, err := strconv.Atoi(port)
		if err != nil {
			t.Fatal(err)
		}
		return singBoxOutbound{Type: "trojan", Tag: tag, Server: host, ServerPort: n,
			Password: "demo-password", Detour: detour, TLS: &singBoxTLS{Enabled: true,
				ServerName: "demo-proxy.node.internal", CertificatePath: WindowsInstalledCAPath, ALPN: []string{"http/1.1"}}}
	}
	for i, outbound := range sb.Outbounds {
		switch outbound.Tag {
		case "opaque:a@slow":
			sb.Outbounds[i] = proxy(outbound.Tag, exit, "demo-first-a")
		case "opaque:z@fast":
			sb.Outbounds[i] = proxy(outbound.Tag, exit, "demo-first-b")
		}
	}
	sb.Outbounds = append(sb.Outbounds, proxy("demo-first-a", slow, ""), proxy("demo-first-b", fast, ""))
	cfg.Declarations[0].Targets = []string{target.URL + "/service"}
	cfg.Declarations[0].MinSamples = 3
	body, err := json.Marshal(sb)
	if err != nil {
		t.Fatal(err)
	}
	planBody, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := DeriveWindowsRuntimeConfig(body, WindowsPortableMixedProfile, caPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildWindowsSelectorPlan(runtime, planBody, WindowsPortableMixedProfile, caPath)
	if err != nil {
		t.Fatal(err)
	}
	filtered, active, err := plan.Derive(runtime, clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-exit"})
	if err != nil {
		t.Fatal(err)
	}
	if len(active.Declarations) != 1 || active.Declarations[0].Selector != cfg.Declarations[0].Selector {
		t.Fatal("[§7.3] 固定出口仍启动了独立的 Service 决策")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	done := make(chan error, 1)
	go func() {
		done <- RunWindowsDataPlaneProfile(ctx, executable, filtered, filepath.Join(root, "runtime"), WindowsPortableMixedProfile, caPath)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	if err := WaitWindowsAgentAPI(ctx, active); err != nil {
		t.Fatal(err)
	}
	dir, err := newProtectedAgentDir(filepath.Join(root, "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	opts := agent.Options{StatePath: filepath.Join(dir, "state.json"), MeasurementPath: filepath.Join(dir, "measurements.jsonl"), EventsPath: filepath.Join(dir, "events.jsonl"), Once: true, Log: io.Discard}
	for round := 0; round < 3; round++ {
		if err := agent.Run(ctx, active, opts); err != nil {
			t.Fatal(err)
		}
		actual, err := selectorReadback(ctx, active, active.Declarations[0].Selector)
		if err != nil {
			t.Fatal(err)
		}
		want := "opaque:a@slow"
		if round == 2 {
			want = "opaque:z@fast"
		}
		if actual != want {
			t.Fatalf("round %d actual selector = %q, want %q", round+1, actual, want)
		}
		state, err := agent.ReadState(opts.StatePath)
		if err != nil || state == nil || len(state.Selections) != 1 {
			t.Fatalf("missing actual Agent state: %v", err)
		}
		s := state.Selections[0]
		if s.Candidate != actual || len(s.Chain) != 2 || s.Chain[1] != "demo-exit" {
			t.Fatal("Agent state does not bind actual two-hop fixed exit")
		}
		if round == 2 && (!slices.Equal(s.Chain, []string{"demo-prefix-b", "demo-exit"}) || s.Health == nil || s.Health.SelectedP50MS == nil || s.Health.BestP50MS == nil || s.Health.SelectedSamples < 3 || s.Reason == "" || len(s.DecisionScope) != 64) {
			t.Fatal("winning real path lost selected/best quality, reason or decision scope")
		}
	}
	ms, err := measure.Load(opts.MeasurementPath)
	if err != nil || len(ms) != 6 || targetRequests.Load() != 6 {
		t.Fatalf("complete path probes: measurements=%d, target requests=%d, err=%v", len(ms), targetRequests.Load(), err)
	}
	for _, m := range ms {
		if m.Target != target.URL+"/service" || m.Kind != measure.Active {
			t.Fatal("measurement did not come from the actual Service target")
		}
	}
	// §7.3.1：用户入口也必须随真实 selector 切到同一获胜前缀，不能只改变报告。
	a, b, e := slowCount.Load(), fastCount.Load(), exitCount.Load()
	if a != 3 || b != 3 || e != 6 {
		t.Fatalf("two-hop traversal counts = %d/%d/%d", a, b, e)
	}
	u, _ := url.Parse("http://127.0.0.1:1080")
	transport := &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, targetURL := range []string{target.URL, otherTarget.URL} {
		resp, err := client.Get(targetURL + "/service")
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatal("[§7.3] Service 实际请求没有进入统一上网路径")
		}
	}
	if slowCount.Load() != a || fastCount.Load() != b+2 || exitCount.Load() != e+2 {
		t.Fatal("[§7.3] 两个 Service 的实际请求没有使用同一获胜前缀和固定末跳")
	}
	// §5.5：现任前缀真实断开后，继续使用同一窗口和配置，由既有失败率排序完成切换。
	failFast.Store(true)
	if err := agent.Run(ctx, active, opts); err != nil {
		t.Fatal(err)
	}
	actual, err := selectorReadback(ctx, active, active.Declarations[0].Selector)
	if err != nil || actual != "opaque:a@slow" {
		t.Fatalf("failed current prefix did not switch to the surviving path: %q, %v", actual, err)
	}
	state, err := agent.ReadState(opts.StatePath)
	if err != nil || state == nil || len(state.Selections) != 1 {
		t.Fatalf("missing failure-switch state: %v", err)
	}
	s := state.Selections[0]
	if s.Candidate != actual || !slices.Equal(s.Chain, []string{"demo-prefix-a", "demo-exit"}) || s.Reason == "" || s.Health == nil || s.Health.RecentDegraded != 1 || s.Health.SelectedState != "success" {
		t.Fatal("failure switch lost actual fixed-exit chain, failure evidence or reason")
	}
}

func nativeAgentTLS(t *testing.T, root string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-proxy.node.internal"},
		DNSNames: []string{"demo-proxy.node.internal"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	if err := os.MkdirAll(filepath.Join(root, "tls"), 0700); err != nil {
		t.Fatal(err)
	}
	caPath, keyPath := filepath.Join(root, "tls", "ca.crt"), filepath.Join(root, "tls", "demo-key.pem")
	for path, block := range map[string]*pem.Block{caPath: {Type: "CERTIFICATE", Bytes: der}, keyPath: {Type: "PRIVATE KEY", Bytes: private}} {
		body := pem.EncodeToMemory(block)
		err := os.WriteFile(path, body, 0600)
		clear(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	return caPath, keyPath
}

func nativeAgentProxyServer(t *testing.T, executable, root, caPath, keyPath string) (string, string) {
	t.Helper()
	var addresses []string
	var inbounds []map[string]any
	for _, tag := range []string{"demo-first", "demo-last"} {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addresses = append(addresses, l.Addr().String())
		port := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		inbounds = append(inbounds, map[string]any{"type": "trojan", "tag": tag, "listen": "127.0.0.1", "listen_port": port,
			"users": []map[string]string{{"name": "demo-user", "password": "demo-password"}},
			"tls":   map[string]any{"enabled": true, "certificate_path": caPath, "key_path": keyPath, "alpn": []string{"http/1.1"}}})
	}
	body, err := json.Marshal(map[string]any{"log": map[string]string{"level": "error"}, "inbounds": inbounds,
		"outbounds": []map[string]string{{"type": "direct", "tag": "direct"}}, "route": map[string]string{"final": "direct"}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "demo-proxies.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "run", "-c", path)
	configureRunCommand(command)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	guard, err := attachChildGuard(command.Process)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guard.Terminate(); _ = command.Wait(); _ = guard.Close() })
	deadline := time.Now().Add(5 * time.Second)
	for _, address := range addresses {
		for {
			c, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
			if err == nil {
				_ = c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("official local proxy did not start")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return addresses[0], addresses[1]
}

func nativeAgentBridge(t *testing.T, upstream string, delay time.Duration) (string, *atomic.Int64, *atomic.Bool) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var count atomic.Int64
	var failed atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			in, err := l.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			if failed.Load() {
				_ = in.Close()
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer in.Close()
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
				out, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstream)
				if err != nil {
					return
				}
				defer out.Close()
				stop := context.AfterFunc(ctx, func() { _ = in.Close(); _ = out.Close() })
				defer stop()
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(out, in); _ = out.Close(); close(copied) }()
				_, _ = io.Copy(in, out)
				_ = in.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() { cancel(); _ = l.Close(); wg.Wait() })
	return l.Addr().String(), &count, &failed
}
