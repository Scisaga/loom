package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"loom/internal/agent"
	"loom/internal/clientcore"
	"loom/internal/clientruntime"
)

func managedActivationFixture(t *testing.T) *clientActivation {
	t.Helper()
	body := []byte(`{
 "log":{"level":"warn"},"dns":{"servers":[{"tag":"demo-dns","address":"192.0.2.53","detour":"dns-out"}]},
 "inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30"],"auto_route":true,"stack":"system"},{"type":"mixed","tag":"in-1080","listen":"127.0.0.1","listen_port":1080},{"type":"mixed","tag":"probe-in","listen":"127.0.0.1","listen_port":61801,"users":[{"username":"demo-a","password":"demo-probe"},{"username":"demo-b","password":"demo-probe"},{"username":"demo-direct","password":"demo-probe"}]}],
 "outbounds":[{"type":"direct","tag":"dns-out"},{"type":"direct","tag":"opaque-direct"},
 {"type":"hysteria2","tag":"opaque-a","server":"192.0.2.1","server_port":443,"password":"demo-secret","tls":{"enabled":true,"server_name":"demo-exit.node.internal","certificate_path":"C:\\ProgramData\\Loom\\tls\\ca.crt","alpn":["h3"]}},
 {"type":"hysteria2","tag":"opaque-b","server":"192.0.2.2","server_port":443,"password":"demo-secret","tls":{"enabled":true,"server_name":"demo-exit.node.internal","certificate_path":"C:\\ProgramData\\Loom\\tls\\ca.crt","alpn":["h3"]}},
 {"type":"selector","tag":"opaque-service","outbounds":["opaque-a","opaque-b","opaque-direct"],"default":"opaque-a"},{"type":"block","tag":"block"}],
 "route":{"final":"block","rules":[{"inbound":["probe-in"],"auth_user":["demo-a"],"outbound":"opaque-a"},{"inbound":["probe-in"],"auth_user":["demo-b"],"outbound":"opaque-b"},{"inbound":["probe-in"],"auth_user":["demo-direct"],"outbound":"opaque-direct"},{"inbound":["tun-in","in-1080"],"outbound":"opaque-service"}]},
 "experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-api"}}}`)
	planBody := []byte(`{"schema":1,"node":"demo-windows","api":"127.0.0.1:61800","api_secret":"demo-api","probe":"127.0.0.1:61801","probe_secret":"demo-probe","declarations":[{"id":"demo-service","selector":"opaque-service","objective":"latency","targets":["http://demo-target.example/"],"tuning_period":"1s","window":"1m","min_samples":2,"stale_after":"1m","switch_threshold":0.2,"candidates":[{"tag":"opaque-a","chain":["demo-prefix-a","demo-exit"],"probe_user":"demo-a"},{"tag":"opaque-b","chain":["demo-prefix-b","demo-exit"],"probe_user":"demo-b"},{"tag":"opaque-direct","probe_user":"demo-direct"}]}]}`)
	runtime, err := clientruntime.DeriveWindowsRuntimeConfig(body, clientruntime.WindowsInstalledProfile, clientruntime.WindowsInstalledCAPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := clientruntime.BuildWindowsSelectorPlan(runtime, planBody, clientruntime.WindowsInstalledProfile, clientruntime.WindowsInstalledCAPath)
	if err != nil {
		t.Fatal(err)
	}
	a := activationFixture(t, "1")
	a.BaseConfig = runtime
	a.Policy = plan
	a.WaitForStart = true
	next, err := a.withPreference(clientcore.Preference{Schema: 1, Mode: clientcore.Auto})
	if err != nil {
		t.Fatal(err)
	}
	a.clear()
	return next
}

func TestAgentActivationModesReconnectAndCancellationBarrier(t *testing.T) {
	var mu sync.Mutex
	current := "opaque-a"
	puts := 0
	planes := 0
	crashes := make(chan struct{}, 1)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(map[string]string{"type": "Selector", "now": current})
			return
		}
		puts++
		t.Error("canceled probe generation sent PUT")
		w.WriteHeader(204)
	}))
	defer api.Close()
	entered := make(chan struct{}, 8)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer proxy.Close()
	start := func(ctx context.Context, _ string, body []byte, _ string, _ clientruntime.WindowsRuntimeProfile, _ string, started func()) error {
		mu.Lock()
		planes++
		if planes != 1 {
			t.Error("overlapping data planes")
		}
		var sb struct {
			Outbounds []struct {
				Type    string
				Default string
			}
		}
		_ = json.Unmarshal(body, &sb)
		for _, o := range sb.Outbounds {
			if o.Type == "selector" {
				current = o.Default
			}
		}
		mu.Unlock()
		started()
		var planeErr error
		select {
		case <-ctx.Done():
		case <-crashes:
			planeErr = errors.New("demo unexpected sing-box exit")
		}
		mu.Lock()
		planes--
		mu.Unlock()
		return planeErr
	}
	wait := func(ctx context.Context, cfg *agent.Config) error {
		cfg.API = strings.TrimPrefix(api.URL, "http://")
		cfg.Probe = strings.TrimPrefix(proxy.URL, "http://")
		return clientruntime.WaitWindowsAgentAPI(ctx, cfg)
	}
	manager, err := newActivationManager(func(context.Context, *clientActivation) error { return nil }, func(ctx context.Context, a *clientActivation) error {
		if a.Version.Snapshot == "222222222222" {
			return errors.New("demo replacement startup failure")
		}
		return runAgentDataPlane(ctx, a, start, wait)
	}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := managedActivationFixture(t)
	if _, err := manager.Replace(ctx, a); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
		t.Fatal("client sent an excluded business probe")
	default:
	}
	previous := manager.active.spec.AgentRuntime
	fixed, err := manager.active.spec.withPreference(clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-exit"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Replace(ctx, fixed); err != nil {
		t.Fatal(err)
	}
	select {
	case <-previous.Done():
	default:
		t.Fatal("new configuration activated before old Agent exited")
	}
	if len(fixed.AgentConfig.Declarations[0].Candidates) != 2 {
		t.Fatal("fixed exit lost prefix candidates")
	}
	select {
	case <-entered:
		t.Fatal("client sent an excluded business probe")
	default:
	}
	previous = manager.active.spec.AgentRuntime
	crashes <- struct{}{}
	activeErr := <-manager.Done()
	if err := manager.Recover(ctx, activeErr); err != nil {
		t.Fatal(err)
	}
	select {
	case <-previous.Done():
	default:
		t.Fatal("crash recovery skipped old Agent exit")
	}
	if manager.active.spec.AgentRuntime == previous || manager.active.spec.Preference.Mode != clientcore.FixedExit {
		t.Fatal("crash recovery reused a canceled Agent or lost the fixed exit")
	}
	select {
	case <-entered:
		t.Fatal("client sent an excluded business probe")
	default:
	}
	previous = manager.active.spec.AgentRuntime
	rejected, err := manager.active.spec.withPreference(manager.active.spec.Preference)
	if err != nil {
		t.Fatal(err)
	}
	rejected.Version.Snapshot = "222222222222"
	rejected.Version.ConfigSHA256 = strings.Repeat("2", 64)
	if _, err := manager.Replace(ctx, rejected); err == nil {
		t.Fatal("startup failure accepted")
	}
	select {
	case <-previous.Done():
	default:
		t.Fatal("rollback skipped old Agent exit")
	}
	if manager.active.spec.Version.Snapshot == "222222222222" || manager.active.spec.Preference.Mode != clientcore.FixedExit || len(manager.active.spec.AgentConfig.Declarations[0].Candidates) != 2 {
		t.Fatal("rollback lost paired config or fixed exit")
	}
	select {
	case <-entered:
		t.Fatal("client sent an excluded business probe")
	default:
	}
	previous = manager.active.spec.AgentRuntime
	direct, err := manager.active.spec.withPreference(clientcore.Preference{Schema: 1, Mode: clientcore.Direct})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Replace(ctx, direct); err != nil {
		t.Fatal(err)
	}
	select {
	case <-previous.Done():
	default:
		t.Fatal("Direct did not join Agent")
	}
	if manager.active.spec.AgentRuntime != nil {
		t.Fatal("Direct retained an Agent")
	}
	mu.Lock()
	got := current
	mu.Unlock()
	if got != "opaque-direct" {
		t.Fatal("Direct did not activate authorized direct behavior")
	}
	auto, err := manager.active.spec.withPreference(clientcore.Preference{Schema: 1, Mode: clientcore.Auto})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Replace(ctx, auto); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
		t.Fatal("client sent an excluded business probe")
	default:
	}
	cancel()
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if puts != 0 || planes != 0 {
		t.Fatal("old generation wrote or survived stop")
	}
}

func TestPreferencePersistenceFailureRestoresPairedActivation(t *testing.T) {
	a := managedActivationFixture(t)
	harness := &activationHarness{}
	manager := newActivationHarnessManager(t, harness)
	defer manager.Stop()
	a.WaitForStart = false
	if _, err := manager.Replace(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	original := manager.active.spec
	control := &routeControl{persist: func(clientcore.Preference) error { return errors.New("demo disk failure") }}
	err := applyRouteRequest(context.Background(), manager, control, routeRequest{preference: clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-exit"}})
	if err == nil {
		t.Fatal("failed persistence was accepted")
	}
	if manager.active.spec.Preference.Mode != clientcore.Auto || manager.active.spec.Version != original.Version || len(manager.active.spec.AgentConfig.Declarations[0].Candidates) != 3 {
		t.Fatal("failed preference did not restore sing-box and Agent pair")
	}
}
