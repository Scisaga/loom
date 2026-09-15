package clientruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/agent"
	"loom/internal/model"
)

func demoUnderlay(key, source string) windowsUnderlaySnapshot {
	return windowsUnderlaySnapshot{key: key, routes: []windowsUnderlayRoute{{
		prefix: netip.MustParsePrefix("0.0.0.0/0"), source: source, index: 1,
	}}}
}

func receiveUnderlay[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("等待底层网络回归事件超时")
		var zero T
		return zero
	}
}

func TestWindowsUnderlayEventsPreserveBudgetAndCancelOutsideCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	snapshot := demoUnderlay("demo-network-a", "192.0.2.10")
	var readErr error
	var notify func()
	stopped := make(chan struct{})
	monitor := newWindowsUnderlayMonitor(ctx, func() (windowsUnderlaySnapshot, error) {
		if notify == nil {
			t.Error("读取快照早于注册，可能遗漏启动期间的切网")
		}
		return snapshot, readErr
	}, func(callback func()) (func(), error) {
		notify = callback
		return func() {
			// 模拟取消 API 等待最后一个回调；持有 monitor 锁取消会死锁。
			notify()
			close(stopped)
		}, nil
	})
	base := agent.ClientOptions{Entries: []agent.ClientEntry{{Node: "demo-entry", Address: "192.0.2.1"}}}
	first, changed := monitor.inputs(base)
	if first.EntryProbesUnavailable || first.Entries[0].Source != "192.0.2.10" {
		t.Fatal("初始源接口未绑定")
	}
	for range 3 {
		notify() // 同快照的路由/地址/网卡通知不能成为三次新预算。
	}
	select {
	case <-changed:
		t.Fatal("相同快照推进了网络代")
	default:
	}
	readErr = errors.New("demo read failure")
	notify()
	receiveUnderlay(t, changed)
	unknown, changed := monitor.inputs(base)
	if !unknown.EntryProbesUnavailable || unknown.UnderlayGeneration != first.UnderlayGeneration {
		t.Fatal("读取失败伪造了新代或继续使用旧证据")
	}
	readErr = nil
	notify()
	receiveUnderlay(t, changed)
	restored, changed := monitor.inputs(base)
	if restored.EntryProbesUnavailable || restored.UnderlayGeneration != first.UnderlayGeneration {
		t.Fatal("同快照恢复重置了预算")
	}
	snapshot = windowsUnderlaySnapshot{key: "demo-no-network"}
	notify()
	receiveUnderlay(t, changed)
	offline, changed := monitor.inputs(base)
	if !offline.EntryProbesUnavailable {
		t.Fatal("离线仍授权入口探测")
	}
	snapshot = demoUnderlay("demo-network-a", "192.0.2.10")
	notify()
	receiveUnderlay(t, changed)
	returned, _ := monitor.inputs(base)
	if returned.UnderlayGeneration == first.UnderlayGeneration {
		t.Fatal("断网后回到相同地址复用了断开前的网络代")
	}
	cancel()
	receiveUnderlay(t, stopped)
}

func TestWindowsUnderlayRegistrationFailureDoesNotAuthorizeProbes(t *testing.T) {
	monitor := newWindowsUnderlayMonitor(context.Background(), func() (windowsUnderlaySnapshot, error) {
		t.Fatal("未建立事件订阅时读取了可授权快照")
		return windowsUnderlaySnapshot{}, nil
	}, func(func()) (func(), error) { return nil, errors.New("demo registration failure") })
	inputs, _ := monitor.inputs(agent.ClientOptions{})
	if !inputs.EntryProbesUnavailable {
		t.Fatal("订阅失败仍授权探测")
	}
	_, cfg := agentNetworkFixture(t)
	runtime, err := StartWindowsAgent(context.Background(), cfg, t.TempDir(), WindowsAgentInputs{Underlay: monitor})
	if err != nil {
		t.Fatalf("订阅失败阻止了已验证数据面中的 Agent 激活: %v", err)
	}
	if err := runtime.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsUnderlayWaitsForPreviousSelectorWriterBeforeReplacement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	snapshot := demoUnderlay("demo-a", "192.0.2.10")
	var notify func()
	monitor := newWindowsUnderlayMonitor(ctx, func() (windowsUnderlaySnapshot, error) { return snapshot, nil },
		func(callback func()) (func(), error) { notify = callback; return func() {}, nil })
	started := make(chan agent.ClientOptions, 3)
	stopping := make(chan struct{}, 3)
	release := make(chan struct{}, 3)
	run := func(ctx context.Context, _ *agent.Config, options agent.ClientOptions) error {
		started <- options
		<-ctx.Done()
		stopping <- struct{}{}
		<-release // 模拟已经发起的 selector HTTP 调用完成取消。
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- runWindowsClientUnderlay(ctx, nil, agent.ClientOptions{}, monitor, run) }()
	first := receiveUnderlay(t, started)
	if first.ResetState {
		t.Fatal("普通 activation 重置了既有决定状态")
	}
	snapshot = demoUnderlay("demo-b", "192.0.2.20")
	notify()
	receiveUnderlay(t, stopping)
	select {
	case <-started:
		t.Fatal("旧 selector writer 未结束时启动了新回路")
	default:
	}
	release <- struct{}{}
	second := receiveUnderlay(t, started)
	if !second.ResetState || second.UnderlayGeneration == first.UnderlayGeneration {
		t.Fatal("新代未撤销旧代决定")
	}
	snapshot = demoUnderlay("demo-a", "192.0.2.10")
	notify()
	receiveUnderlay(t, stopping)
	release <- struct{}{}
	third := receiveUnderlay(t, started)
	if third.UnderlayGeneration == first.UnderlayGeneration || third.UnderlayGeneration == second.UnderlayGeneration {
		t.Fatal("A→B→A 必须是三个 OS 网络代")
	}
	cancel()
	receiveUnderlay(t, stopping)
	release <- struct{}{}
	if err := receiveUnderlay(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsUnderlaySourceUsesPhysicalRouteAndStableMetrics(t *testing.T) {
	snapshot := demoUnderlay("demo-network", "192.0.2.10")
	snapshot.routes[0].metric = 20
	snapshot.routes = append(snapshot.routes,
		windowsUnderlayRoute{prefix: netip.MustParsePrefix("0.0.0.0/0"), source: "192.0.2.20", metric: 10, index: 2},
		windowsUnderlayRoute{prefix: netip.MustParsePrefix("198.51.100.0/24"), source: "192.0.2.10", metric: 100, index: 1})
	if snapshot.source("203.0.113.1") != "192.0.2.20" || snapshot.source("entry.example") != "192.0.2.20" ||
		snapshot.source("198.51.100.1") != "192.0.2.10" || snapshot.source("2001:db8::1") != "" {
		t.Fatal("源接口未按物理路由前缀和有效 metric 选择")
	}
}

func TestWindowsUnderlayLiveAgentSwitchesWithoutRepeatedOrBusinessProbes(t *testing.T) {
	service, stopService := context.WithCancel(context.Background())
	defer stopService()
	var snapshotMu sync.Mutex
	snapshot := demoUnderlay("demo-network-a", "192.0.2.10")
	var notify func()
	monitor := newWindowsUnderlayMonitor(service, func() (windowsUnderlaySnapshot, error) {
		snapshotMu.Lock()
		defer snapshotMu.Unlock()
		return snapshot, nil
	}, func(callback func()) (func(), error) { notify = callback; return func() {}, nil })
	registry, err := agent.NewEntryProbeRegistry(service)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	current := "demo-a"
	selected := make(chan string, 16)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPut {
			var body struct{ Name string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			current = body.Name
			selected <- current
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"type": "Selector", "now": current})
	}))
	defer api.Close()
	var businessRequests atomic.Int64
	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		businessRequests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer forbidden.Close()
	cfg := &agent.Config{Node: "demo-client", API: strings.TrimPrefix(api.URL, "http://"),
		Probe: strings.TrimPrefix(forbidden.URL, "http://"), ObservationStale: "10m", Declarations: []agent.Decl{{
			ID: "demo-service", Selector: "demo-service", Objective: model.Latency, MinSamples: 999,
			TuningPeriod: "1s", Window: "1h", StaleAfter: "1h", Targets: []string{forbidden.URL},
			Candidates: []agent.Cand{{Tag: "demo-a", Chain: []string{"demo-entry-a", "demo-exit"}},
				{Tag: "demo-b", Chain: []string{"demo-entry-b", "demo-exit"}}},
		}}}
	cache, err := agent.NewObservationCache(cfg)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan agent.ClientEntry, 16)
	release := make(chan struct{}, 16)
	measurements := make(chan []agent.ClientPathMeasurement, 16)
	base := agent.ClientOptions{StatePath: filepath.Join(t.TempDir(), "state.json"), Observations: cache, ProbeRegistry: registry,
		Entries: []agent.ClientEntry{{Node: "demo-entry-a", Address: "192.0.2.1"},
			{Node: "demo-entry-a", Address: "192.0.2.1"}, {Node: "demo-entry-b", Address: "192.0.2.2"}},
		OnEntries: func(values []agent.ClientPathMeasurement) { measurements <- values },
		Probe: func(ctx context.Context, entry agent.ClientEntry) (time.Duration, error) {
			started <- entry
			select {
			case <-release:
			case <-ctx.Done():
				return 0, ctx.Err()
			}
			if entry.Source == "192.0.2.10" && entry.Node == "demo-entry-b" || entry.Source == "192.0.2.20" && entry.Node == "demo-entry-a" {
				return time.Millisecond, nil
			}
			return 50 * time.Millisecond, nil
		}}
	startAgent := func(options agent.ClientOptions) (context.CancelFunc, <-chan error) {
		ctx, cancel := context.WithCancel(service)
		done := make(chan error, 1)
		go func() { done <- runWindowsClientUnderlay(ctx, cfg, options, monitor, agent.RunClient) }()
		return cancel, done
	}
	stop, done := startAgent(base)
	defer func() { stop() }()
	for range 2 {
		entry := receiveUnderlay(t, started) // 尚未释放任何结果：证明去重后并行。
		if entry.Source != "192.0.2.10" {
			t.Fatal("首代探测绑定错误源接口")
		}
	}
	release <- struct{}{}
	release <- struct{}{}
	if receiveUnderlay(t, selected) != "demo-b" {
		t.Fatal("首次入口结果未影响真实 selector")
	}
	// 持续连接时注入真实网络快照变化；数据面 HTTP 服务与观测 cache 始终相同。
	snapshotMu.Lock()
	snapshot = demoUnderlay("demo-network-b", "192.0.2.20")
	snapshotMu.Unlock()
	notify()
	for range 2 {
		entry := receiveUnderlay(t, started)
		if entry.Source != "192.0.2.20" {
			t.Fatal("运行中切网继续使用旧源接口")
		}
	}
	state, err := agent.ReadState(base.StatePath)
	if err != nil || state == nil || len(state.Selections) != 0 {
		t.Fatal("新代结果到达前仍展示旧代决定")
	}
	release <- struct{}{}
	release <- struct{}{}
	if receiveUnderlay(t, selected) != "demo-a" {
		t.Fatal("新代入口结果未替换正在运行的 selector 选择")
	}
	stop()
	if err := receiveUnderlay(t, done); err != nil {
		t.Fatal(err)
	}
	// profile/配置重连增加候选，也只能复用该网络代第一次冻结的入口。
	cfg.Declarations[0].Candidates = append(cfg.Declarations[0].Candidates, agent.Cand{Tag: "demo-c", Chain: []string{"demo-entry-c", "demo-exit"}})
	base.Entries = append(base.Entries, agent.ClientEntry{Node: "demo-entry-c", Address: "192.0.2.3"})
	for len(measurements) > 0 {
		<-measurements
	}
	stop, done = startAgent(base)
	var values []agent.ClientPathMeasurement
	for len(values) == 0 {
		values = receiveUnderlay(t, measurements)
	}
	if len(values) != 3 || values[2].Samples != 0 || values[2].DelayMS != nil {
		t.Fatal("同代新增入口被主动探测或伪造了观测")
	}
	notify() // 相同快照通知不能重启回路或追加预算。
	stop()
	if err := receiveUnderlay(t, done); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
		t.Fatal("同代重连/配置更新/OS 重复通知触发了额外探测")
	default:
	}
	if businessRequests.Load() != 0 {
		t.Fatal("新增了业务路径探测")
	}
}
