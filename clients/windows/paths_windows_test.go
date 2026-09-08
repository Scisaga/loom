//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/clientcore"
	"loom/internal/clientreport"
	"loom/internal/clientruntime"
)

func windowsPathControlFixture(t *testing.T) (string, *routeControl, context.CancelFunc) {
	t.Helper()
	a := managedActivationFixture(t)
	t.Cleanup(a.clear)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	root := t.TempDir()
	control := &routeControl{state: clientRuntimeState{Generation: ctx, Policy: a.Policy, Preference: a.Preference, Applied: a.Version.Snapshot, Ready: true, Exited: make(chan struct{})}}
	routeControls.Store(root, control)
	t.Cleanup(func() { routeControls.Delete(root) })
	return root, control, cancel
}

func TestWindowsPathsUseActualAgentReadback(t *testing.T) {
	root, control, _ := windowsPathControlFixture(t)
	a := managedActivationFixture(t)
	defer a.clear()
	var puts atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			puts.Add(1)
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"type": "Selector", "now": "opaque-b"})
	}))
	defer api.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer proxy.Close()
	a.AgentConfig.API = strings.TrimPrefix(api.URL, "http://")
	a.AgentConfig.Probe = strings.TrimPrefix(proxy.URL, "http://")
	state := control.snapshot()
	runtime, err := clientruntime.StartWindowsAgent(state.Generation, a.AgentConfig, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Stop()
	state.Agent = runtime
	control.update(state)
	reader := new(windowsPathReader)
	rows := reader.Read(context.Background(), root, time.Now())
	if len(rows) != 1 || rows[0].Candidate != "opaque-b" || rows[0].Chain != "本机 → demo-prefix-b → demo-exit → 目标" {
		t.Fatalf("必须映射实际读回，不沿用默认 opaque-a: %+v", rows)
	}
	if rows[0].Health != "未知" || rows[0].SelectedQuality != "未知" || rows[0].BestQuality != "未知" || strings.Contains(formatWindowsPaths(rows, true), "0 ms") {
		t.Fatalf("未完成的测量不能伪造质量: %+v", rows)
	}
	if puts.Load() != 0 {
		t.Fatal("只读展示不应写 selector")
	}
}

func TestWindowsPathsFormatServicesQualityAndReason(t *testing.T) {
	zero, p50, p95, kbps := 0, 25, 40, 800
	scope := strings.Repeat("a", 64)
	rows := windowsPathsFromReport(&clientreport.AgentState{Selections: []clientreport.AgentSelection{
		{Declaration: "demo-service-a", Candidate: "opaque-b", Chain: []string{"demo-prefix", "demo-exit"}, UpdatedAt: "2026-09-08T00:00:00Z", Reason: "改善达到切换门槛 [decision_scope=" + scope + "]", Health: &clientreport.AgentCandidateHealth{SelectedState: "success", SelectedP50MS: &p50, SelectedP95MS: &p95, BestP50MS: &zero}},
		{Declaration: "demo-service-b", Candidate: "opaque-c", Chain: []string{"demo-other"}, Reason: "当前路径发生故障", Health: &clientreport.AgentCandidateHealth{SelectedState: "degraded", SelectedKBps: &kbps}},
		{Declaration: "demo-service-c", Candidate: "opaque-direct", Reason: "直连模式；不进行 Agent 路径测量"},
	}})
	if len(rows) != 3 || rows[0].DecisionScope != scope || rows[0].Reason != "改善达到切换门槛" || rows[1].Chain != "本机 → demo-other → 目标" || rows[2].Chain != "本机 → 目标（直连）" || rows[2].Health != "未知" {
		t.Fatalf("服务路径与原因投影错误: %+v", rows)
	}
	if rows[0].SelectedQuality != "P50 25 ms · P95 40 ms" || rows[0].BestQuality != "P50 0 ms" || rows[1].SelectedQuality != "800 KB/s" || rows[1].BestQuality != "未知" || rows[1].Health != "不稳定" {
		t.Fatalf("质量必须区别无值和真实零值: %+v", rows)
	}
	compact, detail := formatWindowsPaths(rows, false), formatWindowsPaths(rows, true)
	if strings.Contains(compact, "原因：") || !strings.Contains(detail, "原因：改善达到切换门槛") || !strings.Contains(detail, "读取时间：2026-09-08T00:00:00Z") || formatWindowsPaths(nil, true) != "未连接" {
		t.Fatalf("路径详情格式不符: %s", detail)
	}
}

func TestWindowsPathReaderLimitsReadsAndDiscardsFailures(t *testing.T) {
	root, control, cancel := windowsPathControlFixture(t)
	reads := 0
	fail := false
	reader := &windowsPathReader{read: func(context.Context, clientRuntimeState, time.Time) (*clientreport.AgentState, error) {
		reads++
		if fail {
			return nil, errors.New("demo API unavailable")
		}
		return &clientreport.AgentState{Selections: []clientreport.AgentSelection{{Declaration: "demo-service", Candidate: "opaque-b", Chain: []string{"demo-prefix-b", "demo-exit"}}}}, nil
	}}
	now := time.Now()
	first := reader.Read(context.Background(), root, now)
	for i := 1; i < 10; i++ {
		if got := reader.Read(context.Background(), root, now.Add(time.Duration(i)*500*time.Millisecond)); !slices.Equal(first, got) {
			t.Fatalf("缓存读回变化: %+v", got)
		}
	}
	if reads != 1 {
		t.Fatalf("重复 UI 轮询不应逐次 GET: %d", reads)
	}
	if !reader.current(root) {
		t.Fatal("当前读回应允许发布到当前连接")
	}
	first[0].Chain = "不能改变内部快照"
	if reader.Read(context.Background(), root, now)[0].Chain == first[0].Chain {
		t.Fatal("调用方污染了缓存")
	}
	fail = true
	rows := reader.Read(context.Background(), root, now.Add(windowsPathReadInterval))
	if len(rows) != 1 || rows[0].Chain != "未知" || rows[0].Candidate != "" || rows[0].UpdatedAt != "" {
		t.Fatalf("读取失败不得保留上次实际路径: %+v", rows)
	}
	state := control.snapshot()
	state.Preference = clientcore.Preference{Schema: 1, Mode: clientcore.Direct}
	control.update(state)
	reader.Read(context.Background(), root, now.Add(windowsPathReadInterval+time.Millisecond))
	if reads != 3 {
		t.Fatalf("偏好变化应立即失效，不等待限速: %d", reads)
	}
	cancel()
	if reader.current(root) {
		t.Fatal("完成读回后取消也必须在 GUI 回填前被识别")
	}
	if rows := reader.Read(context.Background(), root, now.Add(windowsPathReadInterval+2*time.Millisecond)); rows != nil {
		t.Fatalf("断开后不得保留路径: %+v", rows)
	}
}

func TestWindowsPathsDiscardGenerationChangedDuringRead(t *testing.T) {
	for _, change := range []string{"cancel", "replace", "disconnect"} {
		t.Run(change, func(t *testing.T) {
			root, control, cancel := windowsPathControlFixture(t)
			reader := &windowsPathReader{read: func(ctx context.Context, state clientRuntimeState, at time.Time) (*clientreport.AgentState, error) {
				switch change {
				case "cancel":
					cancel()
				case "replace":
					next, stop := context.WithCancel(context.Background())
					t.Cleanup(stop)
					state.Generation = next
					control.update(state)
				case "disconnect":
					state.Ready = false
					control.update(state)
				}
				return &clientreport.AgentState{Selections: []clientreport.AgentSelection{{Declaration: "demo-service", Candidate: "opaque-old", Chain: []string{"demo-old"}}}}, nil
			}}
			if rows := reader.Read(context.Background(), root, time.Now()); rows != nil {
				t.Fatalf("旧代结果不能回填: %+v", rows)
			}
		})
	}
}
