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

	"loom/internal/agent"
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
	if rows[0].Health != "" || rows[0].LinkLabels != "—\n—\n—" || strings.Contains(formatWindowsPaths(rows, true), "0 ms") {
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
		{Declaration: "demo-service-a", Candidate: "opaque-b", Chain: []string{"demo-prefix", "demo-exit"}, UpdatedAt: "2026-09-08T00:00:00Z", Reason: "改善达到切换门槛 [decision_scope=" + scope + "]", Health: &clientreport.AgentCandidateHealth{SelectedState: "success", SelectedSamples: 4, Candidates: 3, RecentSuccess: 2, Unknown: 1, SelectedP50MS: &p50, SelectedP95MS: &p95, BestP50MS: &zero}},
		{Declaration: "demo-service-b", Candidate: "opaque-c", Chain: []string{"demo-other"}, Reason: "当前路径发生故障", Health: &clientreport.AgentCandidateHealth{SelectedState: "degraded", SelectedKBps: &kbps}},
		{Declaration: "demo-service-c", Candidate: "opaque-direct", Reason: "直连模式；不进行 Agent 路径测量"},
	}})
	if len(rows) != 3 || rows[0].DecisionScope != scope || rows[0].Reason != "改善达到切换门槛" || rows[1].Chain != "本机 → demo-other → 目标" || rows[2].Chain != "本机 → 目标（直连）" || rows[2].Health != "未知" {
		t.Fatalf("服务路径与原因投影错误: %+v", rows)
	}
	if rows[0].SelectedQuality != "P50（中位）25 ms · P95 40 ms" || rows[0].BestQuality != "最低中位延迟 0 ms" || rows[1].SelectedQuality != "800 KB/s" || rows[1].BestQuality != "未知" || rows[1].Health != "部分失败" {
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

// §16.1：单样本、失败样本和未知候选不能通过统计标签被包装成健康或已完成选优。
func TestWindowsPathsShowProbeCountsAndIncompleteComparison(t *testing.T) {
	latency := 37
	health := &clientreport.AgentCandidateHealth{Candidates: 12, RecentSuccess: 1, RecentFailed: 1, Unknown: 9, Stale: 1,
		SelectedState: "success", SelectedSamples: 1, SelectedP50MS: &latency, SelectedP95MS: &latency}
	rows := windowsPathsFromReport(&clientreport.AgentState{Selections: []clientreport.AgentSelection{{Declaration: "demo-service", Health: health, UpdatedAt: "demo-read-time"}}})
	row := rows[0]
	if row.Health != "单次可达" || row.SelectedQuality != "单个成功样本 37 ms" || row.MeasurementSummary != "近期探测 1 次 · 失败 0 · 已测 2/12" ||
		!strings.Contains(row.Comparison, "9 个未测，1 个已过期") || !strings.Contains(row.Comparison, "比较尚未覆盖全部候选") {
		t.Fatalf("[§16.1] 单样本或未比较边界失真：%+v", row)
	}
	if detail := formatWindowsPaths(rows, true); strings.Contains(detail, "P95") || strings.Contains(detail, "最近探测：demo-read-time") || !strings.Contains(detail, "读取时间：demo-read-time") {
		t.Fatalf("[§16.1] 单样本统计或读回时间失真：%s", detail)
	}
	health.SelectedState, health.SelectedSamples, health.SelectedFailures = "degraded", 2, 1
	row = windowsPathsFromReport(&clientreport.AgentState{Selections: []clientreport.AgentSelection{{Health: health}}})[0]
	if row.Health != "部分失败" || !strings.Contains(row.MeasurementSummary, "探测 2 次 · 失败 1") || strings.Contains(row.SelectedQuality, "P95") {
		t.Fatalf("[§16.1] 失败样本不能变成成功延迟分位：%+v", row)
	}
}

// §16.1：入口单次结果与服务器估算不能显示为整路径实测或健康绿灯。
func TestWindowsPathsDescribeEntryAndServerEvidence(t *testing.T) {
	reason := "入口与服务器分段观测估算 90 ms；未测整条业务路径"
	rows := windowsPathsFromReport(&clientreport.AgentState{Selections: []clientreport.AgentSelection{{Declaration: "demo-service", Candidate: "demo-path", Chain: []string{"demo-entry", "demo-exit"}, Reason: reason}}})
	entry, link, delta, target, rate := int64(12), int64(38), int64(3), int64(57), float64(6400000)
	applyWindowsPathMeasurements(&rows[0], []agent.ClientPathMeasurement{
		{Hop: 0, To: "demo-entry", Kind: "entry", DelayMS: &entry, Samples: 1, ObservedAt: "demo-entry-time"},
		{Hop: 1, From: "demo-entry", To: "demo-exit", Kind: "public-hysteria2", DelayMS: &link, VariationMS: &delta, RateBPS: &rate, Samples: 2, ObservedAt: "demo-link-time"},
		{Hop: 2, From: "demo-exit", To: "https://demo.example/", Kind: "target", DelayMS: &target, Samples: 2},
	})
	row := rows[0]
	if row.Health != "" || row.MeasurementSummary != "" || row.LinkLabels != "ping 12 ms\n38 ms · Δ3 ms · 6.4 Mb/s\n57 ms" {
		t.Fatalf("misleading display: %+v", row)
	}
	for _, want := range []string{"本机 → demo-entry", "demo-entry → demo-exit", "demo-link-time", "固定响应探测速率", "https://demo.example/"} {
		if !strings.Contains(formatWindowsPaths(rows, true), want) {
			t.Errorf("missing link detail %q", want)
		}
	}
	if strings.Contains(row.LinkLabels, "90") || strings.Contains(formatWindowsPaths(rows, false), "业务未测") {
		t.Fatal("reason became a measured edge or health badge")
	}
	applyWindowsPathMeasurements(&rows[0], nil)
	if rows[0].LinkLabels != "—\n—\n—" || rows[0].LinkDetails != "" {
		t.Fatal("old measurements survived empty input")
	}
}

func TestWindowsPathTargetFailuresAreAttachedToTheirOwnLink(t *testing.T) {
	row := windowsPathDisplay{Candidate: "demo-path", Chain: "本机 → demo-exit → 目标"}
	applyWindowsPathMeasurements(&row, []agent.ClientPathMeasurement{
		{Hop: 0, To: "demo-exit", Kind: "entry", Samples: 1, Failures: 1},
		{Hop: 1, From: "demo-exit", To: "https://demo.example/", Kind: "target", Samples: 2, Failures: 2, Error: "demo timeout"},
		{Hop: 1, From: "demo-exit", To: "https://missing.example/", Kind: "target"},
	})
	if row.LinkLabels != "ping 无响应\n1/2 目标有观测" || !strings.Contains(row.LinkDetails, "https://demo.example/：探测失败") || !strings.Contains(row.LinkDetails, "失败 2/2") || row.Health != "" {
		t.Fatalf("failure attributed to the entire device or wrong link: %+v", row)
	}
}
