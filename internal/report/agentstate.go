package report

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"time"
)

// 与 internal/agent.StatePath 的线格式约定。report 不能 import agent：agent
// 本身要 import report 读取观测，反向依赖会形成环。
func readAgentState(path string) (*AgentState, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st AgentState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	sort.Slice(st.Selections, func(i, j int) bool {
		a, b := st.Selections[i], st.Selections[j]
		if a.Declaration != b.Declaration {
			return a.Declaration < b.Declaration
		}
		if a.Selector != b.Selector {
			return a.Selector < b.Selector
		}
		return a.Candidate < b.Candidate
	})
	return &st, nil
}

const AgentStateStaleAfter = 30 * time.Minute

func validateAgentState(st *AgentState, node string, now time.Time) []string {
	if st == nil {
		return nil
	}
	var out []string
	if st.Node == "" || st.Node != node {
		out = append(out, "Agent 状态节点与 report 节点不一致")
	}
	if v := st.ComponentVersion; len(v) > 64 || strings.TrimSpace(v) != v || strings.ContainsAny(v, "\r\n\x00") {
		out = append(out, "Agent component_version 非法")
	}
	checkTime := func(label, raw string) {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			out = append(out, label+"时间无效:"+raw)
			return
		}
		age := now.UTC().Sub(t.UTC())
		if age > AgentStateStaleAfter {
			out = append(out, label+"已过期:"+raw)
		} else if age < -2*time.Minute {
			out = append(out, label+"来自未来:"+raw)
		}
	}
	checkTime("Agent 状态", st.TS)
	for _, s := range st.Selections {
		if s.Declaration == "" || s.Selector == "" || s.Candidate == "" {
			out = append(out, "Agent 选择缺 declaration/selector/candidate")
		}
		checkTime("Agent 选择 "+s.Declaration, s.UpdatedAt)
		for _, problem := range validateAgentCandidateHealth(s.Health) {
			out = append(out, "Agent 候选健康 "+s.Declaration+":"+problem)
		}
	}
	return out
}

// validateAgentStateForConfig 在通用线格式检查之外，核对“这份配置要求 Agent
// 管哪些 declaration”。只遍历实际状态会产生一个危险真空：某个 tick 永久
// 失败后，该 declaration 会从状态和界面一起消失，却没人报错。
func validateAgentStateForConfig(st *AgentState, cfg *Config, now time.Time) []string {
	if cfg == nil {
		return validateAgentState(st, "", now)
	}
	out := validateAgentState(st, cfg.Node, now)
	expected := map[string]bool{}
	for _, route := range cfg.ExpectedRoutes {
		if route.Access == cfg.Node && route.Declaration != "" {
			expected[route.Declaration] = true
		}
	}
	// 没有本机 Agent workload 的服务器节点不需要 selections；ExpectedRoutes
	// 同时携带全网其他接入节点的候选，必须按 Access 过滤。
	if len(expected) == 0 && cfg.AgentState == "" && cfg.ExpectedComponents.Agent == "" {
		return out
	}
	if st == nil {
		if len(expected) > 0 || cfg.AgentState != "" || cfg.ExpectedComponents.Agent != "" {
			out = append(out, "Agent 状态不存在，缺少全部期望 declaration")
		}
		return out
	}
	actual := map[string]bool{}
	for _, selection := range st.Selections {
		id := selection.Declaration
		if actual[id] {
			out = append(out, "Agent 状态重复 declaration:"+id)
		}
		actual[id] = true
		if len(expected) > 0 && !expected[id] {
			out = append(out, "Agent 状态含非期望 declaration:"+id)
		}
		// component_version 非空表示写状态的 Agent 已声明支持新版协议；这时
		// Health=nil 不再是“旧版兼容”，而是探测半途失败留下的假绿窗口。
		if st.ComponentVersion != "" && selection.Health == nil {
			out = append(out, "Agent declaration "+id+" 未上报候选健康")
		}
	}
	for id := range expected {
		if !actual[id] {
			out = append(out, "Agent 状态缺少期望 declaration:"+id)
		}
	}
	sort.Strings(out)
	return out
}

func validateAgentCandidateHealth(h *AgentCandidateHealth) []string {
	if h == nil { // 旧 agent-state 兼容；缺失不等于健康。
		return nil
	}
	var out []string
	if h.Candidates <= 0 {
		out = append(out, "candidates 必须为正")
	}
	counts := []struct {
		name string
		v    int
	}{
		{"recent_success", h.RecentSuccess},
		{"recent_degraded", h.RecentDegraded},
		{"recent_failed", h.RecentFailed},
		{"stale", h.Stale},
		{"unknown", h.Unknown},
	}
	var sum int64
	for _, c := range counts {
		if c.v < 0 || c.v > h.Candidates {
			out = append(out, c.name+" 超出 candidates 边界")
		}
		sum += int64(c.v)
	}
	if sum != int64(h.Candidates) {
		out = append(out, "五类计数之和不等于 candidates")
	}
	if h.SelectedSamples < 0 || h.SelectedFailures < 0 || h.SelectedFailures > h.SelectedSamples {
		out = append(out, "selected samples/failures 非法")
	}
	latencyOK := func(name string, v *int) {
		if v != nil && *v < 0 {
			out = append(out, name+" 不能为负")
		}
	}
	latencyOK("selected_p50_ms", h.SelectedP50MS)
	latencyOK("selected_p95_ms", h.SelectedP95MS)
	latencyOK("best_p50_ms", h.BestP50MS)
	throughputOK := func(name string, v *int) {
		if v != nil && *v <= 0 {
			out = append(out, name+" 必须为正")
		}
	}
	throughputOK("selected_kbps", h.SelectedKBps)
	throughputOK("best_kbps", h.BestKBps)
	if h.SelectedP50MS != nil && h.SelectedP95MS != nil && *h.SelectedP95MS < *h.SelectedP50MS {
		out = append(out, "selected_p95_ms 小于 selected_p50_ms")
	}
	if h.SelectedP50MS != nil && h.BestP50MS != nil && *h.BestP50MS > *h.SelectedP50MS {
		out = append(out, "best_p50_ms 大于 selected_p50_ms")
	}
	if h.SelectedKBps != nil && h.BestKBps == nil {
		out = append(out, "有 selected_kbps 却缺 best_kbps")
	} else if h.SelectedKBps != nil && h.BestKBps != nil && *h.BestKBps < *h.SelectedKBps {
		out = append(out, "best_kbps 小于 selected_kbps")
	}

	usable := h.RecentSuccess + h.RecentDegraded
	if usable > 0 && h.BestP50MS == nil {
		out = append(out, "有近期成功候选却缺 best_p50_ms")
	} else if usable == 0 && h.BestP50MS != nil {
		out = append(out, "没有近期成功候选却带 best_p50_ms")
	}
	if usable == 0 && h.BestKBps != nil {
		out = append(out, "没有近期成功候选却带 best_kbps")
	}
	switch h.SelectedState {
	case "success":
		if h.RecentSuccess == 0 || h.SelectedSamples == 0 || h.SelectedFailures != 0 ||
			h.SelectedP50MS == nil || h.SelectedP95MS == nil {
			out = append(out, "selected_state=success 与样本/分类不一致")
		}
	case "degraded":
		if h.RecentDegraded == 0 || h.SelectedSamples == 0 || h.SelectedFailures <= 0 ||
			h.SelectedFailures >= h.SelectedSamples || h.SelectedP50MS == nil || h.SelectedP95MS == nil {
			out = append(out, "selected_state=degraded 与样本/分类不一致")
		}
	case "failed":
		if h.RecentFailed == 0 || h.SelectedSamples == 0 || h.SelectedFailures != h.SelectedSamples ||
			h.SelectedP50MS != nil || h.SelectedP95MS != nil || h.SelectedKBps != nil {
			out = append(out, "selected_state=failed 与样本/分类不一致")
		}
	case "stale":
		if h.Stale == 0 || h.SelectedSamples != 0 || h.SelectedFailures != 0 ||
			h.SelectedP50MS != nil || h.SelectedP95MS != nil || h.SelectedKBps != nil {
			out = append(out, "selected_state=stale 与样本/分类不一致")
		}
	case "unknown":
		if h.Unknown == 0 || h.SelectedSamples != 0 || h.SelectedFailures != 0 ||
			h.SelectedP50MS != nil || h.SelectedP95MS != nil || h.SelectedKBps != nil {
			out = append(out, "selected_state=unknown 与样本/分类不一致")
		}
	default:
		out = append(out, "selected_state 非法:"+h.SelectedState)
	}
	return out
}
