package observation

import (
	"cmp"
	"sort"
	"strings"
	"time"
)

// §16.1：原 report 状态合法性规则与验签一起跨平台复用。
const AgentStateStaleAfter = 30 * time.Minute

func ValidateAgentState(st *AgentState, node string, now time.Time) []string {
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
		for _, problem := range ValidateAgentCandidateHealth(s.Health) {
			out = append(out, "Agent 候选健康 "+s.Declaration+":"+problem)
		}
	}
	return out
}

func ValidateAgentCandidateHealth(h *AgentCandidateHealth) []string {
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

func sortComponentStatuses(xs []ComponentStatus) {
	sort.Slice(xs, func(i, j int) bool {
		a, b := xs[i], xs[j]
		for _, pair := range [][2]string{
			{a.Name, b.Name}, {a.Expected, b.Expected},
			{a.Actual, b.Actual}, {a.Error, b.Error},
		} {
			if n := cmp.Compare(pair[0], pair[1]); n != 0 {
				return n < 0
			}
		}
		return false
	})
}

func ValidateComponentStatuses(xs []ComponentStatus) []string {
	if len(xs) > 16 {
		return []string{"组件条目超过 16 个"}
	}
	allowed := map[string]bool{
		"sing-box": true, "wireguard": true, "tailscale": true, "agent-protocol": true,
	}
	seen := map[string]bool{}
	var out []string
	validText := func(s string, limit int) bool {
		return len(s) <= limit && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\r\n\x00")
	}
	for _, c := range xs {
		switch {
		case !allowed[c.Name]:
			out = append(out, "未知组件名:"+c.Name)
		case seen[c.Name]:
			out = append(out, "重复组件:"+c.Name)
		}
		seen[c.Name] = true
		if c.Expected == "" || !validText(c.Expected, 64) {
			out = append(out, "组件 "+c.Name+" 的 expected 非法")
		}
		if c.Actual != "" && !validText(c.Actual, 64) {
			out = append(out, "组件 "+c.Name+" 的 actual 非法")
		}
		if !validText(c.Error, 512) {
			out = append(out, "组件 "+c.Name+" 的 error 非法")
		}
		if c.Actual == "" && c.Error == "" {
			out = append(out, "组件 "+c.Name+" 既没有 actual 也没有 error")
		}
	}
	return out
}
