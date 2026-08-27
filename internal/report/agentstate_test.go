package report

import (
	"strings"
	"testing"
	"time"
)

func TestAgentStateValidationRejectsWrongNodeAndStaleSelection(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	st := &AgentState{Node: "other", TS: now.Format(time.RFC3339), Selections: []AgentSelection{{
		Declaration: "d", Selector: "svc:d", Candidate: "cand:d:gz02",
		UpdatedAt: now.Add(-AgentStateStaleAfter - time.Second).Format(time.RFC3339),
	}}}
	got := strings.Join(validateAgentState(st, "jm24", now), "\n")
	if !strings.Contains(got, "不一致") || !strings.Contains(got, "过期") {
		t.Fatalf("错误节点和过期选择都应被拒绝:%s", got)
	}
}

func TestAgentStateValidationAcceptsFreshSelectorRead(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	st := &AgentState{Node: "jm24", TS: now.Format(time.RFC3339), Selections: []AgentSelection{{
		Declaration: "d", Selector: "svc:d", Candidate: "cand:d:gz02",
		UpdatedAt: now.Add(-time.Minute).Format(time.RFC3339),
	}}}
	if got := validateAgentState(st, "jm24", now); len(got) != 0 {
		t.Fatalf("新鲜状态被误拒:%v", got)
	}
}

func TestAgentStateValidationAcceptsCandidateHealthAndOldFormat(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	p50, p95, best, selectedKBps, bestKBps := 120, 190, 80, 300, 500
	st := &AgentState{
		Node: "jm24", TS: now.Format(time.RFC3339), ComponentVersion: "0.1.0",
		Selections: []AgentSelection{{
			Declaration: "d", Selector: "svc:d", Candidate: "cand:d:gz02",
			UpdatedAt: now.Format(time.RFC3339), Health: &AgentCandidateHealth{
				Candidates: 4, RecentSuccess: 1, RecentDegraded: 1,
				RecentFailed: 1, Stale: 1, SelectedState: "degraded",
				SelectedSamples: 5, SelectedFailures: 2,
				SelectedP50MS: &p50, SelectedP95MS: &p95, BestP50MS: &best,
				SelectedKBps: &selectedKBps, BestKBps: &bestKBps,
			},
		}},
	}
	if got := validateAgentState(st, "jm24", now); len(got) != 0 {
		t.Fatalf("合法候选健康被误拒:%v", got)
	}

	// Health/component_version 都是新增可选字段；旧 Agent 状态不能在滚动升级
	// 期间被当成格式损坏，但调用方也不能把缺失解释为健康。
	st.ComponentVersion = ""
	st.Selections[0].Health = nil
	if got := validateAgentState(st, "jm24", now); len(got) != 0 {
		t.Fatalf("旧格式状态不再兼容:%v", got)
	}
}

func TestAgentStateValidationRejectsImpossibleCandidateHealth(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	p50, p95, selectedKBps, bestKBps := 200, 100, 300, 200
	st := &AgentState{Node: "jm24", TS: now.Format(time.RFC3339), Selections: []AgentSelection{{
		Declaration: "d", Selector: "svc:d", Candidate: "cand:d:gz02",
		UpdatedAt: now.Format(time.RFC3339), Health: &AgentCandidateHealth{
			Candidates: 2, RecentSuccess: 2, RecentFailed: 1,
			SelectedState: "success", SelectedSamples: 1, SelectedFailures: 1,
			SelectedP50MS: &p50, SelectedP95MS: &p95,
			SelectedKBps: &selectedKBps, BestKBps: &bestKBps,
		},
	}}}
	got := strings.Join(validateAgentState(st, "jm24", now), "\n")
	for _, want := range []string{"五类计数", "p95", "best_p50", "best_kbps", "selected_state=success"} {
		if !strings.Contains(got, want) {
			t.Errorf("没有拒绝 %s 矛盾:%s", want, got)
		}
	}
}

func TestAgentStateForConfigRejectsMissingDeclarationAndNilHealth(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	cfg := &Config{
		Node: "jm24", AgentState: "/var/lib/loom/agent-state.json",
		ExpectedComponents: ComponentVersions{Agent: "0.1.0"},
		ExpectedRoutes: []ExpectedRoute{
			{Access: "jm24", Declaration: "d1", Chain: []string{"gz02"}},
			{Access: "jm24", Declaration: "d2", Chain: []string{"hz01"}},
			// 其他接入节点的全网底图不能被误算成本机 declaration。
			{Access: "other", Declaration: "remote", Chain: []string{"sg02"}},
		},
	}
	st := &AgentState{
		Node: "jm24", TS: now.Format(time.RFC3339), ComponentVersion: "0.1.0",
		Selections: []AgentSelection{{
			Declaration: "d1", Selector: "svc:d1", Candidate: "cand:d1:gz02",
			UpdatedAt: now.Format(time.RFC3339),
		}},
	}
	got := strings.Join(validateAgentStateForConfig(st, cfg, now), "\n")
	for _, want := range []string{"d1 未上报候选健康", "缺少期望 declaration:d2"} {
		if !strings.Contains(got, want) {
			t.Errorf("没有拒绝 %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "remote") {
		t.Fatalf("把其他接入节点的 declaration 算到本机:\n%s", got)
	}
}

func TestAgentStateForConfigAllowsLegacyHealthButNotEmptyNewState(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	cfg := &Config{
		Node: "jm24", AgentState: "/state",
		ExpectedComponents: ComponentVersions{Agent: "0.1.0"},
		ExpectedRoutes:     []ExpectedRoute{{Access: "jm24", Declaration: "d"}},
	}
	legacy := &AgentState{
		Node: "jm24", TS: now.Format(time.RFC3339),
		Selections: []AgentSelection{{
			Declaration: "d", Selector: "svc:d", Candidate: "cand:d:gz02",
			UpdatedAt: now.Format(time.RFC3339),
		}},
	}
	if got := validateAgentStateForConfig(legacy, cfg, now); len(got) != 0 {
		t.Fatalf("旧 Agent 的 nil Health 应保持线格式兼容:%v", got)
	}
	emptyNew := &AgentState{
		Node: "jm24", TS: now.Format(time.RFC3339), ComponentVersion: "0.1.0",
	}
	got := strings.Join(validateAgentStateForConfig(emptyNew, cfg, now), "\n")
	if !strings.Contains(got, "缺少期望 declaration:d") {
		t.Fatalf("新版 Agent 空状态被假绿:%s", got)
	}
}
