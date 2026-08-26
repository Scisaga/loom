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
