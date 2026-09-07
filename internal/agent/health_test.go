package agent

import (
	"testing"

	"loom/internal/measure"
)

func intValue(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

func TestSummarizeCandidateHealthSeparatesFreshFailedStaleAndUnknown(t *testing.T) {
	const node = "n"
	d := &Decl{ID: "d", Candidates: []Cand{
		{Tag: "ok"}, {Tag: "degraded"}, {Tag: "failed"}, {Tag: "stale"}, {Tag: "unknown"},
	}}
	scope := decisionScope(node, d)
	fresh := []measure.Summary{
		{Declaration: "d", CandidateID: "ok", Samples: 4, P50: 80, P95: 110, KBps: 500},
		{Declaration: "d", CandidateID: "degraded", Samples: 5, Failures: 2, P50: 120, P95: 190, KBps: 300},
		{Declaration: "d", CandidateID: "failed", Samples: 3, Failures: 3},
		// A removed candidate must not inflate any count or latency summary.
		{Declaration: "d", CandidateID: "removed", Samples: 1, P50: 1, P95: 1},
	}
	all := []measure.Measurement{
		{Node: node, DecisionScope: scope, Declaration: "d", CandidateID: "stale", TS: "2026-08-26T10:00:00Z"},
		{Node: node, DecisionScope: scope, Declaration: "other", CandidateID: "unknown", TS: "2026-08-26T12:00:00Z"},
		{Node: node, DecisionScope: scope, Declaration: "d", CandidateID: "unknown", TS: "not-a-time"},
	}

	h := summarizeCandidateHealth(d, "degraded", fresh, all, node, scope)
	if h.Candidates != 5 || h.RecentSuccess != 1 || h.RecentDegraded != 1 ||
		h.RecentFailed != 1 || h.Stale != 1 || h.Unknown != 1 {
		t.Fatalf("分类不互斥或漏项:%+v", h)
	}
	if h.SelectedState != healthDegraded || h.SelectedSamples != 5 || h.SelectedFailures != 2 {
		t.Fatalf("当前候选摘要不对:%+v", h)
	}
	if intValue(h.SelectedP50MS) != 120 || intValue(h.SelectedP95MS) != 190 ||
		intValue(h.BestP50MS) != 80 || intValue(h.SelectedKBps) != 300 ||
		intValue(h.BestKBps) != 500 {
		t.Fatalf("延迟摘要不对:%+v", h)
	}
}

func TestSummarizeCandidateHealthDoesNotReuseStaleLatency(t *testing.T) {
	const node = "n"
	d := &Decl{ID: "d", Candidates: []Cand{{Tag: "old"}, {Tag: "never"}}}
	scope := decisionScope(node, d)
	all := []measure.Measurement{{
		Node: node, DecisionScope: scope, Declaration: "d", CandidateID: "old", TS: "2026-08-26T10:00:00Z", FirstByteMs: 12,
	}}
	h := summarizeCandidateHealth(d, "old", nil, all, node, scope)
	if h.Stale != 1 || h.Unknown != 1 || h.SelectedState != healthStale {
		t.Fatalf("旧样本没有保持 stale/unknown 区分:%+v", h)
	}
	if h.BestP50MS != nil || h.SelectedP50MS != nil || h.SelectedP95MS != nil ||
		h.SelectedKBps != nil || h.BestKBps != nil || h.SelectedSamples != 0 || h.SelectedFailures != 0 {
		t.Fatalf("陈旧样本重新进入了延迟/样本摘要:%+v", h)
	}
}

func TestSummarizeCandidateHealthDoesNotCallLegacyOrOtherScopeStale(t *testing.T) {
	const node = "n"
	d := &Decl{ID: "d", Targets: []string{"https://new.example/"}, Candidates: []Cand{{Tag: "a"}}}
	scope := decisionScope(node, d)
	all := []measure.Measurement{
		{Node: node, Declaration: "d", CandidateID: "a", TS: "2026-08-26T10:00:00Z"},
		{Node: node, Declaration: "d", CandidateID: "a", DecisionScope: "old-scope", TS: "2026-08-26T11:00:00Z"},
		{Node: "other", Declaration: "d", CandidateID: "a", DecisionScope: scope, TS: "2026-08-26T12:00:00Z"},
	}
	h := summarizeCandidateHealth(d, "a", nil, all, node, scope)
	if h.Unknown != 1 || h.Stale != 0 || h.SelectedState != healthUnknown {
		t.Fatalf("legacy/异 node/scope 历史被错误展示为 stale:%+v", h)
	}
}
