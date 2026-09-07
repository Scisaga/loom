package agent

import (
	"testing"
	"time"

	"loom/internal/measure"
	"loom/internal/model"
)

func TestDecisionScopeIsOrderIndependentAndBindsDecisionSemantics(t *testing.T) {
	base := &Decl{
		ID: "svc", Selector: "svc:svc", Objective: model.Latency,
		Targets:      []string{"https://b.example/", "https://a.example/"},
		TuningPeriod: "10m", SwitchThreshold: 0.2, Window: "6h",
		MinSamples: 4, StaleAfter: "2h", ProbeBudget: 4,
		Candidates: []Cand{
			{Tag: "b", Chain: []string{"relay", "exit"}, ProbeUser: "probe-b"},
			{Tag: "a", Chain: []string{"exit"}, ProbeUser: "probe-a"},
		},
	}
	equivalent := *base
	equivalent.Targets = []string{"https://a.example/", "https://b.example/"}
	equivalent.Candidates = []Cand{base.Candidates[1], base.Candidates[0]}
	equivalent.TuningPeriod = "600s"
	equivalent.Window = "360m"
	equivalent.StaleAfter = "120m"
	want := decisionScope("access-a", base)
	if got := decisionScope("access-a", &equivalent); got != want {
		t.Fatalf("semantically equivalent plan changed scope:\n%s\n%s", want, got)
	}

	tests := map[string]struct {
		node string
		edit func(*Decl)
	}{
		"access node":        {node: "access-b"},
		"target":             {node: "access-a", edit: func(d *Decl) { d.Targets[0] = "https://new.example/" }},
		"candidate chain":    {node: "access-a", edit: func(d *Decl) { d.Candidates[0].Chain = []string{"other", "exit"} }},
		"candidate set":      {node: "access-a", edit: func(d *Decl) { d.Candidates = d.Candidates[:1] }},
		"decision threshold": {node: "access-a", edit: func(d *Decl) { d.MinSamples++ }},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			changed := cloneDecl(base)
			if test.edit != nil {
				test.edit(changed)
			}
			if got := decisionScope(test.node, changed); got == want {
				t.Fatalf("%s change did not change scope", name)
			}
		})
	}
}

func TestDecisionWindowRejectsLegacyOtherNodeAndChangedPlanSamples(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	current := &Decl{
		ID: "svc", Selector: "svc:svc", Objective: model.Latency,
		Targets: []string{"https://new.example/"}, Window: "1h", StaleAfter: "30m", MinSamples: 2,
		Candidates: []Cand{{Tag: "current"}, {Tag: "challenger"}},
	}
	old := cloneDecl(current)
	old.Targets = []string{"https://old.example/"}
	scope := decisionScope("access-a", current)
	oldScope := decisionScope("access-a", old)
	ts := now.Add(-time.Minute).Format(time.RFC3339)
	measurements := []measure.Measurement{
		{TS: ts, Node: "access-a", Declaration: "svc", CandidateID: "current", DecisionScope: scope, FirstByteMs: 100},
		{TS: ts, Node: "access-a", Declaration: "svc", CandidateID: "challenger", DecisionScope: oldScope, FirstByteMs: 1},
		{TS: ts, Node: "access-a", Declaration: "svc", CandidateID: "challenger", FirstByteMs: 1},
		{TS: ts, Node: "access-b", Declaration: "svc", CandidateID: "challenger", DecisionScope: scope, FirstByteMs: 1},
	}
	fresh := inWindow(measurements, "access-a", current.ID, scope, now, time.Hour, 30*time.Minute)
	if len(fresh) != 1 || fresh[0].CandidateID != "current" {
		t.Fatalf("异 node/scope 或 legacy 样本进入当前窗口:%+v", fresh)
	}
	if got := Decide(current, "current", measure.Summarize(fresh)); got.Switch {
		t.Fatalf("旧目标的快样本让新配置提前切换:%+v", got)
	}
}

func cloneDecl(d *Decl) *Decl {
	cp := *d
	cp.Targets = append([]string(nil), d.Targets...)
	cp.Candidates = append([]Cand(nil), d.Candidates...)
	for i := range cp.Candidates {
		cp.Candidates[i].Chain = append([]string(nil), d.Candidates[i].Chain...)
	}
	return &cp
}
