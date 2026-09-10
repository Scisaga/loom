package clientroute

import (
	"math"
	"testing"
	"time"

	"loom/internal/observation"
)

func TestEvidenceCostCombinesSequentialFailureRates(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	evidence := Evidence{MaxAge: time.Minute, ByNode: map[string]observation.Observation{
		"entry": {
			Node: "entry", TS: now.Format(time.RFC3339),
			Edges: []observation.Edge{{To: "exit", RTTMs: 20, Samples: 100, Failures: 6}},
		},
		"exit": {
			Node: "exit", TS: now.Format(time.RFC3339),
			Targets: []observation.Reach{{
				Target: "https://target.example/", FirstByteMs: 30, Samples: 100, Failures: 6,
			}},
		},
	}}

	cost := evidence.Cost(
		[]string{"entry", "exit"}, []string{"https://target.example/"}, now, []string{"neighbor"},
	)
	if !cost.Known || cost.Failed || math.Abs(cost.FailureRate-0.1164) > 0.000001 {
		t.Fatalf("顺序路径失败率=%v,期望 0.1164；cost=%+v", cost.FailureRate, cost)
	}
}

func TestDecideRemovesRedundantRelayBeforeThresholdCandidates(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	declaration := Declaration{
		ID: "web", Selector: "route:web", Objective: "latency", SwitchThreshold: 0.5,
		Targets: []string{"https://target.example/"},
		Candidates: []Candidate{
			{Tag: "current", Chain: []string{"entry-a", "relay", "exit"}},
			{Tag: "fast-same-hops", Chain: []string{"entry-b", "relay", "exit"}},
			{Tag: "shorter", Chain: []string{"entry-c", "exit"}},
		},
	}
	observed := func(node string, edges ...observation.Edge) observation.Observation {
		return observation.Observation{Node: node, TS: now.Format(time.RFC3339), Edges: edges}
	}
	evidence := Evidence{MaxAge: time.Minute, ByNode: map[string]observation.Observation{
		"entry-a": observed("entry-a", observation.Edge{To: "relay", RTTMs: 10, Samples: 1}),
		"entry-b": observed("entry-b", observation.Edge{To: "relay", Samples: 1}),
		"entry-c": observed("entry-c", observation.Edge{To: "exit", RTTMs: 20, Samples: 1}),
		"relay":   observed("relay", observation.Edge{To: "exit", RTTMs: 10, Samples: 1}),
		"exit": {Node: "exit", TS: now.Format(time.RFC3339), Targets: []observation.Reach{{
			Target: "https://target.example/", FirstByteMs: 10, Samples: 1,
		}}},
	}}
	entries := map[string]EntryResult{
		"entry-a": {RTT: 10 * time.Millisecond, At: now},
		"entry-b": {RTT: 5 * time.Millisecond, At: now},
		"entry-c": {RTT: 5 * time.Millisecond, At: now},
	}
	decision, err := Decide(declaration, "current", entries, evidence, map[string][]string{
		"current": {"neighbor", "neighbor"}, "fast-same-hops": {"neighbor", "neighbor"}, "shorter": {"neighbor"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Candidate != "shorter" {
		t.Fatalf("candidate=%q reason=%q; want shorter relay-free candidate", decision.Candidate, decision.Reason)
	}
	if want := "减少中继 3→2 跳"; !contains(decision.Reason, want) {
		t.Fatalf("reason=%q; want %q", decision.Reason, want)
	}
}

func TestDecideEntryOnlyNeverAddsRelay(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	decision, err := Decide(Declaration{
		ID: "web", Selector: "route:web", Objective: "latency", Targets: []string{"https://missing.example/"},
		Candidates: []Candidate{
			{Tag: "current", Chain: []string{"exit"}},
			{Tag: "extra-relay", Chain: []string{"entry", "exit"}},
		},
	}, "current", map[string]EntryResult{
		"exit":  {RTT: 30 * time.Millisecond, At: now},
		"entry": {RTT: time.Millisecond, At: now},
	}, Evidence{MaxAge: time.Minute, ByNode: map[string]observation.Observation{}}, map[string][]string{
		"current": {}, "extra-relay": {"unknown"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Candidate != "current" {
		t.Fatalf("entry-only evidence added an unknown relay: %+v", decision)
	}
}

func contains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
