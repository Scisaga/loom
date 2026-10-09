package clientmodel

import (
	"testing"
	"time"
)

func TestSelectionOrderWithMissingAndComparableMetrics(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	const target = "https://demo-web.example/probe"
	routes := []RouteCandidate{
		{ID: "demo-a", Scope: "service:demo-web", FinalExit: "demo-exit", Chain: []string{"demo-exit"}},
		{ID: "demo-b", Scope: "service:demo-web", FinalExit: "demo-exit", Chain: []string{"demo-exit"}},
		{ID: "demo-c", Scope: "service:demo-web", FinalExit: "demo-exit", Chain: []string{"demo-exit"}},
	}
	for _, tc := range []struct {
		name    string
		metrics [3]int64
		current string
		want    string
	}{
		{"comparable improvement", [3]int64{100, 0, 10}, "demo-a", "demo-c"},
		{"current missing metric", [3]int64{100, 0, 10}, "demo-b", "demo-b"},
		{"equal current metric", [3]int64{10, 0, 10}, "demo-c", "demo-c"},
		{"equal better alternatives", [3]int64{100, 10, 10}, "demo-a", "demo-b"},
		{"no current", [3]int64{100, 0, 10}, "", "demo-c"},
		{"baseline missing metric", [3]int64{0, 100, 10}, "", "demo-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var samples []Observation
			for i, route := range routes {
				samples = append(samples, Observation{CandidateID: route.ID, Scope: route.Scope, NetworkGeneration: "demo-network",
					Target: target, Action: "https_request", Result: "available", ObservedAt: now.Format(time.RFC3339),
					ValidUntil: now.Add(time.Minute).Format(time.RFC3339), MetricMillis: tc.metrics[i]})
			}
			for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
				permuted := []RouteCandidate{routes[order[0]], routes[order[1]], routes[order[2]]}
				observations := []Observation{samples[order[2]], samples[order[1]], samples[order[0]]}
				selected, err := Select(permuted, observations, Preference{Schema: 3, Mode: ModeAuto}, tc.current, "demo-network", now, target)
				if err != nil || selected.CandidateID != tc.want {
					t.Errorf("order %v: selected %s, want %s: %v", order, selected.CandidateID, tc.want, err)
				}
			}
		})
	}
}

func TestSelectionMetricDoesNotOutrankItsEvidenceScope(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	const target = "https://demo-web.example/probe"
	routes := []RouteCandidate{
		{ID: "demo-faster", Scope: "service:demo-web", FinalExit: "demo-exit", Chain: []string{"demo-exit"}},
		{ID: "demo-current", Scope: "service:demo-web", FinalExit: "demo-exit", Chain: []string{"demo-exit"}},
	}
	for _, mode := range []string{"expired", "other network", "multiple targets"} {
		t.Run(mode, func(t *testing.T) {
			var samples []Observation
			for i, route := range routes {
				samples = append(samples, Observation{CandidateID: route.ID, Scope: route.Scope, NetworkGeneration: "demo-network",
					Target: target, Action: "https_request", Result: "available", ObservedAt: now.Add(-time.Minute).Format(time.RFC3339),
					ValidUntil: now.Add(time.Minute).Format(time.RFC3339), MetricMillis: int64(10 + i*90)})
			}
			targets := []string{target}
			switch mode {
			case "expired":
				samples[0].ValidUntil = now.Format(time.RFC3339)
			case "other network":
				samples[0].NetworkGeneration = "demo-old-network"
			case "multiple targets":
				targets = append(targets, "https://demo-web.example/other")
				for _, sample := range append([]Observation(nil), samples...) {
					sample.Target = targets[1]
					samples = append(samples, sample)
				}
			}
			selected, err := Select(routes, samples, Preference{Schema: 3, Mode: ModeFixed, Exit: "demo-exit"}, "demo-current", "demo-network", now, targets...)
			if err != nil || selected.CandidateID != "demo-current" {
				t.Fatal("incomparable measurement displaced the actual selection", selected, err)
			}
		})
	}
}
