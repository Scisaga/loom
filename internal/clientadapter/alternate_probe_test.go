package clientadapter

import (
	"context"
	"loom/internal/clientmodel"
	"reflect"
	"testing"
	"time"
)

func TestAlternateSamplingIsBoundedFairAndDoesNotTouchCurrentSelector(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	scope := "service:demo-service"
	target := "https://demo.example/"
	routes := []clientmodel.RouteCandidate{{ID: "demo-current", FinalExit: "demo-exit", Scope: scope}, {ID: "demo-b", FinalExit: "demo-exit", Scope: scope}, {ID: "demo-a", FinalExit: "demo-exit", Scope: scope}}
	state := State{Preference: clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeFixed, Exit: "demo-exit"}, NetworkGeneration: "demo-underlay"}
	selector := &fakeSelector{current: map[string]string{scope: "demo-current"}}
	before := map[string]string{scope: "demo-current"}
	calls := []string{}
	probe := func(_ context.Context, candidate, target string) ProbeResult {
		calls = append(calls, candidate)
		return ProbeResult{Available: true, Metric: time.Millisecond}
	}
	for i := 0; i < 3; i++ {
		var err error
		state, err = sampleAlternateBusiness(context.Background(), routes, state, "demo-current", []string{target}, func() time.Time { return at }, probe)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(calls, []string{"demo-a", "demo-b"}) || !reflect.DeepEqual(selector.current, before) || len(state.Observations) != 2 {
		t.Fatal("alternate scan exceeded budget or changed selector", calls, state)
	}
	at = at.Add(11 * time.Minute)
	request, found, err := NextAlternateProbe(routes, state, "demo-current", []string{target}, at)
	if err != nil || !found || request.CandidateID != "demo-a" {
		t.Fatal("rotation did not recover oldest path", request, found, err)
	}
}

func TestIndependentAlternateImprovementBecomesActualReadbackAfterMeasurement(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	scope := "service:demo-service"
	target := "https://demo.example/"
	routes := []clientmodel.RouteCandidate{{ID: "demo-current", FinalExit: "demo-exit", Scope: scope}, {ID: "demo-alternate", FinalExit: "demo-exit", Scope: scope}}
	selector := &fakeSelector{current: map[string]string{scope: routes[0].ID}}
	state := State{Preference: clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeFixed, Exit: "demo-exit"}, NetworkGeneration: "demo-underlay", Observations: []clientmodel.Observation{{CandidateID: routes[0].ID, Scope: scope, Target: target, NetworkGeneration: "demo-underlay", Result: "available", Action: "https_request", ObservedAt: at.Format(time.RFC3339), ValidUntil: at.Add(time.Minute).Format(time.RFC3339), MetricMillis: 100}}}
	state, err := sampleAlternateBusiness(context.Background(), routes, state, routes[0].ID, []string{target}, func() time.Time { return at.Add(time.Second) }, func(_ context.Context, candidate, actualTarget string) ProbeResult {
		if selector.current[scope] != routes[0].ID || candidate != routes[1].ID || actualTarget != target {
			t.Fatal("production selector was changed to take an alternate sample")
		}
		return ProbeResult{Available: true, Metric: 10 * time.Millisecond}
	})
	if err != nil {
		t.Fatal(err)
	}
	activation, err := Activate(context.Background(), selector, routes, state, Probes{target: nil}, func() time.Time { return at.Add(time.Second) })
	if err != nil || len(activation.Selections) != 1 || activation.Selections[0].CandidateID != routes[1].ID || selector.current[scope] != routes[1].ID {
		t.Fatal("measured improvement was not applied and read back", err, activation)
	}
}
