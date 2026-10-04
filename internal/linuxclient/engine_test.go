package linuxclient

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

type fakeSelector struct {
	current map[string]string
	closed  int
	failSet string
}

func TestServiceActivationNeverSharesBusinessOutcome(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	routes := []clientmodel.RouteCandidate{{ID: "demo-a", FinalExit: "direct", Scope: "service:demo-a"}, {ID: "demo-b", FinalExit: "direct", Scope: "service:demo-b"}}
	selector := &fakeSelector{current: map[string]string{"service:demo-a": "demo-a", "service:demo-b": "demo-b"}}
	calls := 0
	options := Options{Now: func() time.Time { return now }, Probe: func(context.Context) ProbeResult {
		calls++
		return ProbeResult{Available: calls == 1, Action: "https_request"}
	}}
	value, err := activateServices(context.Background(), options, control.DeviceView{}, selector, routes, defaultState("demo-network"))
	if err == nil || calls != 2 || len(value.State.Observations) != 2 || value.Selections[0].State != "available" || value.Selections[1].State != "unavailable" {
		t.Fatal("one Service probe was applied to another", calls, err, value.Selections)
	}
}

func (selector *fakeSelector) Read(_ context.Context, scope string) (string, error) {
	value, found := selector.current[scope]
	if !found {
		return "", errors.New("missing selector")
	}
	return value, nil
}

func (selector *fakeSelector) Set(_ context.Context, scope, candidate string) error {
	if candidate == selector.failSet {
		return errors.New("apply failed")
	}
	selector.current[scope] = candidate
	return nil
}

func (selector *fakeSelector) CloseConnections(context.Context) error {
	selector.closed++
	return nil
}

func linuxRoutes() []clientmodel.RouteCandidate {
	return []clientmodel.RouteCandidate{
		{ID: "direct", FinalExit: "direct", Scope: "service"},
		{ID: "one-hop", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "service"},
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}, Scope: "service"},
	}
}

func TestActivateUsesSharedPreferenceAndNecessaryFallback(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	selector := &fakeSelector{current: map[string]string{"service": "one-hop"}}
	state := defaultState("network-a")
	state.Preference = clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeFixed, Exit: "demo-exit"}
	results := []bool{false, true}
	activation, err := Activate(context.Background(), selector, linuxRoutes(), state, func(context.Context) ProbeResult {
		result := results[0]
		results = results[1:]
		return ProbeResult{Available: result, Metric: 12 * time.Millisecond}
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if selector.current["service"] != "relay" || activation.Selections[0].CandidateID != "relay" ||
		activation.Selections[0].State != "available" || len(activation.State.Observations) != 2 || len(results) != 0 {
		t.Fatalf("fallback activation = %+v selector=%+v remaining=%d", activation, selector.current, len(results))
	}
	if activation.State.Observations[0].CandidateID != "one-hop" || activation.State.Observations[0].Result != "unavailable" ||
		activation.State.Observations[1].CandidateID != "relay" || activation.State.Observations[1].Result != "available" {
		t.Fatalf("observations = %+v", activation.State.Observations)
	}
}

func TestActivationWithoutBusinessTargetKeepsRuntimeSelectionUnknown(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	selector := &fakeSelector{current: map[string]string{"service": "one-hop"}}
	state := defaultState("demo-network")
	activation, err := Activate(context.Background(), selector, linuxRoutes(), state, nil, func() time.Time { return now })
	if err != nil || len(activation.Selections) != 1 || activation.Selections[0].CandidateID != "one-hop" ||
		activation.Selections[0].State != "unknown" || len(activation.State.Observations) != 0 {
		t.Fatalf("target-free activation = %+v, %v", activation, err)
	}
}

func TestActivateReusesCurrentGenerationObservationWithoutProbe(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	selector := &fakeSelector{current: map[string]string{"service": "relay"}}
	state := defaultState("network-a")
	state.Preference = clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeFixed, Exit: "demo-exit"}
	state.Observations = []clientmodel.Observation{{CandidateID: "relay", NetworkGeneration: "network-a", Scope: "service",
		Result: "available", Action: "tcp_udp_dns", ObservedAt: now.Add(-time.Minute).Format(time.RFC3339),
		ValidUntil: now.Add(time.Minute).Format(time.RFC3339)}}
	activation, err := Activate(context.Background(), selector, linuxRoutes(), state, func(context.Context) ProbeResult {
		t.Fatal("restart unexpectedly probed an already-current observation")
		return ProbeResult{}
	}, func() time.Time { return now })
	if err != nil || activation.Selections[0].CandidateID != "relay" || selector.closed != 0 {
		t.Fatalf("restart activation=%+v closed=%d err=%v", activation, selector.closed, err)
	}
}

func TestSelectionReadbackExpiresSelectedObservation(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	activation := Activation{State: defaultState("network-a"),
		Selections: []SelectionStatus{{Scope: "service", CandidateID: "relay"}}}
	activation.State.Observations = []clientmodel.Observation{{CandidateID: "relay", NetworkGeneration: "network-a",
		Scope: "service", Result: "available", Action: "tcp_udp_dns", ObservedAt: now.Add(-time.Minute).Format(time.RFC3339),
		ValidUntil: now.Add(time.Minute).Format(time.RFC3339)}}
	if observationState(activation.State.Observations, "relay", activation.State.NetworkGeneration, now) != "available" {
		t.Fatal("current selected observation was treated as stale")
	}
	if observationState(activation.State.Observations, "relay", activation.State.NetworkGeneration, now.Add(time.Minute)) != "unknown" {
		t.Fatal("expired selected observation was treated as current")
	}
	activation.State.NetworkGeneration = "network-b"
	if observationState(activation.State.Observations, "relay", activation.State.NetworkGeneration, now) != "unknown" {
		t.Fatal("another network generation observation was treated as current")
	}
}

func TestApplySelectionsRollsBackOnFailure(t *testing.T) {
	selector := &fakeSelector{current: map[string]string{"a": "old-a", "b": "old-b"}, failSet: "new-b"}
	if _, err := applySelections(context.Background(), selector, map[string]string{"a": "new-a", "b": "new-b"}); err == nil {
		t.Fatal("failed selector apply succeeded")
	}
	if !reflect.DeepEqual(selector.current, map[string]string{"a": "old-a", "b": "old-b"}) {
		t.Fatalf("selector rollback = %+v", selector.current)
	}
}

func TestCancellationDoesNotBecomeBusinessFailure(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	routes := []clientmodel.RouteCandidate{
		{ID: "one-hop", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "demo-service"},
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-relay", "demo-exit"}, Scope: "demo-service"},
	}
	for _, cancelOnFallback := range []bool{false, true} {
		name := "first probe"
		if cancelOnFallback {
			name = "fallback probe"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			selector := &fakeSelector{current: map[string]string{"demo-service": "one-hop"}}
			calls := 0
			activation, err := Activate(ctx, selector, routes, LocalState{Preference: clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeFixed, Exit: "demo-exit"}, NetworkGeneration: "demo-network"}, func(context.Context) ProbeResult {
				calls++
				if !cancelOnFallback || calls == 2 {
					cancel()
				}
				return ProbeResult{Description: "demo probe interrupted"}
			}, func() time.Time { return now })
			expectedCalls := 1
			expectedCandidate := "one-hop"
			if cancelOnFallback {
				expectedCalls, expectedCandidate = 2, "relay"
			}
			if !errors.Is(err, context.Canceled) || calls != expectedCalls ||
				len(activation.State.Observations) != expectedCalls-1 ||
				len(activation.Selections) != 1 || activation.Selections[0].CandidateID != expectedCandidate ||
				activation.Selections[0].State != "unknown" {
				t.Fatalf("cancelled probe invented business evidence: activation=%+v calls=%d err=%v", activation, calls, err)
			}
			if cancelOnFallback && (activation.State.Observations[0].CandidateID != "one-hop" || activation.State.Observations[0].Result != "unavailable") {
				t.Fatalf("earlier real failure was lost: %+v", activation.State.Observations)
			}
		})
	}
}
