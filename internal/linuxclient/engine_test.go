package linuxclient

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"loom/internal/clientmodel"
)

type fakeSelector struct {
	current map[string]string
	closed  int
	failSet string
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
	state.Preference = clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeFixed, Exit: "demo-exit"}
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

func TestActivateReusesCurrentGenerationObservationWithoutProbe(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	selector := &fakeSelector{current: map[string]string{"service": "relay"}}
	state := defaultState("network-a")
	state.Preference = clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeFixed, Exit: "demo-exit"}
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

func TestApplySelectionsRollsBackOnFailure(t *testing.T) {
	selector := &fakeSelector{current: map[string]string{"a": "old-a", "b": "old-b"}, failSet: "new-b"}
	if _, err := applySelections(context.Background(), selector, map[string]string{"a": "new-a", "b": "new-b"}); err == nil {
		t.Fatal("failed selector apply succeeded")
	}
	if !reflect.DeepEqual(selector.current, map[string]string{"a": "old-a", "b": "old-b"}) {
		t.Fatalf("selector rollback = %+v", selector.current)
	}
}
