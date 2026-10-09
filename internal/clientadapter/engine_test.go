package clientadapter

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
	readAs  string
}

func (selector *fakeSelector) Read(_ context.Context, scope string) (string, error) {
	if selector.readAs != "" {
		return selector.readAs, nil
	}
	value, found := selector.current[scope]
	if !found {
		return "", errors.New("missing selector")
	}
	return value, nil
}

func (selector *fakeSelector) Set(_ context.Context, scope, candidate string) error {
	selector.current[scope] = candidate
	return nil
}

func (*fakeSelector) CloseConnections(context.Context, []string) error { return nil }

func TestActivateUsesReadbackAndOneSameExitFallback(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	routes := []clientmodel.RouteCandidate{
		{ID: "one-hop", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "internet"},
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-relay", "demo-exit"}, Scope: "internet"},
	}
	selector := &fakeSelector{current: map[string]string{"internet": "one-hop"}}
	results := []ProbeResult{{Available: false, Metric: time.Second}, {Available: true, Metric: 2 * time.Second}}
	activation, err := Activate(context.Background(), selector, routes, State{
		Preference:        clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeFixed, Exit: "demo-exit"},
		NetworkGeneration: "demo-network"}, func(context.Context) ProbeResult {
		result := results[0]
		results = results[1:]
		return result
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if selector.current["internet"] != "relay" || len(activation.Selections) != 1 ||
		activation.Selections[0].CandidateID != "relay" || len(activation.State.Observations) != 2 {
		t.Fatalf("fallback did not preserve selector readback: selector=%+v activation=%+v", selector.current, activation)
	}
}

func TestApplyRejectsMismatchedSelectorReadback(t *testing.T) {
	selector := &fakeSelector{current: map[string]string{"internet": "one-hop"}, readAs: "unauthorized"}
	if _, err := ApplySelections(context.Background(), selector, map[string]string{"internet": "relay"}); err == nil {
		t.Fatal("mismatched selector readback was accepted as Selection")
	}
}

func TestActivateWithoutProbeKeepsActualSelectionUnknown(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	routes := []clientmodel.RouteCandidate{{ID: "demo-direct", FinalExit: "direct", Scope: "demo-service"}}
	selector := &fakeSelector{current: map[string]string{"demo-service": "demo-direct"}}
	activation, err := Activate(context.Background(), selector, routes, State{
		Preference: clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeAuto}, NetworkGeneration: "demo-network"},
		nil, func() time.Time { return now })
	if err != nil || len(activation.Selections) != 1 || activation.Selections[0].CandidateID != "demo-direct" ||
		activation.Selections[0].State != "unknown" || len(activation.State.Observations) != 0 {
		t.Fatalf("runtime readback did not remain independent of business evidence: %+v, %v", activation, err)
	}
	failed, err := Activate(context.Background(), selector, routes, activation.State,
		func(context.Context) ProbeResult { return ProbeResult{Description: "demo business failed"} }, func() time.Time { return now })
	if !errors.Is(err, clientmodel.ErrNoUsableCandidate) || len(failed.Selections) != 0 ||
		!reflect.DeepEqual(failed.BlockedScopes, []string{"demo-service"}) || selector.current["demo-service"] != BlockedSelection ||
		failed.State.NetworkGeneration == "" || len(failed.State.Observations) != 1 || failed.State.Observations[0].Result != "unavailable" {
		t.Fatalf("business failure did not retain evidence and read back its Service rejection: %+v, %v", failed, err)
	}
}

func TestServicesProbeIndependentlyAndRecoverWithoutClearingEvidence(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	routes := []clientmodel.RouteCandidate{
		{ID: "demo-a", FinalExit: "direct", Scope: "service:demo-a"},
		{ID: "demo-b", FinalExit: "direct", Scope: "service:demo-b"},
	}
	selector := &fakeSelector{current: map[string]string{routes[0].Scope: BlockedSelection, routes[1].Scope: BlockedSelection}}
	calls := map[string]int{}
	recovered := false
	probe := func(scope string) Probe {
		return func(context.Context) ProbeResult {
			calls[scope]++
			return ProbeResult{Available: scope == routes[0].Scope || recovered, Action: "https_request"}
		}
	}
	state := State{Preference: clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeAuto}, NetworkGeneration: "demo-network"}
	first, err := ActivateServices(context.Background(), selector, routes, state, probe, func() time.Time { return now })
	if !errors.Is(err, clientmodel.ErrNoUsableCandidate) || len(first.Selections) != 1 || first.Selections[0].CandidateID != "demo-a" ||
		!reflect.DeepEqual(first.BlockedScopes, []string{routes[1].Scope}) || len(first.State.Observations) != 2 || calls[routes[0].Scope] != 1 || calls[routes[1].Scope] != 1 {
		t.Fatal("Service outcomes were shared or one failure stopped the other Service", first, calls, err)
	}
	recovered = true
	again, err := ActivateServices(context.Background(), selector, routes, first.State, probe, func() time.Time { return now.Add(29 * time.Second) })
	if !errors.Is(err, clientmodel.ErrNoUsableCandidate) || !reflect.DeepEqual(first.State, again.State) || calls[routes[1].Scope] != 1 {
		t.Fatal("a still-valid failure was discarded or retried", err)
	}
	last, err := ActivateServices(context.Background(), selector, routes, again.State, probe, func() time.Time { return now.Add(30 * time.Second) })
	if err != nil || len(last.Selections) != 2 || len(last.BlockedScopes) != 0 || calls[routes[0].Scope] != 1 || calls[routes[1].Scope] != 2 {
		t.Fatal("failure expiry did not restore only its Service", last, calls, err)
	}
	if _, err := Activate(context.Background(), selector, routes, state, probe(routes[0].Scope), func() time.Time { return now }); err == nil {
		t.Fatal("one target measurement was accepted for two Services")
	}
}

func TestSelectorReadbackAcceptsRuntimeStatusFieldsButRejectsAmbiguity(t *testing.T) {
	value, err := decodeSelectorReadback([]byte(`{"type":"Selector","now":"relay","all":["one-hop","relay"],"history":[]}`))
	if err != nil || value != "relay" {
		t.Fatalf("real selector response = %q, %v", value, err)
	}
	for _, body := range []string{`{"type":"Selector"}`, `{"now":"relay"}{"now":"one-hop"}`} {
		if _, err := decodeSelectorReadback([]byte(body)); err == nil {
			t.Fatalf("invalid selector response accepted: %s", body)
		}
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
			activation, err := Activate(ctx, selector, routes, State{Preference: clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeFixed, Exit: "demo-exit"}, NetworkGeneration: "demo-network"}, func(context.Context) ProbeResult {
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
