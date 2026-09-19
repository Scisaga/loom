package clientadapter

import (
	"context"
	"errors"
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

func (*fakeSelector) CloseConnections(context.Context) error { return nil }

func TestActivateUsesReadbackAndOneSameExitFallback(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	routes := []clientmodel.RouteCandidate{
		{ID: "one-hop", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "internet"},
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-relay", "demo-exit"}, Scope: "internet"},
	}
	selector := &fakeSelector{current: map[string]string{"internet": "one-hop"}}
	results := []ProbeResult{{Available: false, Metric: time.Second}, {Available: true, Metric: 2 * time.Second}}
	activation, err := Activate(context.Background(), selector, routes, State{
		Preference:        clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeFixed, Exit: "demo-exit"},
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
