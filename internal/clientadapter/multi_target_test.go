package clientadapter

import (
	"context"
	"loom/internal/clientmodel"
	"testing"
	"time"
)

func TestMultipleTargetsRetainPartialPathAndRetryOnlyExpiredTarget(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	scope := "service:demo-service"
	routes := []clientmodel.RouteCandidate{{ID: "demo-a", FinalExit: "direct", Scope: scope}, {ID: "demo-b", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: scope}}
	selector := &fakeSelector{current: map[string]string{scope: "demo-a"}}
	state := State{Preference: clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeAuto}, NetworkGeneration: "demo-network"}
	calls := map[string]int{}
	recovered := false
	probes := Probes{}
	for _, target := range []string{"https://demo.example/a", "https://demo.example/b"} {
		probes[target] = func(context.Context) ProbeResult {
			calls[target]++
			return ProbeResult{Available: target == "https://demo.example/b" || recovered, Action: "https_request"}
		}
	}
	first, err := Activate(context.Background(), selector, routes, state, probes, func() time.Time { return at })
	if err != nil || selector.current[scope] != "demo-a" || len(first.State.Observations) != 2 || first.Selections[0].State != "unknown" {
		t.Fatal("partial results replaced the path or overwrote each other", first, err)
	}
	if first.State.Observations[0].Target != "https://demo.example/a" || first.State.Observations[0].Result != "unavailable" || first.State.Observations[1].Result != "available" {
		t.Fatal("target attribution lost", first)
	}
	recovered = true
	second, err := Activate(context.Background(), selector, routes, first.State, probes, func() time.Time { return at.Add(30 * time.Second) })
	if err != nil || second.Selections[0].State != "available" || calls["https://demo.example/a"] != 2 || calls["https://demo.example/b"] != 1 || second.State.Observations[1] != first.State.Observations[1] {
		t.Fatal("expiry repeated or renewed a still-valid target", second, calls, err)
	}
}

func TestAllTargetFailuresFallbackOnlyTheirService(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	scope := "service:demo-service"
	routes := []clientmodel.RouteCandidate{{ID: "demo-a", FinalExit: "direct", Scope: scope}, {ID: "demo-b", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: scope}, {ID: "demo-other", FinalExit: "direct", Scope: "service:demo-other"}}
	selector := &fakeSelector{current: map[string]string{scope: "demo-a", "service:demo-other": "demo-other"}}
	calls := map[string]int{}
	factory := func(service string) Probes {
		probes := Probes{}
		for _, target := range []string{"https://demo.example/a", "https://demo.example/b"} {
			probes[target] = func(context.Context) ProbeResult {
				id := selector.current[service]
				calls[id]++
				return ProbeResult{Available: id != "demo-a", Action: "https_request"}
			}
		}
		return probes
	}
	result, err := ActivateServices(context.Background(), selector, routes, State{Preference: clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeAuto}, NetworkGeneration: "demo-network"}, factory, func() time.Time { return at })
	if err != nil || selector.current[scope] != "demo-b" || selector.current["service:demo-other"] != "demo-other" || calls["demo-a"] != 2 || calls["demo-b"] != 2 || calls["demo-other"] != 2 || len(result.State.Observations) != 6 {
		t.Fatal("failure was applied before all targets or escaped its Service", result, calls, err)
	}
}
