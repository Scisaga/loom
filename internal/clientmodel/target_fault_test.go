package clientmodel

import (
	"testing"
	"time"
)

// The algorithm currently accepts HTTPS outcomes for an actual target outside
// the configured probe set. Native connection outcomes remain a separate input
// gap; these vectors do not claim that the ordinary-traffic producer is wired.
func targetFaultSample(candidate, target, result string, at time.Time) Observation {
	return Observation{CandidateID: candidate, Scope: "access", Target: target, Action: "https_request", NetworkGeneration: "demo-local", Result: result,
		ObservedAt: at.Format(time.RFC3339), ValidUntil: at.Add(10 * time.Minute).Format(time.RFC3339)}
}

func TestTargetFailureExploresUnknownSlowerRouteAndRecoveryStillUsesPerformanceRules(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		probes []string
	}{
		{"without-probes", nil},
		{"unrelated-probe", []string{"https://demo-probe.example/health"}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			testTargetFailureAndRecovery(t, scenario.probes)
		})
	}
}

func testTargetFailureAndRecovery(t *testing.T, probes []string) {
	t.Helper()
	at, routes, resources, _ := routingEvidenceFixture()
	for i := range resources {
		resources[i].ValidUntil = at.Add(10 * time.Minute).UnixMilli()
	}
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{"tcp://demo-d.example:443": routes[1].ID}}
	_, memory, err := ChooseWithStability(routes, nil, resources, nil, pref, current, SelectionMemory{}, "demo-local", at, 0, DefaultPerformanceRule, probes...)
	if err != nil {
		t.Fatal(err)
	}
	target, origin := "https://demo-c.example/ordinary", "tcp://demo-c.example:443"
	observations := []Observation{targetFaultSample(routes[0].ID, target, "unavailable", at.Add(time.Second))}
	choose := func(seconds int64) Selection {
		t.Helper()
		selected, next, err := ChooseWithStability(routes, observations, resources, nil, pref, current, memory, "demo-local", at.Add(time.Duration(seconds)*time.Second), seconds*1000, DefaultPerformanceRule, probes...)
		if err != nil {
			t.Fatal(err)
		}
		memory = next
		if selected.CandidateID != routes[0].ID || selected.Targets["tcp://demo-d.example:443"] != routes[1].ID {
			t.Fatal("one target's failure changed the default or an unrelated target", selected)
		}
		return selected
	}
	selected := choose(2)
	if selected.Targets[origin] != routes[1].ID {
		t.Fatal("a definite target failure waited for a slower unknown route to prove performance improvement", selected)
	}
	if memory.Decisions[origin].Current == routes[1].ID {
		t.Fatal("a proposed fault response was recorded as applied")
	}
	memory, err = ConfirmSelection(memory, selected, 2000)
	if err != nil {
		t.Fatal(err)
	}
	current = selected
	if selected = choose(3); selected.Targets[origin] != routes[1].ID {
		t.Fatal("unknown fallback returned to the failed faster route", selected)
	}
	// Fresh recovery is a performance improvement while the selected fallback
	// itself has not failed. It still needs distinct evidence and its interval.
	observations = []Observation{targetFaultSample(routes[0].ID, target, "available", at.Add(3*time.Second))}
	if selected = choose(3); selected.Targets[origin] != routes[1].ID || memory.Decisions[origin].Confirmations != 1 {
		t.Fatal("first recovery sample skipped confirmation or cooldown", selected, memory.Decisions[origin])
	}
	if selected = choose(3); selected.Targets[origin] != routes[1].ID || memory.Decisions[origin].Confirmations != 1 {
		t.Fatal("replayed recovery was counted as a new measurement", selected, memory.Decisions[origin])
	}
	observations = []Observation{targetFaultSample(routes[0].ID, target, "available", at.Add(4*time.Second))}
	for i := range resources {
		resources[i].ObservedAt = at.Add(4 * time.Second).UnixMilli()
	}
	if selected = choose(4); selected.Targets[origin] != routes[1].ID || memory.Decisions[origin].Confirmations != 2 {
		t.Fatal("two recovery samples bypassed the minimum interval", selected, memory.Decisions[origin])
	}
	if selected = choose(34); selectedTarget(selected, origin) != routes[0].ID {
		t.Fatal("sustained recovery remained blocked after the interval", selected)
	}
}

func TestAllFailedTargetRoutesKeepCurrentDespiteFasterTransport(t *testing.T) {
	at, routes, resources, _ := routingEvidenceFixture()
	for i := range resources {
		resources[i].ValidUntil = at.Add(10 * time.Minute).UnixMilli()
	}
	target, origin := "https://demo-c.example/ordinary", "tcp://demo-c.example:443"
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{origin: routes[1].ID}}
	_, memory, err := ChooseWithStability(routes, nil, resources, nil, pref, current, SelectionMemory{}, "demo-local", at, 0, DefaultPerformanceRule)
	if err != nil {
		t.Fatal(err)
	}
	observations := []Observation{targetFaultSample(routes[0].ID, target, "unavailable", at.Add(time.Second)), targetFaultSample(routes[1].ID, target, "unavailable", at.Add(time.Second))}
	for _, seconds := range []int64{35, 36, 90} {
		for i := range resources {
			resources[i].ObservedAt = at.Add(time.Duration(seconds) * time.Second).UnixMilli()
		}
		selected, next, err := ChooseWithStability(routes, observations, resources, nil, pref, current, memory, "demo-local", at.Add(time.Duration(seconds)*time.Second), seconds*1000, DefaultPerformanceRule)
		if err != nil || selected.CandidateID != current.CandidateID || selected.Targets[origin] != routes[1].ID || next.Decisions[origin].Pending != "" {
			t.Fatal("known-failed targets oscillated on transport cost", selected, err)
		}
		memory = next
	}
	if state, err := ObservationState(observations, routes[1].ID, "access", "demo-local", []string{target}, at.Add(90*time.Second)); err != nil || state != "unavailable" {
		t.Fatal("keeping the selection invented target success", state, err)
	}
}

func TestUnknownTargetFallbackDoesNotReturnToFailedFasterRoute(t *testing.T) {
	at, routes, resources, _ := routingEvidenceFixture()
	for i := range resources {
		resources[i].ValidUntil = at.Add(10 * time.Minute).UnixMilli()
	}
	target, origin := "https://demo-c.example/ordinary", "tcp://demo-c.example:443"
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{origin: routes[1].ID}}
	memory, err := ConfirmSelection(SelectionMemory{PolicyID: pref.PolicyID, NetworkGeneration: "demo-local"}, current, 2000)
	if err != nil {
		t.Fatal(err)
	}
	observations := []Observation{targetFaultSample(routes[0].ID, target, "unavailable", at.Add(time.Second))}
	for _, seconds := range []int64{3, 35, 90} {
		for i := range resources {
			resources[i].ObservedAt = at.Add(time.Duration(seconds) * time.Second).UnixMilli()
		}
		selected, next, err := ChooseWithStability(routes, observations, resources, nil, pref, current, memory, "demo-local", at.Add(time.Duration(seconds)*time.Second), seconds*1000, DefaultPerformanceRule)
		if err != nil || selected.CandidateID != current.CandidateID || selected.Targets[origin] != routes[1].ID {
			t.Fatal("unknown fallback returned to a known-failed faster route", selected, err)
		}
		memory = next
	}
}

func TestTargetFaultRequiresCurrentDefiniteEvidenceAndNeverOverridesFixedExit(t *testing.T) {
	for _, scenario := range []string{"unknown", "expired", "future", "other-network", "cancelled", "fixed-exit"} {
		t.Run(scenario, func(t *testing.T) {
			at, routes, resources, _ := routingEvidenceFixture()
			if scenario == "fixed-exit" {
				for i := range routes {
					routes[i].FixedExit, routes[i].FinalExit = true, "demo-fixed"
					routes[i].Chain = []string{"demo-fixed"}
				}
			}
			pref := Preference{Schema: 3, PolicyID: "demo-policy"}
			current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{}}
			_, memory, err := ChooseWithStability(routes, nil, resources, nil, pref, current, SelectionMemory{}, "demo-local", at, 0, DefaultPerformanceRule)
			if err != nil {
				t.Fatal(err)
			}
			sample := targetFaultSample(routes[0].ID, "https://demo-c.example/ordinary", "unavailable", at)
			switch scenario {
			case "unknown":
				sample.Result = "unknown"
			case "expired":
				sample.ValidUntil = at.Add(time.Second).Format(time.RFC3339)
			case "future":
				sample.ObservedAt = at.Add(3 * time.Second).Format(time.RFC3339)
			case "other-network":
				sample.NetworkGeneration = "demo-previous"
			}
			observations := []Observation{sample}
			if scenario == "cancelled" {
				observations = nil // Cancellation produces no failure observation.
			}
			selected, _, err := ChooseWithStability(routes, observations, resources, nil, pref, current, memory, "demo-local", at.Add(2*time.Second), 2000, DefaultPerformanceRule)
			if err != nil || selected.CandidateID != current.CandidateID || len(selected.Targets) != 0 {
				t.Fatal("non-failure evidence or fixed exit created a target-specific switch", selected, err)
			}
		})
	}
}
