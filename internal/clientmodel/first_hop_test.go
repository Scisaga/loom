package clientmodel

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"loom/internal/control"
)

func firstHopSelectionFixture() ([]RouteCandidate, []control.Observation, time.Time) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	var routes []RouteCandidate
	var samples []control.Observation
	for _, id := range []string{"a", "b", "c"} {
		ref := &ResourceSampleRef{ResourceID: "demo-resource-" + id, SpecDigest: "sha256:" + strings.Repeat(id, 64), Target: "demo.example:443", Action: "hysteria2_tls"}
		routes = append(routes, RouteCandidate{ID: "demo-" + id, FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "service:demo-web", FirstHop: ref})
		samples = append(samples, control.Observation{Level: "resource", ResourceID: ref.ResourceID, SpecDigest: ref.SpecDigest, Target: ref.Target, Action: ref.Action,
			NetworkGeneration: "demo-network", Result: "available", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli()})
	}
	return routes, samples, at
}

func TestFirstHopFailureRequiresExactExecutionAndOriginalWindow(t *testing.T) {
	routes, samples, at := firstHopSelectionFixture()
	failed := samples[0]
	failed.Result = "unavailable"
	pref := Preference{Schema: 3, Mode: ModeFixed, Exit: "demo-exit"}
	for _, tc := range []struct {
		name   string
		change func(*control.Observation)
	}{
		{"credential or execution", func(v *control.Observation) { v.SpecDigest = "sha256:" + strings.Repeat("d", 64) }},
		{"resource", func(v *control.Observation) { v.ResourceID = "demo-another-resource" }},
		{"network", func(v *control.Observation) { v.NetworkGeneration = "demo-other-network" }},
		{"target", func(v *control.Observation) { v.Target = "other.example:443" }},
		{"action", func(v *control.Observation) { v.Action = "wireguard_dns" }},
		{"future sample", func(v *control.Observation) { v.ObservedAt = at.Add(time.Second).UnixMilli() }},
		{"expired", func(v *control.Observation) { v.ObservedAt--; v.ValidUntil = at.UnixMilli() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := failed
			tc.change(&value)
			selected, err := Select(routes[:1], nil, []control.Observation{value}, pref, "demo-a", "demo-network", at)
			if err != nil || selected.CandidateID != "demo-a" {
				t.Fatal("out-of-scope or expired failure excluded an authorized path", selected, err)
			}
		})
	}
	if _, err := Select(routes[:1], nil, []control.Observation{failed}, pref, "demo-a", "demo-network", at); !errors.Is(err, ErrNoUsableCandidate) {
		t.Fatal("matching authentication failure was ignored", err)
	}
	selected, err := Select(routes, nil, []control.Observation{failed}, pref, "demo-a", "demo-network", at)
	if err != nil || selected.CandidateID != "demo-b" {
		t.Fatal("failed first hop did not permit another path to the same final exit", selected, err)
	}
}

func TestFirstHopSuccessOrdersAttemptsWithoutCreatingBusinessHealth(t *testing.T) {
	routes, samples, at := firstHopSelectionFixture()
	const target = "https://demo.example/"
	pref := Preference{Schema: 3, Mode: ModeAuto}
	positive := samples[1:2]
	for _, current := range []string{"", "demo-a"} {
		want := "demo-b"
		if current != "" {
			want = current
		}
		selected, err := Select(routes, nil, positive, pref, current, "demo-network", at, target)
		state, _ := ObservationState(nil, selected.CandidateID, routes[0].Scope, "demo-network", []string{target}, at)
		if err != nil || selected.CandidateID != want || state != "unknown" {
			t.Fatal("resource success invented health or displaced an unfailed current selection", selected, state, err)
		}
	}
	failed := Observation{CandidateID: "demo-b", Scope: routes[0].Scope, NetworkGeneration: "demo-network", Target: target, Action: "https_request", Result: "unavailable", ObservedAt: at.Format(time.RFC3339), ValidUntil: at.Add(time.Minute).Format(time.RFC3339)}
	selected, err := Select(routes, []Observation{failed}, positive, pref, "demo-b", "demo-network", at, target)
	if err != nil || selected.CandidateID != "demo-a" {
		t.Fatal("first-hop success overrode the failed Service", selected, err)
	}
}

func TestBusinessRecoveryAndPartialTargetsPreserveTheirScope(t *testing.T) {
	routes, samples, at := firstHopSelectionFixture()
	const target = "https://demo.example/"
	failed := samples[0]
	failed.Result = "unavailable"
	failed.ObservedAt += 500 // A same-second business result cannot be ordered before this fraction.
	pref := Preference{Schema: 3, Mode: ModeAuto}
	for _, tc := range []struct {
		name, target, scope string
		delta               time.Duration
		want                string
	}{
		{"later success", target, routes[0].Scope, time.Second, "demo-a"},
		{"same time success", target, routes[0].Scope, 0, "demo-a"},
		{"older success", target, routes[0].Scope, -time.Second, "demo-b"},
		{"future success", target, routes[0].Scope, 3 * time.Second, "demo-b"},
		{"other target", "https://other.example/", routes[0].Scope, time.Second, "demo-b"},
		{"other Service", target, "service:demo-other", time.Second, "demo-b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			good := Observation{CandidateID: "demo-a", Scope: tc.scope, NetworkGeneration: "demo-network", Target: tc.target, Action: "https_request", Result: "available", ObservedAt: at.Add(tc.delta).Format(time.RFC3339), ValidUntil: at.Add(time.Minute).Format(time.RFC3339)}
			partial := good
			partial.Target, partial.Result = "https://demo.example/other", "unavailable"
			selected, err := Select(routes, []Observation{good, partial}, []control.Observation{failed}, pref, "demo-a", "demo-network", at.Add(2*time.Second), target, partial.Target)
			if err != nil || selected.CandidateID != tc.want {
				t.Fatal("business recovery borrowed a target/scope or failed to supersede old authentication", selected, err)
			}
		})
	}
}

func TestFirstHopAttemptOrderIsDeterministicAndDoesNotRefreshSamples(t *testing.T) {
	routes, samples, at := firstHopSelectionFixture()
	samples[0].Result = "unavailable"
	before := append([]control.Observation(nil), samples...)
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		values := []RouteCandidate{routes[order[0]], routes[order[1]], routes[order[2]]}
		resources := []control.Observation{samples[order[2]], samples[order[1]], samples[order[0]]}
		selected, err := Select(values, nil, resources, Preference{Schema: 3, Mode: ModeAuto}, "demo-a", "demo-network", at)
		if err != nil || selected.CandidateID != "demo-b" {
			t.Fatal("input order changed selection", order, selected, err)
		}
	}
	if !reflect.DeepEqual(before, samples) {
		t.Fatal("selection rewrote an original resource sample")
	}
	if _, err := Select(routes, nil, []control.Observation{samples[0], samples[0]}, Preference{Schema: 3, Mode: ModeAuto}, "", "demo-network", at); err == nil {
		t.Fatal("duplicate samples were silently resolved")
	}
	for i := range samples {
		samples[i].Result = "unavailable"
		samples[i].ObservedAt = at.Add(time.Duration(2-i) * time.Second).UnixMilli()
		samples[i].ValidUntil = samples[i].ObservedAt + 1000
	}
	selected, err := Select(routes, nil, samples, Preference{Schema: 3, Mode: ModeAuto}, "demo-a", "demo-network", at.Add(4*time.Second))
	if err != nil || selected.CandidateID != "demo-c" {
		t.Fatal("expired first-hop failures starved the oldest untried path", selected, err)
	}
}

func TestFutureBusinessSamplesCannotDetermineCurrentHealthOrAttemptOrder(t *testing.T) {
	routes, _, at := firstHopSelectionFixture()
	const target = "https://demo.example/"
	for _, result := range []string{"available", "unavailable"} {
		sample := Observation{CandidateID: "demo-a", Scope: routes[0].Scope, NetworkGeneration: "demo-network", Target: target, Action: "https_request", Result: result, ObservedAt: at.Add(time.Second).Format(time.RFC3339), ValidUntil: at.Add(time.Minute).Format(time.RFC3339)}
		selected, err := Select(routes, []Observation{sample}, nil, Preference{Schema: 3, Mode: ModeAuto}, "demo-a", "demo-network", at, target)
		state, _ := ObservationState([]Observation{sample}, "demo-a", routes[0].Scope, "demo-network", []string{target}, at)
		if err != nil || selected.CandidateID != "demo-a" || state != "unknown" || sample.CurrentAt(at) {
			t.Fatal("a sample after the caller's time was treated as current evidence", selected, state, err)
		}
	}
}
