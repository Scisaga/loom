package clientmodel

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"loom/internal/control"
)

func fixedProbeFallbackFixture() (time.Time, []RouteCandidate, []control.Observation) {
	at, routes, samples, _ := routingEvidenceFixture()
	for i := range routes {
		routes[i].FixedExit, routes[i].FinalExit = true, "demo-fixed"
		routes[i].Chain = []string{"demo-fixed"}
	}
	return at, routes, samples
}

func TestProbeFailureDoesNotRemoveTheOnlyQualifiedAttempt(t *testing.T) {
	at, routes, samples := fixedProbeFallbackFixture()
	samples[0].Result, samples[0].RoundTripMS = "unavailable", nil
	before := samples[0]
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	for _, current := range []string{routes[0].ID, ""} {
		for _, now := range []time.Time{at.Add(time.Second), at.Add(time.Minute)} {
			selection, _, err := ChooseWithNativeStability(routes[:1], nil, nil, samples[:1], nil, pref,
				Selection{Scope: "access", CandidateID: current, Targets: map[string]string{}}, SelectionMemory{}, "demo-local", now, 1000, DefaultPerformanceRule)
			if err != nil || selection.CandidateID != routes[0].ID || len(selection.Targets) != 0 {
				t.Fatal("a diagnostic failure or expiry blocked the only qualified attempt", current, now, selection, err)
			}
		}
	}
	if !reflect.DeepEqual(before, samples[0]) {
		t.Fatal("fallback rewrote the original measurement")
	}
	// Real qualification loss is still terminal, even with a later TCP success.
	routes[0].GraphUnavailable = true
	native := []Observation{nativeSample(routes[0].ID, "demo-c.example:443", "available", at.Add(time.Second), 1)}
	if _, _, err := ChooseWithNativeStability(routes[:1], nil, native, samples[:1], nil, pref, Selection{}, SelectionMemory{}, "demo-local", at.Add(2*time.Second), 2000, DefaultPerformanceRule); !errors.Is(err, ErrNoUsableCandidate) {
		t.Fatal("business evidence revived a path without qualified topology", err)
	}
	if _, err := Select(nil, nil, nil, pref, "", "demo-local", at); !errors.Is(err, ErrNoUsableCandidate) {
		t.Fatal("empty qualification acquired an execution choice", err)
	}
}

func TestForwardProbeFailureRetainsTheOnlyQualifiedNextHop(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	ref := LinkSampleRef{DeviceID: "demo-forward", ResourceID: "demo-exit-resource", LinkID: "demo-exit-link", SpecDigest: control.ReleaseDigest([]byte("demo-exit-spec")), Target: "[fdab::2]:53", Action: "wireguard_echo"}
	route := RouteCandidate{ID: "demo-exit-sender", PolicyID: "demo-policy", FixedExit: true, SourceNode: ref.DeviceID, FinalExit: "demo-exit", Chain: []string{ref.DeviceID, "demo-exit"}, Scope: "demo-forward-scope", RelayLinks: []LinkSampleRef{ref}}
	failed := control.Observation{Level: "link", ResourceID: ref.ResourceID, LinkID: ref.LinkID, SpecDigest: ref.SpecDigest, Target: ref.Target, Action: ref.Action, NetworkGeneration: "demo-network", Result: "unavailable", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli(), DurationMS: new(int64(8))}
	choices, _, err := ChooseForwardWithStability([]RouteCandidate{route}, []control.Observation{failed}, nil, Preference{Schema: 3, PolicyID: route.PolicyID}, Selection{Scope: route.Scope, CandidateID: route.ID, Targets: map[string]string{}}, SelectionMemory{}, "demo-network", at.Add(time.Second), 1000, DefaultPerformanceRule)
	if err != nil || !reflect.DeepEqual(choices, []string{route.ID}) {
		t.Fatal("forward diagnostic failure removed the last lawful next-hop attempt", choices, err)
	}
}

func TestProbeFailureUsesAnAlternativeWithoutPerformanceCooldown(t *testing.T) {
	at, routes, samples := fixedProbeFallbackFixture()
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{}}
	selection, memory, err := ChooseWithStability(routes, nil, samples, nil, pref, current, SelectionMemory{}, "demo-local", at, 0, DefaultPerformanceRule)
	if err != nil {
		t.Fatal(err)
	}
	memory, err = ConfirmSelection(memory, selection, 0)
	if err != nil {
		t.Fatal(err)
	}
	samples[0].Result, samples[0].RoundTripMS = "unavailable", nil
	samples[0].ObservedAt = at.Add(time.Second).UnixMilli()
	for _, available := range [][]control.Observation{samples, samples[:1]} {
		got, _, err := ChooseWithStability(routes, nil, available, nil, pref, current, memory, "demo-local", at.Add(2*time.Second), 2000, DefaultPerformanceRule)
		if err != nil || got.CandidateID != routes[1].ID {
			t.Fatal("a qualified available/unknown alternative waited for performance cooldown", got, err)
		}
	}
	samples[1].Result, samples[1].RoundTripMS = "unavailable", nil
	for _, actual := range []string{routes[0].ID, ""} {
		got, _, err := ChooseWithStability(routes, nil, samples, nil, pref, Selection{Scope: "access", CandidateID: actual, Targets: map[string]string{}}, memory, "demo-local", at.Add(2*time.Second), 2000, DefaultPerformanceRule)
		if err != nil || got.CandidateID == "" || actual != "" && got.CandidateID != actual {
			t.Fatal("all-negative diagnostics prevented an attempt or displaced the lawful current path", got, err)
		}
	}
}

func TestProbeFallbackRecoveryDoesNotRepeatInitialDiscovery(t *testing.T) {
	at, routes, samples := fixedProbeFallbackFixture()
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{}}
	_, memory, err := ChooseWithStability(routes, nil, samples[:1], nil, pref, current, SelectionMemory{}, "demo-local", at, 0, DefaultPerformanceRule)
	if err != nil {
		t.Fatal(err)
	}
	memory, err = ConfirmSelection(memory, current, 0)
	if err != nil {
		t.Fatal(err)
	}
	choose := func(seconds int64, observed []control.Observation) Selection {
		t.Helper()
		selection, next, err := ChooseWithStability(routes, nil, observed, nil, pref, current, memory, "demo-local", at.Add(time.Duration(seconds)*time.Second), seconds*1000, DefaultPerformanceRule)
		if err != nil {
			t.Fatal(err)
		}
		memory = next
		return selection
	}
	samples[0].Result, samples[0].RoundTripMS = "unavailable", nil
	samples[0].ObservedAt = at.Add(time.Second).UnixMilli()
	fallback := choose(2, samples[:1])
	if fallback.CandidateID != routes[1].ID {
		t.Fatal("diagnostic fault failed to explore the unknown alternative", fallback)
	}
	memory, err = ConfirmSelection(memory, fallback, 2000)
	if err != nil {
		t.Fatal(err)
	}
	current = fallback
	samples[0].Result, samples[0].RoundTripMS = "available", new(int64(10))
	samples[0].ObservedAt = at.Add(3 * time.Second).UnixMilli()
	if got := choose(4, samples[:1]); got.CandidateID != current.CandidateID {
		t.Fatal("the first recovery sample bypassed confirmation/cooldown as initial discovery", got)
	}
	for i := range samples {
		samples[i].ObservedAt = at.Add(5 * time.Second).UnixMilli()
	}
	if got := choose(6, samples); got.CandidateID != current.CandidateID {
		t.Fatal("the first comparable improvement bypassed confirmation", got)
	}
	for i := range samples {
		samples[i].ObservedAt = at.Add(7 * time.Second).UnixMilli()
	}
	if got := choose(8, samples); got.CandidateID != current.CandidateID {
		t.Fatal("sustained improvement bypassed the minimum interval", got)
	}
	if got := choose(34, samples); got.CandidateID != routes[0].ID {
		t.Fatal("sustained comparable recovery did not optimize after the interval", got)
	}
}

func TestNativeTCPSuccessRefutesOnlyAnEarlierProvenFirstHopFailure(t *testing.T) {
	at, routes, samples := fixedProbeFallbackFixture()
	samples[0].Result, samples[0].RoundTripMS = "unavailable", nil
	samples[0].ObservedAt = at.Add(2 * time.Second).UnixMilli()
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	for _, test := range []struct {
		name      string
		sample    Observation
		recovered bool
	}{
		{"later", nativeSample(routes[0].ID, "demo-c.example:443", "available", at.Add(3*time.Second), 1), true},
		{"older", nativeSample(routes[0].ID, "demo-c.example:443", "available", at.Add(time.Second), 1), false},
		{"older attempt finishes later", nativeSample(routes[0].ID, "demo-c.example:443", "available", at.Add(time.Second), 2500), false},
		{"equal", nativeSample(routes[0].ID, "demo-c.example:443", "available", at.Add(2*time.Second), 0), false},
		{"unknown", nativeSample(routes[0].ID, "demo-c.example:443", "unknown", at.Add(3*time.Second), 1), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			evaluation, err := evaluateNativeRouting(routes, nil, []Observation{test.sample}, samples, nil, pref, routes[0].ID, "demo-local", at.Add(4*time.Second), nil)
			path, found := evaluation.paths[routes[0].ID]
			if err != nil || !found || path.failed == test.recovered || test.recovered && (!path.entryReady || path.cost != nil) {
				t.Fatal("native TCP did not preserve the temporal/proven-dependency boundary", path, found, err)
			}
		})
	}
	late := nativeSample(routes[0].ID, "demo-c.example:443", "available", at.Add(3*time.Second), 1)
	for _, alter := range []func(*Observation){
		func(v *Observation) { v.NetworkGeneration = "demo-other-network" },
		func(v *Observation) { v.CandidateID = routes[1].ID },
		func(v *Observation) { v.ValidUntil = at.Add(4 * time.Second).Format(time.RFC3339Nano) },
	} {
		changed := late
		alter(&changed)
		evaluation, err := evaluateNativeRouting(routes, nil, []Observation{changed}, samples, nil, pref, routes[0].ID, "demo-local", at.Add(4*time.Second), nil)
		if err != nil || !evaluation.paths[routes[0].ID].failed {
			t.Fatal("unrelated or expired TCP erased a first-hop failure", err)
		}
	}
	// A candidate fixes its local first hop, but forward chooses the suffix.
	// A positive TCP event carries no proof that it used this remote link.
	ref := LinkSampleRef{DeviceID: "demo-entry", ResourceID: "demo-relay-resource", LinkID: "demo-relay-link", SpecDigest: control.ReleaseDigest([]byte("demo-relay-spec")), Target: "[fdab::2]:53", Action: "wireguard_echo"}
	routes[0].Chain = []string{"demo-entry", "demo-fixed"}
	routes[0].RelayLinks = []LinkSampleRef{ref}
	remote := control.Observation{Level: "link", ResourceID: ref.ResourceID, LinkID: ref.LinkID, SpecDigest: ref.SpecDigest, Target: ref.Target, Action: ref.Action, NetworkGeneration: "demo-remote-network", Result: "unavailable", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli(), DurationMS: new(int64(8))}
	shared := []control.DeviceLinkObservation{{DeviceID: ref.DeviceID, ReportSequence: 1, ReportDigest: control.ReleaseDigest([]byte("demo-remote-report")), CurrentUntil: remote.ValidUntil, Observation: remote}}
	evaluation, err := evaluateNativeRouting(routes, nil, []Observation{late}, samples, shared, pref, routes[0].ID, "demo-local", at.Add(4*time.Second), nil)
	if err != nil || !evaluation.paths[routes[0].ID].failed {
		t.Fatal("TCP success erased an unobserved remote relay failure", err)
	}
	// Local first-hop success cannot make a non-fixed path with a failed remote
	// suffix outrank an unknown, qualified alternative to another exit.
	for i := range routes {
		routes[i].FixedExit = false
	}
	routes[1].FinalExit, routes[1].Chain = "demo-other-exit", []string{"demo-other-exit"}
	outerSamples := []control.Observation{samples[0]}
	outerSamples[0].Result, outerSamples[0].RoundTripMS = "available", new(int64(10))
	got, err := SelectWithLinks(routes, nil, outerSamples, shared, pref, routes[0].ID, "demo-local", at.Add(4*time.Second))
	if err != nil || got.CandidateID != routes[1].ID {
		t.Fatal("an entry-ready but diagnostic-failed suffix outranked an unknown legal path", got, err)
	}
}
