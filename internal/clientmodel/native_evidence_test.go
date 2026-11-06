package clientmodel

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"loom/internal/control"
)

func nativeSample(candidate, target, result string, started time.Time, millis int64) Observation {
	completed := started.Add(time.Duration(millis) * time.Millisecond)
	return Observation{CandidateID: candidate, Scope: "access", Target: target, Action: "tcp_connect", NetworkGeneration: "demo-local", Result: result,
		ObservedAt: completed.Format(time.RFC3339Nano), ValidUntil: completed.Add(time.Minute).Format(time.RFC3339Nano), MetricMillis: millis}
}

func TestNativeTCPFailureExploresOnlyItsTCPKeyAndRecoveryStaysStable(t *testing.T) {
	at, routes, resources, _ := routingEvidenceFixture()
	for i := range resources {
		resources[i].ValidUntil = at.Add(2 * time.Minute).UnixMilli()
	}
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{"udp://demo-c.example:443": routes[0].ID}}
	_, memory, err := ChooseWithNativeStability(routes, nil, nil, resources, nil, pref, current, SelectionMemory{}, "demo-local", at, 0, DefaultPerformanceRule)
	if err != nil {
		t.Fatal(err)
	}
	native := []Observation{nativeSample(routes[0].ID, "demo-c.example:443", "unavailable", at.Add(time.Second), 250)}
	choose := func(seconds int64) Selection {
		t.Helper()
		got, next, err := ChooseWithNativeStability(routes, nil, native, resources, nil, pref, current, memory, "demo-local", at.Add(time.Duration(seconds)*time.Second), seconds*1000, DefaultPerformanceRule)
		if err != nil {
			t.Fatal(err)
		}
		memory = next
		return got
	}
	selected := choose(2)
	key := "tcp://demo-c.example:443"
	if selected.CandidateID != routes[0].ID || selected.Targets[key] != routes[1].ID || selectedTarget(selected, "udp://demo-c.example:443") != routes[0].ID {
		t.Fatal("ordinary TCP fault changed another target, UDP, or default", selected)
	}
	memory, err = ConfirmSelection(memory, selected, 2000)
	if err != nil {
		t.Fatal(err)
	}
	current = selected
	native = []Observation{nativeSample(routes[0].ID, "demo-c.example:443", "available", at.Add(3*time.Second), 25)}
	if selected = choose(4); selected.Targets[key] != routes[1].ID || memory.Decisions[key].Confirmations != 1 {
		t.Fatal("recovery bypassed confirmation", selected, memory)
	}
	if selected = choose(4); selected.Targets[key] != routes[1].ID || memory.Decisions[key].Confirmations != 1 {
		t.Fatal("replayed recovery counted twice", selected, memory)
	}
	native = append(native, nativeSample(routes[0].ID, "demo-c.example:443", "available", at.Add(3*time.Second), 50))
	if selected = choose(4); selected.Targets[key] != routes[1].ID || memory.Decisions[key].Confirmations != 1 {
		t.Fatal("same-start duplicate recovery counted as a new attempt", selected, memory)
	}
	native = []Observation{nativeSample(routes[0].ID, "demo-c.example:443", "available", at.Add(5*time.Second), 25)}
	// Target confirmation is a gate; the second performance vote comes from
	// newly measured segments, independently of TCP completion timestamps.
	for i := range resources {
		resources[i].ObservedAt = at.Add(5 * time.Second).UnixMilli()
	}
	if selected = choose(6); selected.Targets[key] != routes[1].ID {
		t.Fatal("recovery bypassed minimum interval", selected)
	}
	if selected = choose(34); selectedTarget(selected, key) != routes[0].ID {
		t.Fatal("sustained recovery never optimized", selected)
	}
}

func TestNativeTCPLatestAttemptWinsAndConflictingStartIsUnknown(t *testing.T) {
	at, routes, resources, _ := routingEvidenceFixture()
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{}}
	oldSlow := nativeSample(routes[0].ID, "demo-c.example:443", "available", at.Add(time.Second), 5000)
	newFailure := nativeSample(routes[0].ID, "demo-c.example:443", "unavailable", at.Add(2*time.Second), 100)
	for _, values := range [][]Observation{{oldSlow, newFailure}, {newFailure, oldSlow}} {
		got, _, err := ChooseWithNativeStability(routes, nil, values, resources, nil, pref, current, SelectionMemory{}, "demo-local", at.Add(7*time.Second), 7000, DefaultPerformanceRule)
		if err != nil || got.Targets["tcp://demo-c.example:443"] != routes[1].ID {
			t.Fatal("late completion replaced newer attempt", got, err)
		}
	}
	conflict := nativeSample(routes[0].ID, "demo-c.example:443", "available", at.Add(2*time.Second), 200)
	got, _, err := ChooseWithNativeStability(routes, nil, []Observation{newFailure, conflict, newFailure}, resources, nil, pref, current, SelectionMemory{}, "demo-local", at.Add(7*time.Second), 7000, DefaultPerformanceRule)
	if err != nil || len(got.Targets) != 0 {
		t.Fatal("same-start conflict invented a fault or success", got, err)
	}
}

func TestNativeTCPSameStartSameOutcomeRetainsOneRealSample(t *testing.T) {
	at, routes, resources, _ := routingEvidenceFixture()
	early := nativeSample(routes[1].ID, "demo-c.example:443", "available", at, 25)
	later := nativeSample(routes[1].ID, "demo-c.example:443", "available", at, 50)
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{}}
	for _, samples := range [][]Observation{{early, later}, {later, early}} {
		got, _, err := ChooseWithNativeStability(routes, nil, samples, resources, nil, pref, current, SelectionMemory{}, "demo-local", at.Add(time.Second), 1000, DefaultPerformanceRule)
		if err != nil || got.Targets["tcp://demo-c.example:443"] != routes[1].ID {
			t.Fatal("same-start successes were changed into conflicting evidence", got, err)
		}
		evaluation, err := evaluateNativeRouting(routes, nil, samples, resources, nil, pref, current.CandidateID, "demo-local", at.Add(time.Second), nil)
		fact := evaluation.native[routes[1].ID]["tcp://demo-c.example:443"]
		completed, _ := time.Parse(time.RFC3339Nano, early.ObservedAt)
		deadline, _ := time.Parse(time.RFC3339Nano, early.ValidUntil)
		if err != nil || fact.at != completed.UnixMilli() || fact.until != deadline.UnixMilli() || fact.conflict {
			t.Fatal("duplicate delivery replaced the original completion or deadline", fact, err)
		}
	}
}

func TestNativeTCPDoesNotChangeHTTPSCoverageAndOnlyRefutesItsFirstHop(t *testing.T) {
	at, routes, resources, egress := routingEvidenceFixture()
	url := "https://demo-c.example/health"
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{}}
	https := []Observation{targetFaultSample(routes[0].ID, url, "unavailable", at)}
	native := []Observation{nativeSample(routes[0].ID, "demo-c.example:443", "available", at.Add(time.Second), 30)}
	got, _, err := ChooseWithNativeStability(routes, https, native, resources, nil, pref, current, SelectionMemory{}, "demo-local", at.Add(2*time.Second), 2000, DefaultPerformanceRule, url)
	if err != nil || got.Targets["tcp://demo-c.example:443"] != routes[1].ID {
		t.Fatal("TCP success cleared HTTPS failure", got, err)
	}
	if state, err := ObservationState(native, routes[0].ID, "access", "demo-local", []string{url}, at.Add(2*time.Second)); err != nil || state != "unknown" {
		t.Fatal("TCP counted as HTTPS", state, err)
	}
	// Service coverage still favors the exit with its own URL evidence.
	shared := []control.DeviceLinkObservation{egress(routes[1].FinalExit, url, "available", 0)}
	got, _, err = ChooseWithNativeStability(routes, nil, native, resources, shared, pref, Selection{}, SelectionMemory{}, "demo-local", at.Add(2*time.Second), 2000, DefaultPerformanceRule, url)
	if err != nil || got.CandidateID != routes[1].ID {
		t.Fatal("TCP increased Service coverage", got, err)
	}
	resources[0].Result, resources[0].RoundTripMS = "unavailable", nil
	got, _, err = ChooseWithNativeStability(routes, nil, native, resources, nil, pref, current, SelectionMemory{}, "demo-local", at.Add(2*time.Second), 2000, DefaultPerformanceRule)
	if err != nil || got.CandidateID != routes[0].ID {
		t.Fatal("a later actual TCP success could not refute its first-hop diagnosis", got, err)
	}
	// A later successful HTTPS probe cannot clear a native TCP failure either.
	native = []Observation{nativeSample(routes[0].ID, "demo-c.example:443", "unavailable", at, 30)}
	resources[0].Result, resources[0].RoundTripMS = "available", new(int64(10))
	https[0].Result, https[0].ObservedAt = "available", at.Add(time.Second).Format(time.RFC3339)
	got, _, err = ChooseWithNativeStability(routes, https, native, resources, nil, pref, current, SelectionMemory{}, "demo-local", at.Add(2*time.Second), 2000, DefaultPerformanceRule, url)
	if err != nil || got.Targets["tcp://demo-c.example:443"] != routes[1].ID {
		t.Fatal("HTTPS success cleared TCP failure", got, err)
	}
}

func TestNativeTCPFixedExitAndAllFailedTargetsDoNotFlap(t *testing.T) {
	at, routes, resources, _ := routingEvidenceFixture()
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{}}
	native := []Observation{nativeSample(routes[0].ID, "demo-c.example:443", "unavailable", at, 50), nativeSample(routes[1].ID, "demo-c.example:443", "unavailable", at, 50)}
	got, _, err := ChooseWithNativeStability(routes, nil, native, resources, nil, pref, current, SelectionMemory{}, "demo-local", at.Add(time.Second), 1000, DefaultPerformanceRule)
	if err != nil || got.CandidateID != current.CandidateID || len(got.Targets) != 0 {
		t.Fatal("all-failed targets cycled candidates", got, err)
	}
	for i := range routes {
		routes[i].FixedExit, routes[i].FinalExit, routes[i].Chain = true, "demo-fixed", []string{"demo-fixed"}
	}
	withNative, _, err := ChooseWithNativeStability(routes, nil, native[:1], resources, nil, pref, current, SelectionMemory{}, "demo-local", at.Add(time.Second), 1000, DefaultPerformanceRule)
	withoutNative, _, otherErr := ChooseWithStability(routes, nil, resources, nil, pref, current, SelectionMemory{}, "demo-local", at.Add(time.Second), 1000, DefaultPerformanceRule)
	if err != nil || otherErr != nil || !reflect.DeepEqual(withNative, withoutNative) {
		t.Fatal("fixed exit ranked TCP targets", withNative, withoutNative, err)
	}
}

func TestNativeTCPFailureExploresUnknownEntryWithinTheSameExit(t *testing.T) {
	at, routes, resources, _ := routingEvidenceFixture()
	// A non-fixed Policy may have two entries to one currently usable exit.
	// The second entry has no local sample yet; unknown is not known failure.
	routes[1].FinalExit, routes[1].Chain = routes[0].FinalExit, append([]string{}, routes[0].Chain...)
	current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{}}
	native := []Observation{nativeSample(routes[0].ID, "demo-c.example:443", "unavailable", at, 50)}
	got, _, err := ChooseWithNativeStability(routes, nil, native, resources[:1], nil, Preference{Schema: 3, PolicyID: "demo-policy"}, current, SelectionMemory{}, "demo-local", at.Add(time.Second), 1000, DefaultPerformanceRule)
	if err != nil || got.CandidateID != current.CandidateID || got.Targets["tcp://demo-c.example:443"] != routes[1].ID {
		t.Fatal("a known target failure outranked an unmeasured legal entry", got, err)
	}
}

func TestNativeTCPValidationAndBindingKeepOriginalLocalCoordinates(t *testing.T) {
	at, routes, resources, _ := routingEvidenceFixture()
	sample := nativeSample(routes[0].ID, "demo-c.example:443", "available", at, 25)
	if sample.Validate() != nil {
		t.Fatal("millisecond TCP sample rejected")
	}
	for _, change := range []func(*Observation){
		func(s *Observation) { s.Target = "tcp://demo-c.example:443" },
		func(s *Observation) { s.Target = "https://demo-c.example/" },
		func(s *Observation) { s.Scope = "local_network:demo-service" },
		func(s *Observation) {
			s.ObservedAt = at.Add(25*time.Millisecond + time.Nanosecond).Format(time.RFC3339Nano)
		},
		func(s *Observation) { s.ObservedAt = "2030-01-01T00:00:00.0250Z" },
		func(s *Observation) { s.MetricMillis = at.UnixMilli() + 25 },
	} {
		invalid := sample
		change(&invalid)
		if invalid.Validate() == nil {
			t.Fatal("noncanonical TCP sample accepted", invalid)
		}
	}
	// HTTPS keeps its original second-precision canonical form.
	https := targetFaultSample(routes[0].ID, "https://demo-c.example/", "available", at)
	https.ObservedAt = sample.ObservedAt
	if https.Validate() == nil {
		t.Fatal("TCP timestamp rule silently changed HTTPS bytes")
	}
	memory := SelectionMemory{PolicyID: "demo-policy", NetworkGeneration: "demo-local", NativeBinding: &NativeBinding{Revision: "demo-revision", NetworkGeneration: "demo-local", ExecutionSpec: "demo-spec"}}
	current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{}}
	_, next, err := ChooseWithNativeStability(routes, nil, nil, resources, nil, Preference{Schema: 3, PolicyID: "demo-policy"}, current, memory, "demo-local", at, 0, DefaultPerformanceRule)
	if err != nil || next.NativeBinding == nil || *next.NativeBinding != *memory.NativeBinding {
		t.Fatal("ordinary choice lost native binding", next, err)
	}
	next.NativeBinding.Revision = "demo-new-revision"
	if memory.NativeBinding.Revision != "demo-revision" {
		t.Fatal("proposal mutated the prior binding")
	}
	_, next, err = ChooseWithNativeStability(routes, nil, nil, nil, nil, Preference{Schema: 3, PolicyID: "demo-policy"}, current, memory, "demo-other-network", at, 0, DefaultPerformanceRule)
	if err != nil || next.NativeBinding != nil {
		t.Fatal("new network inherited old native binding", next, err)
	}
}

func TestNativeTCPTargetExpiryKeepsChoiceAndCapacityEvictsOldest(t *testing.T) {
	at, routes, resources, _ := routingEvidenceFixture()
	current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{}}
	memory := SelectionMemory{PolicyID: "demo-policy", NetworkGeneration: "demo-local", Decisions: map[string]SelectionDecision{}}
	for i := range 128 {
		key := fmt.Sprintf("tcp://demo-%03d.example:443", i)
		current.Targets[key] = routes[1].ID
		memory.Decisions[key] = SelectionDecision{Current: routes[1].ID, AppliedMS: int64(i + 1)}
	}
	expired := nativeSample(routes[0].ID, "demo-000.example:443", "unavailable", at.Add(-2*time.Minute), 10)
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	got, next, err := ChooseWithNativeStability(routes, nil, []Observation{expired}, resources, nil, pref, current, memory, "demo-local", at, 1000, DefaultPerformanceRule)
	if err != nil || !reflect.DeepEqual(got.Targets, current.Targets) || next.Decisions["tcp://demo-000.example:443"].AppliedMS != 1 {
		t.Fatal("expiry restored a failed faster route without new evidence", got, err)
	}
	newFailure := nativeSample(routes[0].ID, "demo-new.example:443", "unavailable", at, 10)
	got, _, err = ChooseWithNativeStability(routes, nil, []Observation{newFailure}, resources, nil, pref, current, memory, "demo-local", at.Add(time.Second), 1000, DefaultPerformanceRule)
	if err != nil || len(got.Targets) != 128 || got.Targets["tcp://demo-new.example:443"] != routes[1].ID || got.Targets["tcp://demo-000.example:443"] != "" {
		t.Fatal("new passive target did not cause bounded oldest-target eviction", len(got.Targets), got, err)
	}
}
