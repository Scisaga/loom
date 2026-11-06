package clientadapter

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"loom/internal/clientmodel"
)

func nativeBody(t *testing.T, revision, policy, candidate, result string, start, end time.Time) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"observations": []any{map[string]any{"revision": revision, "policy_id": policy, "candidate_id": candidate, "target": "demo.example:443", "result": result, "started_at": start.UnixMilli(), "observed_at": end.UnixMilli()}}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestNativeBindingReconfirmsSamePathAndPreservesPerformanceClock(t *testing.T) {
	at, routes, samples := engineEvidence()
	s := &fakeSelector{current: map[string]string{"access": "reject"}}
	state := State{Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-network", ResourceObservations: samples, NativeExecutionSpec: "demo-spec"}
	first, err := Activate(context.Background(), s, routes, state, nil, func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	before := first.State.SelectionMemory["access"]
	revision := before.NativeBinding.Revision
	first.State.NetworkGeneration = "demo-other-network"
	s.elapsed = 1000
	second, err := Activate(context.Background(), s, routes, first.State, nil, func() time.Time { return at.Add(time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	after := second.State.SelectionMemory["access"]
	if after.NativeBinding == nil || after.NativeBinding.Revision == revision || after.NativeBinding.NetworkGeneration != "demo-other-network" || s.closed != 0 {
		t.Fatal("same path crossed networks without a new confirmed binding", after)
	}
	// An execution-only same-value CAS is not a performance switch.
	second.State.NativeExecutionSpec = "demo-next-spec"
	third, err := Activate(context.Background(), s, routes, second.State, nil, func() time.Time { return at.Add(2 * time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	if third.State.SelectionMemory["access"].Decisions[""].AppliedMS != after.Decisions[""].AppliedMS {
		t.Fatal("binding refresh reset the performance cooldown")
	}
}

func TestNativeReadDoesNotRebindRejectedSelection(t *testing.T) {
	at, routes, samples := engineEvidence()
	for i := range routes {
		routes[i].PolicyID = "demo-another-policy"
	}
	s := &fakeSelector{current: map[string]string{"access": "reject"}}
	state := State{Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-network", NativeExecutionSpec: "demo-spec", ResourceObservations: samples}
	for range 3 {
		applied, err := Activate(context.Background(), s, routes, state, nil, func() time.Time { return at })
		if !errors.Is(err, clientmodel.ErrNoUsableCandidate) || s.revision != 0 {
			t.Fatal("rejection was forced into a meaningless native binding CAS", err, s.revision)
		}
		state = applied.State
		_, changed, err := RefreshNativeObservations(context.Background(), s, routes, state, func() time.Time { return at })
		if err != nil || changed {
			t.Fatal("local feedback polling reactivated a blocked selection", changed, err)
		}
	}
}

func TestNativeObservationsKeepOriginalBindingAndAttemptOrder(t *testing.T) {
	at, routes, _ := engineEvidence()
	id := routes[0].ID
	memory := clientmodel.SelectionMemory{PolicyID: "demo-policy", NetworkGeneration: "demo-network", NativeBinding: &clientmodel.NativeBinding{Revision: "demo-revision", NetworkGeneration: "demo-network", ExecutionSpec: "demo-spec"}, Decisions: map[string]clientmodel.SelectionDecision{"": {Current: id}}}
	state := State{Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-network", NativeExecutionSpec: "demo-spec", SelectionMemory: map[string]clientmodel.SelectionMemory{"access": memory}}
	newer := nativeBody(t, "demo-revision", "demo-policy", id, "available", at.Add(2*time.Second), at.Add(3*time.Second))
	values, err := ConsumeNativeObservations(newer, state, routes, at.Add(4*time.Second))
	if err != nil || len(values) != 1 || values[0].Action != "tcp_connect" || values[0].MetricMillis != 1000 {
		t.Fatal("native result not consumed", values, err)
	}
	state.NativeObservations = values
	older := nativeBody(t, "demo-revision", "demo-policy", id, "unavailable", at, at.Add(5*time.Second))
	values, err = ConsumeNativeObservations(older, state, routes, at.Add(6*time.Second))
	if err != nil || len(values) != 1 || values[0].Result != "available" || values[0].ValidUntil != state.NativeObservations[0].ValidUntil {
		t.Fatal("late old attempt replaced a newer fact or renewed its lifetime", values, err)
	}
	for _, revision := range []string{"demo-old-revision", "demo-other-instance"} {
		values, err = ConsumeNativeObservations(nativeBody(t, revision, "demo-policy", id, "unavailable", at.Add(6*time.Second), at.Add(7*time.Second)), state, routes, at.Add(8*time.Second))
		if err != nil || len(values) != 1 || values[0].Result != "available" {
			t.Fatal("old binding was reassigned to the current selector", values, err)
		}
	}
	state.NativeExecutionSpec = "demo-new-spec"
	values, err = ConsumeNativeObservations(newer, state, routes, at.Add(4*time.Second))
	if err != nil || len(values) != 0 {
		t.Fatal("old execution evidence survived its specification", values, err)
	}
}

func TestNativeObservationDecoderRejectsUnknownAndUnboundedInput(t *testing.T) {
	for _, body := range [][]byte{[]byte(`{"observations":null}`), []byte(`{"observations":[],"extra":true}`), []byte(`{"observations":[]} {}`), make([]byte, NativeObservationReadbackLimit+1)} {
		if _, err := DecodeNativeObservations(body); err == nil {
			t.Fatal("noncanonical native observation response accepted")
		}
	}
}

func TestNativeSameStartHealthAndUnknownCannotRenewOrWashFacts(t *testing.T) {
	at, routes, _ := engineEvidence()
	id := routes[0].ID
	memory := clientmodel.SelectionMemory{PolicyID: "demo-policy", NetworkGeneration: "demo-network", NativeBinding: &clientmodel.NativeBinding{Revision: "demo-revision", NetworkGeneration: "demo-network", ExecutionSpec: "demo-spec"}, Decisions: map[string]clientmodel.SelectionDecision{"": {Current: id}}}
	state := State{Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-network", NativeExecutionSpec: "demo-spec", SelectionMemory: map[string]clientmodel.SelectionMemory{"access": memory}}
	first, err := ConsumeNativeObservations(nativeBody(t, "demo-revision", "demo-policy", id, "available", at, at.Add(time.Millisecond)), state, routes, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	state.NativeObservations = first
	same, err := ConsumeNativeObservations(nativeBody(t, "demo-revision", "demo-policy", id, "available", at, at.Add(2*time.Millisecond)), state, routes, at.Add(time.Second))
	if err != nil || len(same) != 1 || same[0] != first[0] || NativeRoutingChanged(first, same, memory) {
		t.Fatal("same-start success became a conflict or a fresh sample", same, err)
	}
	conflict, err := ConsumeNativeObservations(nativeBody(t, "demo-revision", "demo-policy", id, "unknown", at, at.Add(3*time.Millisecond)), state, routes, at.Add(time.Second))
	if err != nil || len(conflict) != 1 || conflict[0].Result != "unknown" {
		t.Fatal("unknown left an earlier health conclusion active", conflict, err)
	}
	state.NativeObservations = conflict
	wash, err := ConsumeNativeObservations(nativeBody(t, "demo-revision", "demo-policy", id, "available", at, at.Add(time.Millisecond)), state, routes, at.Add(time.Second))
	if err != nil || len(wash) != 1 || wash[0].Result != "unknown" || wash[0].ValidUntil != conflict[0].ValidUntil {
		t.Fatal("duplicate success washed a conflict or extended its deadline", wash, err)
	}
}

func TestNativeExecutionSpecTracksOnlyCurrentExecutionDependencies(t *testing.T) {
	view, _, _ := resourceProbeFixture(t)
	specFor := func() string {
		t.Helper()
		routes, graphs, err := AccessRoutingInputs(view, []string{"demo-a"})
		if err != nil {
			t.Fatal(err)
		}
		spec, err := NativeExecutionSpec(view, routes, graphs, "demo-a")
		if err != nil {
			t.Fatal(err)
		}
		return spec
	}
	baseline := specFor()
	view.Name = "Demo renamed device"
	view.Services[0].Name = "Demo renamed service"
	view.Services[0].ProbeURLs = []string{"https://demo.example/check"}
	view.Policies[0].Name = "Demo renamed Policy"
	view.Policies[1].AllowDirect = new(false)
	if got := specFor(); got != baseline {
		t.Fatal("labels, unrestricted probe URLs or an unselected Policy invalidated business observations")
	}
	view.Resources[0].DialPort = 8443
	if got := specFor(); got == baseline {
		t.Fatal("changed receiving execution retained old business observations")
	}
	baseline = specFor()
	view.DNSServers = []string{"192.0.2.53"}
	if got := specFor(); got == baseline {
		t.Fatal("changed source DNS retained old business observations")
	}
	baseline = specFor()
	view.Services[0].RestrictToProbeTargets = new(true)
	if got := specFor(); got == baseline {
		t.Fatal("changed Service access boundary retained old business observations")
	}
}
