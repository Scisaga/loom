package linuxclient

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestLinuxReportFiltersAtSnapshotWithoutChangingCandidateRecovery(t *testing.T) {
	store, _, makeView := linuxAcceptanceFixture(t, func(_ uint64, view *control.DeviceView) {
		view.Responsibilities = []string{"access", "internet_egress"}
		view.Policies[0].LocalEgressDevices = new([]string{view.DeviceID})
		view.Services[0].ProbeURLs = []string{"https://demo-service.example/a", "https://demo-service.example/b"}

	})
	lkg := makeView(7, true)
	if len(testDeviceExecution(lkg.View).Routes) != 2 {
		t.Fatal("fixture must have selected and unselected candidates")
	}
	at := time.Date(2030, 1, 1, 0, 1, 0, 120_000_000, time.UTC)
	state := defaultState("demo-underlay")
	state.Preference = clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}
	state.ObservationViewDigest = lkg.ViewDigest
	for _, row := range []struct {
		route           int
		target, result  string
		observed, until time.Time
	}{
		{0, "https://demo-service.example/a", "available", at.Add(-time.Second), at.Add(time.Minute)},
		{1, "https://demo-service.example/a", "unavailable", at.Add(-time.Second), at.Add(time.Minute)},
		{0, "https://demo-service.example/b", "unavailable", at.Add(-time.Minute), at.Truncate(time.Second)},
		{1, "https://demo-service.example/b", "available", at.Add(time.Second), at.Add(time.Minute)},
	} {
		route := testDeviceExecution(lkg.View).Routes[row.route]
		state.Observations = append(state.Observations, clientmodel.Observation{CandidateID: route.ID, Scope: control.AccessSelectorScope, Target: row.target, Action: "https_request", NetworkGeneration: state.NetworkGeneration,
			Result: row.result, ObservedAt: row.observed.UTC().Format(time.RFC3339), ValidUntil: row.until.UTC().Format(time.RFC3339)})
	}
	sort.Slice(state.Observations, func(i, j int) bool { return state.Observations[i].Key() < state.Observations[j].Key() })
	before, _ := json.Marshal(state)
	activation := Activation{State: state, Selections: []SelectionStatus{{Scope: control.AccessSelectorScope, CandidateID: testDeviceExecution(lkg.View).Routes[0].ID}}}
	report, err := selectionReport(context.Background(), lkg, activation, at, []control.ComponentReadback{}, control.RuntimeReadback{State: "running", AppliedViewDigest: lkg.ViewDigest}, nil, nil)
	if err != nil || len(report.Observations) != 2 || len(report.Selections) != 1 {
		t.Fatal("report did not retain exactly the current candidates", err)
	}
	byID := map[string]string{}
	for _, value := range report.Observations {
		byID[value.CandidateID] = value.Result
	}
	if byID[testDeviceExecution(lkg.View).Routes[0].ID] != "available" || byID[testDeviceExecution(lkg.View).Routes[1].ID] != "unavailable" || report.ReportedAt != at.UnixMilli() {
		t.Fatal("nonselected failure or frozen report time was lost")
	}
	after, _ := json.Marshal(state)
	if string(before) != string(after) || !reflect.DeepEqual(activation.State, state) {
		t.Fatal("report pruning changed the original recovery state")
	}
	report.Schema, report.NetworkID, report.DeviceID, report.ReportSequence = 3, lkg.NetworkID, lkg.View.DeviceID, 1
	signed, err := control.SignDeviceReport(report, store.PrivateKey())
	if err != nil || signed.Verify(store.PublicKey()) != nil {
		t.Fatal("filtered producer report did not use the existing signer", err)
	}
	// Two expired entries with the same wire key must still reject before filtering.
	activation.State.Observations = []clientmodel.Observation{state.Observations[1], state.Observations[1]}
	activation.State.Observations[0].ObservedAt, activation.State.Observations[1].ObservedAt = at.Add(-time.Minute).Format(time.RFC3339), at.Add(-time.Minute).Format(time.RFC3339)
	activation.State.Observations[0].ValidUntil, activation.State.Observations[1].ValidUntil = at.Add(-time.Second).Format(time.RFC3339), at.Add(-time.Second).Format(time.RFC3339)
	if _, err := selectionReport(context.Background(), lkg, activation, at, []control.ComponentReadback{}, report.Runtime, nil, nil); err == nil {
		t.Fatal("expired duplicate candidate inputs disappeared before validation")
	}
}
