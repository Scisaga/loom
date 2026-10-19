//go:build windows

package main

import (
	"encoding/json"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestWindowsReportFiltersAtSnapshotKeepsUnselectedEvidence(t *testing.T) {
	invite, envelope := windowsFixture(t)
	public := invite.ControlProof.Genesis.Payload.(control.Genesis).ControlConfig.Members[0].PublicKey
	lkg := envelope(public, 7, func(view *control.DeviceView) {
		view.Responsibilities = []string{"access", "internet_egress"}
		view.Policies[0].LocalEgressDevices = new([]string{view.DeviceID})
		view.BusinessProbeTargets = []control.ServiceProbeTargets{{ServiceID: "demo-service", Targets: []string{"https://demo.example/a", "https://demo.example/b"}}}
	})
	if len(lkg.View.Routes) != 2 {
		t.Fatal("fixture requires selected and unselected candidates")
	}
	at := time.Date(2030, 1, 1, 0, 1, 0, 120_000_000, time.UTC)
	activation := clientadapter.Activation{State: clientadapter.State{Preference: clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeAuto}, NetworkGeneration: "demo-underlay"},
		Selections: []clientadapter.SelectionStatus{{Scope: lkg.View.Routes[0].Scope, CandidateID: lkg.View.Routes[0].ID}}}
	for _, row := range []struct {
		route           int
		target, result  string
		observed, until time.Time
	}{
		{0, "https://demo.example/a", "available", at.Add(-time.Second), at.Add(time.Minute)},
		{1, "https://demo.example/a", "unavailable", at.Add(-time.Second), at.Add(time.Minute)},
		{0, "https://demo.example/b", "unavailable", at.Add(-time.Minute), at.Truncate(time.Second)},
		{1, "https://demo.example/b", "available", at.Add(time.Second), at.Add(time.Minute)},
	} {
		route := lkg.View.Routes[row.route]
		activation.State.Observations = append(activation.State.Observations, clientmodel.Observation{CandidateID: route.ID, Scope: route.Scope, Target: row.target, Action: "https_request", NetworkGeneration: activation.State.NetworkGeneration,
			Result: row.result, ObservedAt: row.observed.Format(time.RFC3339), ValidUntil: row.until.Format(time.RFC3339)})
	}
	before, _ := json.Marshal(activation.State)
	report, err := windowsDeviceReport(&lkg, activation, nil, at)
	if err != nil || len(report.Observations) != 2 || report.ReportedAt != at.UnixMilli() || len(report.Selections) != 1 {
		t.Fatal("Windows report did not use the frozen sample window", err)
	}
	byID := map[string]string{}
	for _, value := range report.Observations {
		byID[value.CandidateID] = value.Result
	}
	if byID[lkg.View.Routes[0].ID] != "available" || byID[lkg.View.Routes[1].ID] != "unavailable" {
		t.Fatal("unselected candidate failure was omitted")
	}
	after, _ := json.Marshal(activation.State)
	if string(before) != string(after) {
		t.Fatal("wire projection modified local recovery evidence")
	}
	expired := activation.State.Observations[2]
	activation.State.Observations = []clientmodel.Observation{expired, expired}
	if _, err := windowsDeviceReport(&lkg, activation, nil, at); err == nil {
		t.Fatal("expired duplicates bypassed whole-collection validation")
	}
}
