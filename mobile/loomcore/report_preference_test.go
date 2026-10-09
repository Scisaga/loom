package loomcore

import (
	"encoding/json"
	"testing"

	"loom/internal/control"
)

func TestAndroidReportsTheSavedPreferenceIndependentlyOfRuntime(t *testing.T) {
	_, body := androidFixture(t, 7, false)
	reserved, err := ReserveAndroidReportSequence(body)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := decodeState(reserved)
	route := state.LKG.View.Routes[0]
	selected, _ := json.Marshal([]androidSelection{{Scope: route.Scope, CandidateID: route.ID}})
	for _, sample := range []struct{ mode, status string }{{"auto", "running"}, {"direct", "stopped"}, {"fixed_exit", "running"}, {"fixed_exit", "error"}} {
		mode, status := sample.mode, sample.status
		exit := ""
		if mode == "fixed_exit" {
			exit = "demo-unavailable-exit"
		}
		preference, err := NewAndroidPreference(mode, exit)
		if err != nil {
			t.Fatal(err)
		}
		runtime := control.RuntimeReadback{State: status}
		selections := []byte("[]")
		if status == "running" {
			runtime.AppliedViewDigest, selections = state.LKG.ViewDigest, selected
		} else if status == "error" {
			runtime.ErrorCode = "demo-runtime-failed"
		}
		encoded, _ := json.Marshal(runtime)
		report, err := androidReport(state, preference, nil, []byte("[]"), selections, encoded, []byte("[]"), nil, "demo-underlay", "2030-01-01T00:00:00Z")
		if err != nil || report.Preference == nil || report.Preference.Mode != mode || report.Preference.Exit != exit || report.Verify(state.PublicKey) != nil {
			t.Fatal("report lost the existing setting or its signature", mode, status, err)
		}
		if status == "running" && report.Selections[0].CandidateID != route.ID || status != "running" && len(report.Selections) != 0 {
			t.Fatal("preference changed actual runtime readback")
		}
	}
	for _, invalid := range [][]byte{[]byte("null"), []byte(`{"mode":"auto","schema":4}`), []byte(`{"mode":"fixed_exit","schema":3}`)} {
		if _, err := androidReport(state, invalid, nil, []byte("[]"), []byte("[]"), []byte(`{"state":"stopped","applied_view_digest":"","error_code":""}`), []byte("[]"), nil, "demo-underlay", "2030-01-01T00:00:00Z"); err == nil {
			t.Fatal("invalid saved preference was replaced with Auto")
		}
	}
}
