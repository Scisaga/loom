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
	route := testDeviceExecution(state.LKG.View).Routes[0]
	selected, _ := json.Marshal([]androidSelection{{Scope: control.AccessSelectorScope, CandidateID: route.ID}})
	for _, sample := range []struct{ mode, status string }{{"auto", "running"}, {"direct", "stopped"}, {"fixed_exit", "running"}, {"fixed_exit", "error"}} {
		mode, status := sample.mode, sample.status
		preference, err := testPolicyPreference()
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
		report, err := androidReport(state, preference, nil, []byte("[]"), selections, encoded, []byte("[]"), nil, "demo-underlay", "2030-01-01T00:00:00.000Z")
		if err != nil || report.PolicyID != "demo-policy" || report.PolicyChoices != nil || report.Preference != nil || report.Verify(state.PublicKey) != nil {
			t.Fatal("report lost the existing setting or its signature", mode, status, err)
		}
		if status == "running" && report.Selections[0].CandidateID != route.ID || status != "running" && len(report.Selections) != 0 {
			t.Fatal("preference changed actual runtime readback")
		}
	}
	for _, invalid := range [][]byte{[]byte("null"), []byte(`{"mode":"auto","schema":4}`), []byte(`{"mode":"fixed_exit","schema":3}`)} {
		if _, err := androidReport(state, invalid, nil, []byte("[]"), []byte("[]"), []byte(`{"state":"stopped","applied_view_digest":"","error_code":""}`), []byte("[]"), nil, "demo-underlay", "2030-01-01T00:00:00.000Z"); err == nil {
			t.Fatal("invalid saved preference was replaced with Auto")
		}
	}
}

func TestAndroidReportsConfirmedLANWithoutInternetPolicy(t *testing.T) {
	_, body := androidFixture(t, 7, false, func(p *control.Projection) {
		prefix, err := control.AllocateLocalNetworkPrefix(p.NetworkID, "demo-lan", 0, "192.0.2.0/24", nil)
		if err != nil {
			t.Fatal(err)
		}
		p.DeviceAuthorizations[0].Responsibilities = []string{"access", "forward"}
		p.DeviceAuthorizations[0].PolicyIDs = []string{"demo-policy-lan"}
		p.NetworkIntent.Services = append(p.NetworkIntent.Services, control.Service{
			ID: "demo-lan", Name: "Demo LAN", Kind: "local_network", RestrictToProbeTargets: new(false),
			LocalNetwork: &control.LocalNetwork{GatewayNodeID: "demo-access", LocalPrefix: "192.0.2.0/24", VirtualPrefix: prefix.String(), Enabled: true},
		})
		lan := p.NetworkIntent.Policies[0]
		lan.ID, lan.ServiceID, lan.ExitScope, lan.AllowDirect, lan.LocalEgressDevices = "demo-policy-lan", "demo-lan", nil, nil, nil
		p.NetworkIntent.Policies = append(p.NetworkIntent.Policies, lan)
	})
	reserved, err := ReserveAndroidReportSequence(body)
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeState(reserved)
	if err != nil || state.Preference == nil || state.Preference.PolicyID != "" || state.Preference.LANPolicyIDs["demo-lan"] != "demo-policy-lan" {
		t.Fatal("LAN-only identity lost its independent durable choice", err)
	}
	execution := testDeviceExecution(state.LKG.View)
	if len(execution.Routes) != 1 || execution.Routes[0].ServiceID != "demo-lan" {
		t.Fatal("LAN-only report requires exactly one authorized LAN candidate")
	}
	route := execution.Routes[0]
	selected, _ := json.Marshal([]androidSelection{{Scope: "local_network:demo-lan", CandidateID: route.ID}})
	runtime, _ := json.Marshal(control.RuntimeReadback{State: "running", AppliedViewDigest: state.LKG.ViewDigest})
	report, err := androidReport(state, nil, nil, []byte("[]"), selected, runtime, []byte("[]"), nil, "demo-underlay", "2030-01-01T00:00:00.000Z")
	if err != nil {
		t.Fatal("confirmed LAN report must not require an Internet choice", err)
	}
	if report.PolicyID != "" || report.LANPolicyIDs["demo-lan"] != "demo-policy-lan" || len(report.Selections) != 1 ||
		report.Selections[0].ServiceID != "demo-lan" || report.Selections[0].PolicyID != "demo-policy-lan" || report.Selections[0].CandidateID != route.ID ||
		report.Preference != nil || report.PolicyChoices != nil || report.Verify(state.PublicKey) != nil {
		t.Fatal("Android report lost the confirmed LAN selection or its signed independent intent")
	}
	report.LANPolicyIDs = nil
	if report.Verify(state.PublicKey) == nil {
		t.Fatal("LAN choice was outside the signed report")
	}
}
