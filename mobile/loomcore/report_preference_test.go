package loomcore

import (
	"bytes"
	"encoding/json"
	"reflect"
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

// The host supplies only scopes whose complete selector GET/CAS/readback was
// confirmed. The bridge verifies qualification and intent without treating that
// subset as proof that the whole Android runtime is applied.
func TestAndroidReportsPartialScopeConfirmationWithBothIntents(t *testing.T) {
	_, body := androidFixture(t, 7, false, func(p *control.Projection) {
		prefix, err := control.AllocateLocalNetworkPrefix(p.NetworkID, "demo-lan", 0, "192.0.2.0/24", nil)
		if err != nil {
			t.Fatal(err)
		}
		p.DeviceAuthorizations[0].Responsibilities = []string{"access", "forward"}
		p.NetworkIntent.Services = append(p.NetworkIntent.Services, control.Service{
			ID: "demo-lan", Name: "Demo LAN", Kind: "local_network", RestrictToProbeTargets: new(false),
			LocalNetwork: &control.LocalNetwork{GatewayNodeID: "demo-access", LocalPrefix: "192.0.2.0/24", VirtualPrefix: prefix.String(), Enabled: true},
		})
		lan := p.NetworkIntent.Policies[0]
		lan.ID, lan.ServiceID, lan.ExitScope, lan.AllowDirect, lan.LocalEgressDevices = "demo-policy-lan", "demo-lan", nil, nil, nil
		p.NetworkIntent.Policies = append(p.NetworkIntent.Policies, lan)
		p.DeviceAuthorizations[0].PolicyIDs = append(p.DeviceAuthorizations[0].PolicyIDs, lan.ID)
	})
	reserved, err := ReserveAndroidReportSequence(body)
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeState(reserved)
	if err != nil {
		t.Fatal(err)
	}
	if state.Preference.PolicyID != "demo-policy" || state.Preference.LANPolicyIDs["demo-lan"] != "demo-policy-lan" {
		t.Fatal("fixture needs both durable intents")
	}
	selected := map[string]androidSelection{}
	for _, route := range testDeviceExecution(state.LKG.View).Routes {
		scope := control.AccessSelectorScope
		if route.ServiceID == "demo-lan" {
			scope = "local_network:demo-lan"
		}
		selected[scope] = androidSelection{Scope: scope, CandidateID: route.ID}
	}
	if len(selected) != 2 {
		t.Fatal("fixture needs both qualified scopes")
	}
	partial := control.RuntimeReadback{State: "unknown", PermissionViewDigest: state.LKG.ViewDigest, ErrorCode: "runtime_apply_pending"}
	for _, test := range []struct {
		name       string
		runtime    control.RuntimeReadback
		selections []androidSelection
	}{
		{"both pending", partial, []androidSelection{}},
		{"Internet confirmed", partial, []androidSelection{selected[control.AccessSelectorScope]}},
		{"LAN confirmed", partial, []androidSelection{selected["local_network:demo-lan"]}},
		{"both confirmed", control.RuntimeReadback{State: "running", AppliedViewDigest: state.LKG.ViewDigest}, []androidSelection{selected[control.AccessSelectorScope], selected["local_network:demo-lan"]}},
		{"stopped", control.RuntimeReadback{State: "stopped"}, []androidSelection{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			selections, _ := json.Marshal(test.selections)
			runtime, _ := json.Marshal(test.runtime)
			report, err := androidReport(state, nil, nil, []byte("[]"), selections, runtime, []byte("[]"), nil, "demo-underlay", "2030-01-01T00:00:00.000Z")
			if err != nil {
				t.Fatal("confirmed scope subset was lost", err)
			}
			if report.PolicyID != "demo-policy" || report.LANPolicyIDs["demo-lan"] != "demo-policy-lan" || len(report.Selections) != len(test.selections) || !reflect.DeepEqual(report.Runtime, test.runtime) {
				t.Fatal("partial scope report changed an intent, selection or whole-runtime proof")
			}
			for _, selection := range report.Selections {
				scope := control.AccessSelectorScope
				if selection.ServiceID == "demo-lan" {
					scope = "local_network:demo-lan"
				}
				if selection.CandidateID != selected[scope].CandidateID || selection.PolicyID != map[string]string{control.AccessSelectorScope: "demo-policy", "local_network:demo-lan": "demo-policy-lan"}[scope] {
					t.Fatal("bridge reported another scope or Policy")
				}
			}
			wire, err := control.CanonicalEncode(report)
			var restored control.DeviceReport
			if err != nil || control.DecodeCanonical(wire, &restored, control.ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 32, MaxItems: 4096}) != nil || !reflect.DeepEqual(restored, report) || restored.Verify(state.PublicKey) != nil {
				t.Fatal("partial report or its current intent did not sign and round trip", err)
			}
			again, err := control.CanonicalEncode(restored)
			if err != nil || !bytes.Equal(wire, again) {
				t.Fatal("report canonical bytes did not round trip", err)
			}
			if len(restored.Selections) > 0 {
				restored.Selections = nil
				if restored.Verify(state.PublicKey) == nil {
					t.Fatal("confirmed scope was outside signature")
				}
			}
		})
	}
	selectionBody, _ := json.Marshal([]androidSelection{selected[control.AccessSelectorScope]})
	for _, invalid := range []control.RuntimeReadback{
		{State: "unknown"},
		{State: "unknown", PermissionViewDigest: control.ReleaseDigest([]byte("demo-other-view"))},
		{State: "unknown", AppliedViewDigest: state.LKG.ViewDigest, PermissionViewDigest: state.LKG.ViewDigest},
		{State: "stopped"},
		{State: "stopped", PermissionViewDigest: state.LKG.ViewDigest},
		{State: "error", ErrorCode: "demo-failed"},
		{State: "error", ErrorCode: "demo-failed", PermissionViewDigest: state.LKG.ViewDigest},
	} {
		encoded, _ := json.Marshal(invalid)
		if _, err := androidReport(state, nil, nil, []byte("[]"), selectionBody, encoded, []byte("[]"), nil, "demo-underlay", "2030-01-01T00:00:00.000Z"); err == nil {
			t.Fatal("unconfirmed, stopped or failed permissions were turned into a confirmed selection", invalid)
		}
	}
	partialBody, _ := json.Marshal(partial)
	for _, invalid := range []androidSelection{
		{Scope: control.AccessSelectorScope, CandidateID: selected["local_network:demo-lan"].CandidateID},
		{Scope: "local_network:demo-lan", CandidateID: selected[control.AccessSelectorScope].CandidateID},
		{Scope: control.AccessSelectorScope, CandidateID: control.ReleaseDigest([]byte("demo-unqualified-candidate"))},
	} {
		encoded, _ := json.Marshal([]androidSelection{invalid})
		if _, err := androidReport(state, nil, nil, []byte("[]"), encoded, partialBody, []byte("[]"), nil, "demo-underlay", "2030-01-01T00:00:00.000Z"); err == nil {
			t.Fatal("partial scope confirmation bypassed qualified Policy binding")
		}
	}
}
