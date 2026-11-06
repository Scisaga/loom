package clientmodel

import (
	"bytes"
	"errors"
	"testing"

	"loom/internal/control"
)

func TestPolicyChoiceCanonicalRepresentationAndGrantBoundary(t *testing.T) {
	canonical := []byte(`{"policy_id":"demo-policy","schema":3}`)
	var preference Preference
	if err := control.DecodeCanonical(canonical, &preference, control.ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 8, MaxItems: 64}); err != nil {
		t.Fatal(err)
	}
	encoded, err := control.CanonicalEncode(preference)
	if err != nil || !bytes.Equal(canonical, encoded) {
		t.Fatal("canonical choice did not round trip", err)
	}
	for _, invalid := range []string{
		`{"schema":3,"services":[{"policy_id":"","service_id":"demo-a"}]}`,
		`{"schema":3,"services":[{"policy_id":null,"service_id":"demo-a"}]}`,
		`{"schema":3,"services":[{"service_id":"demo-a"},{"service_id":"demo-a"}]}`,
		`{"schema":3,"services":[{"service_id":"demo-b"},{"service_id":"demo-a"}]}`,
		`{"schema":3,"services":null}`,
		`{"mode":"auto","schema":3}`,
	} {
		var value Preference
		if control.DecodeCanonical([]byte(invalid), &value, control.ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 8, MaxItems: 64}) == nil {
			t.Fatal("noncanonical preference accepted", invalid)
		}
	}
	view := control.DeviceView{PolicyIDs: []string{"demo-policy"}, Policies: []control.NetworkPolicy{{ID: "demo-policy", ServiceID: "demo-b", Action: "allow"}}}
	next, err := ReconcilePreference(preference, view)
	services, options := PolicyOptions(view)
	if err != nil || next.PolicyID != "" || len(services) != 0 || len(options) != 0 {
		t.Fatal("deleted Service or receiver permissions became client authorization", err)
	}
	if _, err := ChoosePolicy(next, view, "demo-policy"); err == nil {
		t.Fatal("deleted Service remained selectable")
	}
}

func TestPolicyChoiceInitializationRevocationAndRestart(t *testing.T) {
	view := control.DeviceView{Services: []control.Service{{ID: "demo-service", Name: "Demo service", Kind: "internet", RestrictToProbeTargets: new(false)}}, PolicyIDs: []string{"demo-a"}, Policies: []control.NetworkPolicy{{ID: "demo-a", ServiceID: "demo-service", Action: "allow"}}}
	preference := InitialPreference(view)
	var err error
	if err != nil || preference.PolicyID != "demo-a" {
		t.Fatal("single policy initialization", err)
	}
	view.PolicyIDs = append(view.PolicyIDs, "demo-b")
	view.Policies = append(view.Policies, control.NetworkPolicy{ID: "demo-b", ServiceID: "demo-service", Action: "allow"})
	kept, err := ReconcilePreference(preference, view)
	if err != nil || !kept.Equal(preference) {
		t.Fatal("adding authorization changed saved choice", err)
	}
	fresh, err := ReconcilePreference(Preference{Schema: 3}, view)
	if err != nil || fresh.PolicyID != "" {
		t.Fatal("multiple policies did not remain pending", err)
	}
	view.PolicyIDs = []string{"demo-b"}
	revoked, err := ReconcilePreference(kept, view)
	if err != nil || revoked.PolicyID != "" {
		t.Fatal("revocation silently selected remaining policy", err)
	}
	body, err := control.CanonicalEncode(revoked)
	var restarted Preference
	if err != nil || control.DecodeCanonical(body, &restarted, control.ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 8, MaxItems: 64}) != nil {
		t.Fatal("preference round trip", err)
	}
	restarted, err = ReconcilePreference(restarted, view)
	if err != nil || restarted.PolicyID != "" {
		t.Fatal("restart restored revoked choice", err)
	}
	if _, err := ChoosePolicy(restarted, view, "demo-a"); err == nil {
		t.Fatal("ungranted policy selected")
	}
}

func TestChoiceFiltersBeforeAvailabilityWithoutCrossPolicyFallback(t *testing.T) {
	routes, samples, now := firstHopSelectionFixture()
	routes = routes[:2]
	routes[1].PolicyID = "demo-other-policy"
	samples[0].Result = "unavailable"
	preference := Preference{Schema: 3, PolicyID: "demo-policy"}
	if got, err := Select(routes, nil, samples, preference, "", "demo-network", now); err != nil || got.CandidateID != routes[0].ID {
		t.Fatal("diagnostic fallback escaped the current Policy or blocked its only attempt", got, err)
	}
	preference.PolicyID = ""
	if _, err := Select(routes, nil, nil, preference, "", "demo-network", now); !errors.Is(err, ErrNoUsableCandidate) {
		t.Fatal("pending choice leaked traffic", err)
	}
}

func TestInternetChoicePreservesIndependentLANIntent(t *testing.T) {
	view := control.DeviceView{Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-lan-a", "demo-lan-b", "demo-web-a", "demo-web-b"}, Services: []control.Service{{ID: "demo-web", Kind: "internet", RestrictToProbeTargets: new(false)}, {ID: "demo-lan", Kind: "local_network", RestrictToProbeTargets: new(false), LocalNetwork: &control.LocalNetwork{Enabled: true, GatewayNodeID: "demo-gateway", VirtualPrefix: "10.64.1.0/24", LocalPrefix: "192.0.2.0/24"}}}, Policies: []control.NetworkPolicy{{ID: "demo-lan-a", ServiceID: "demo-lan", Action: "allow"}, {ID: "demo-lan-b", ServiceID: "demo-lan", Action: "allow"}, {ID: "demo-web-a", ServiceID: "demo-web", Action: "allow"}, {ID: "demo-web-b", ServiceID: "demo-web", Action: "allow"}}}
	pref := InitialPreference(view)
	if pref.PolicyID != "" || len(pref.LANPolicyIDs) != 0 {
		t.Fatal("multiple choices silently selected")
	}
	lan, err := ChoosePolicy(pref, view, "demo-lan-a")
	if err != nil {
		t.Fatal(err)
	}
	web, err := ChoosePolicy(lan, view, "demo-web-a")
	if err != nil {
		t.Fatal(err)
	}
	next, err := ChoosePolicy(web, view, "demo-web-b")
	if err != nil || next.LANPolicyIDs["demo-lan"] != "demo-lan-a" {
		t.Fatal("Internet choice erased the independent LAN choice", err)
	}
	if scopes := ChangedSelectorScopes(web, next); len(scopes) != 1 || scopes[0] != "access" {
		t.Fatal("Internet choice would close LAN connections", scopes)
	}
	body, err := control.CanonicalEncode(next)
	if err != nil {
		t.Fatal(err)
	}
	var restored Preference
	if control.DecodeCanonical(body, &restored, control.ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 8, MaxItems: 64}) != nil || !restored.Equal(next) {
		t.Fatal("LAN intent did not survive the one identity preference round trip")
	}
	view.PolicyIDs = []string{"demo-lan-a", "demo-lan-b"}
	revoked, err := ReconcilePreference(restored, view)
	if err != nil || revoked.PolicyID != "" || revoked.LANPolicyIDs["demo-lan"] != "demo-lan-a" {
		t.Fatal("Internet revocation changed LAN intent", err)
	}
}
