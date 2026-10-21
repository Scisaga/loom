package clientmodel

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"loom/internal/control"
)

func TestPolicyChoiceCanonicalRepresentationAndGrantBoundary(t *testing.T) {
	canonical := []byte(`{"schema":3,"services":[{"service_id":"demo-a"},{"policy_id":"demo-policy","service_id":"demo-b"}]}`)
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
	if err != nil || next.Policy("demo-b") != "" || len(next.Services) != 2 || len(services) != 0 || len(options) != 0 {
		t.Fatal("deleted Service or receiver permissions became client authorization", err)
	}
	if _, err := ChoosePolicy(next, view, "demo-b", "demo-policy"); err == nil {
		t.Fatal("deleted Service remained selectable")
	}
}

func TestPolicyChoiceInitializationRevocationAndRestart(t *testing.T) {
	view := control.DeviceView{Services: []control.Service{{ID: "demo-service", Name: "Demo service", Kind: "internet", Matchers: []control.ServiceMatcher{{Kind: "dns_exact", Value: "demo.example"}}}}, PolicyIDs: []string{"demo-a"}, Policies: []control.NetworkPolicy{{ID: "demo-a", ServiceID: "demo-service", Action: "allow"}}}
	preference, err := ReconcilePreference(Preference{Schema: 3, Services: []ServicePreference{}}, view)
	if err != nil || preference.Policy("demo-service") != "demo-a" {
		t.Fatal("single policy initialization", err)
	}
	view.PolicyIDs = append(view.PolicyIDs, "demo-b")
	view.Policies = append(view.Policies, control.NetworkPolicy{ID: "demo-b", ServiceID: "demo-service", Action: "allow"})
	kept, err := ReconcilePreference(preference, view)
	if err != nil || !kept.Equal(preference) {
		t.Fatal("adding authorization changed saved choice", err)
	}
	fresh, err := ReconcilePreference(Preference{Schema: 3, Services: []ServicePreference{}}, view)
	if err != nil || fresh.Policy("demo-service") != "" || len(fresh.Services) != 1 {
		t.Fatal("multiple policies did not remain pending", err)
	}
	view.PolicyIDs = []string{"demo-b"}
	revoked, err := ReconcilePreference(kept, view)
	if err != nil || revoked.Policy("demo-service") != "" || len(revoked.Services) != 1 {
		t.Fatal("revocation silently selected remaining policy", err)
	}
	body, err := control.CanonicalEncode(revoked)
	var restarted Preference
	if err != nil || control.DecodeCanonical(body, &restarted, control.ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 8, MaxItems: 64}) != nil {
		t.Fatal("preference round trip", err)
	}
	restarted, err = ReconcilePreference(restarted, view)
	if err != nil || restarted.Policy("demo-service") != "" {
		t.Fatal("restart restored revoked choice", err)
	}
	if _, err := ChoosePolicy(restarted, view, "demo-service", "demo-a"); err == nil {
		t.Fatal("ungranted policy selected")
	}
}

func TestChoiceFiltersBeforeAvailabilityWithoutCrossPolicyFallback(t *testing.T) {
	now := time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC)
	routes := []RouteCandidate{{ID: "demo-fixed", PolicyID: "demo-fixed-policy", Scope: "service:demo-service", FinalExit: "demo-exit"}, {ID: "demo-auto", PolicyID: "demo-auto-policy", Scope: "service:demo-service", FinalExit: "direct"}}
	preference := Preference{Schema: 3, Services: []ServicePreference{{ServiceID: "demo-service", PolicyID: "demo-fixed-policy"}}}
	failed := Observation{CandidateID: "demo-fixed", Scope: routes[0].Scope, NetworkGeneration: "demo-generation", Action: "https_request", Result: "unavailable", ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)}
	if _, err := Select(routes, []Observation{failed}, nil, preference, "", "demo-generation", now, ""); !errors.Is(err, ErrNoUsableCandidate) {
		t.Fatal("failure escaped selected policy", err)
	}
	preference.Services[0].PolicyID = ""
	if _, err := Select(routes, nil, nil, preference, "", "demo-generation", now, ""); !errors.Is(err, ErrNoUsableCandidate) {
		t.Fatal("pending choice leaked traffic", err)
	}
}
