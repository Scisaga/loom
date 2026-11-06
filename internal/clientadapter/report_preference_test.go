package clientadapter

import (
	"loom/internal/clientmodel"
	"loom/internal/control"
	"testing"
)

func TestReportedPolicyIsOneGrantedChoiceIndependentOfAvailability(t *testing.T) {
	view := control.DeviceView{Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-policy"}, Services: []control.Service{{ID: "demo-service", Kind: "internet", RestrictToProbeTargets: new(false)}}, Policies: []control.NetworkPolicy{{ID: "demo-policy", ServiceID: "demo-service", Action: "allow"}}}
	if _, err := ReportedPolicyID(view, clientmodel.Preference{}); err == nil {
		t.Fatal("missing setting accepted")
	}
	if id, err := ReportedPolicyID(view, clientmodel.EmptyPreference()); err != nil || id != "" {
		t.Fatal("pending selection manufactured a policy", err)
	}
	pref := clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}
	if id, err := ReportedPolicyID(view, pref); err != nil || id != pref.PolicyID {
		t.Fatal("availability erased the granted choice", err)
	}
	view.PolicyIDs = []string{}
	if _, err := ReportedPolicyID(view, pref); err == nil {
		t.Fatal("revoked choice reported")
	}
	view.Responsibilities = []string{"control"}
	if id, err := ReportedPolicyID(view, clientmodel.EmptyPreference()); err != nil || id != "" {
		t.Fatal("control acquired an access choice", err)
	}
}
