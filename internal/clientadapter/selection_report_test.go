package clientadapter

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"reflect"
	"testing"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestTargetSelectionReportPreservesActualPathsAndRejectsAnotherPolicy(t *testing.T) {
	digest := func(value string) string { return control.ReleaseDigest([]byte(value)) }
	view, _, _ := resourceProbeFixture(t)
	execution := testDeviceExecution(view)
	if len(execution.Routes) < 2 {
		t.Fatal("missing alternate paths")
	}
	base, alternative := execution.Routes[0].ID, execution.Routes[1].ID
	foreign, err := control.ProjectDeviceCandidates(view, []string{view.PolicyIDs[1]})
	if err != nil {
		t.Fatal(err)
	}
	other := foreign.Routes[0].ID
	serviceID := execution.Routes[0].ServiceID
	pref := clientmodel.Preference{Schema: 3, PolicyID: view.PolicyIDs[0]}
	actual := []SelectionStatus{{Scope: "access", CandidateID: base, Targets: map[string]string{"tcp://demo-b.example:8443": alternative, "udp://192.0.2.10:443": base}}}
	selections, err := ReportSelections(view, pref, actual)
	want := []control.ReportSelection{{ServiceID: serviceID, PolicyID: pref.PolicyID, CandidateID: base},
		{ServiceID: serviceID, PolicyID: pref.PolicyID, CandidateID: alternative, Target: "tcp://demo-b.example:8443"},
		{ServiceID: serviceID, PolicyID: pref.PolicyID, CandidateID: base, Target: "udp://192.0.2.10:443"}}
	if err != nil || !reflect.DeepEqual(selections, want) {
		t.Fatal("actual target routes were collapsed into the default", selections, err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	report, err := control.SignDeviceReport(control.DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: 1,
		ViewDigest: digest("demo-view"), PolicyID: pref.PolicyID, Selections: selections, NetworkGeneration: "demo-network-generation", ReportedAt: 1,
		Observations: []control.Observation{}, Components: []control.ComponentReadback{}, Runtime: control.RuntimeReadback{State: "running", AppliedViewDigest: digest("demo-view")}}, private)
	if err != nil || report.Verify(base64.RawURLEncoding.EncodeToString(public)) != nil {
		t.Fatal("target report did not use the existing signed report contract", err)
	}
	actual[0].Targets["tcp://demo-b.example:8443"] = other
	if _, err := ReportSelections(view, pref, actual); err == nil {
		t.Fatal("target override borrowed another granted Policy")
	}
}
