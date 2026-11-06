package control

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWebSnapshotRedactsSecretsAndPreservesPolicyReferences(t *testing.T) {
	fixture := newMaterialFixture(t)
	projection, err := Project(fixture.genesis, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	projection.DeviceAuthorizations = []DeviceAuthorization{{ID: "demo-node-a", Name: "Demo control access", Platform: "linux", Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-deleted-policy"}, DistributionURLs: []string{}, RuntimeKey: "demo-private-runtime-value", TransactionID: "demo-transaction", DevicePublicKey: "demo-private-binding-value"}}
	projection.Targets = []TargetState{{TargetKind: "device", TargetID: "demo-node-a", MaterialIDs: []string{materialTestID(t, fixture.genesis)}}}
	snapshot := testWebSnapshotWithIntent(projection, true, true, true)
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"runtime_key", "device_public_key", "demo-private-runtime-value", "demo-private-binding-value"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("UI leaked %s", secret)
		}
	}
	device := snapshot.Devices[0]
	if len(device.Roles) != 2 || device.Roles[0] != "access" || device.Roles[1] != "control" || len(device.PolicyIDs) != 1 || device.PolicyIDs[0] != "demo-deleted-policy" {
		t.Fatal("projection lost member/ordinary separation or retained policy IDs")
	}
	readonly := testWebSnapshotWithIntent(projection, true, true, false)
	if !readonly.Capabilities.Admin || len(readonly.Capabilities.Operations) != 0 || readonly.UIState.LocalWritable {
		t.Fatal("credential manufactured local signing availability")
	}
}

func TestWebReportDoesNotManufactureGlobalBusinessHealth(t *testing.T) {
	_, _, projection := deviceContractFixture(t)
	projection.DeviceAuthorizations[0].Responsibilities = []string{"access", "internet_egress"}
	projection.NetworkIntent.Policies[0].AllowDirect = new(false)
	projection.NetworkIntent.Policies[0].LocalEgressDevices = new([]string{"demo-access"})
	snapshot := testWebSnapshotWithIntent(projection, true, true, true)
	if len(snapshot.Paths) != 1 || snapshot.Paths[0].FinalExit != "demo-access" || !reflect.DeepEqual(snapshot.Paths[0].Chain, []string{"demo-access"}) || snapshot.Paths[0].Selected || snapshot.Paths[0].Availability != "unknown" {
		t.Fatal("unmeasured local candidate disappeared or acquired a selection/health assertion")
	}
	report := DeviceReport{DeviceID: "demo-access", NetworkGeneration: "demo-generation", ReportedAt: 1000, ViewDigest: "demo-digest", Runtime: RuntimeReadback{State: "running", AppliedViewDigest: "demo-digest"}, PolicyID: "demo-policy", Selections: []ReportSelection{{ServiceID: "demo-service", PolicyID: "demo-policy", CandidateID: snapshot.Paths[0].CandidateID}}, Observations: []Observation{}}
	testProjectWebObservations(&snapshot, []DeviceReport{report}, time.UnixMilli(2000))
	if !snapshot.Paths[0].Selected || snapshot.Paths[0].Availability != "unknown" {
		t.Fatal("selector readback without a business probe was lost or manufactured health")
	}
	observation := Observation{Level: "service", ServiceID: "demo-service", CandidateID: snapshot.Paths[0].CandidateID, NetworkGeneration: report.NetworkGeneration, Target: "https://demo.example/", Result: "available", ObservedAt: 1000, ValidUntil: 3000}
	report.Observations = []Observation{observation}
	for _, expiry := range []int64{3000, 4102444800000} {
		report.Observations[0].ValidUntil = expiry
		readback := testWebSnapshotWithIntent(projection, true, true, true)
		testProjectWebObservations(&readback, []DeviceReport{report}, time.UnixMilli(2000))
		if readback.Paths[0].Availability != "unknown" || !readback.Paths[0].Selected {
			t.Fatal("device-provided expiry manufactured current health or lost the reported selection")
		}
		for _, device := range readback.Devices {
			if device.Availability != "unknown" || device.Presence != "unknown" {
				t.Fatal("one observation was folded into unproved global health")
			}
			if device.ID == report.DeviceID && (device.Evidence.NetworkGeneration != report.NetworkGeneration || device.Evidence.Measurements[0].ValidUntil != expiry) {
				t.Fatal("original reported sample or its network binding was lost")
			}
		}
	}
	other := observation
	other.Target, other.Result = "https://other.example/", "unavailable"
	report.Observations = append(report.Observations, other)
	multiple := testWebSnapshotWithIntent(projection, true, true, true)
	testProjectWebObservations(&multiple, []DeviceReport{report}, time.UnixMilli(2000))
	if len(multiple.Paths) != 1 || multiple.Paths[0].Availability != "unknown" {
		t.Fatal("multiple measurements duplicated the path or invented a reduction rule")
	}
	projection.NetworkIntent.Policies[0].Action = "deny"
	withdrawn := testWebSnapshotWithIntent(projection, true, true, true)
	testProjectWebObservations(&withdrawn, []DeviceReport{report}, time.UnixMilli(2000))
	if len(withdrawn.Paths) != 0 {
		t.Fatal("an observation manufactured a withdrawn path")
	}
}

func TestWebRelayProjectionPreservesBothOriginalResourceIdentities(t *testing.T) {
	projection := relayProjectionFixture(t)
	derived, err := DerivedNetworkLinks(projection)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testWebSnapshotWithIntent(projection, true, true, true)
	if len(snapshot.Links) != len(derived) {
		t.Fatal("drawing projection changed the directional candidate inventory")
	}
	for _, original := range derived {
		var found bool
		for _, link := range snapshot.Links {
			if link.ID != original.ID {
				continue
			}
			found = true
			if link.From != original.FromNodeID || link.To != original.ToNodeID || link.FromResourceID != original.FromResourceID || link.ResourceID != original.ResourceID {
				t.Fatal("UI connection grouping must use original endpoint resources", original.ID)
			}
			body, err := json.Marshal(link)
			if err != nil || !strings.Contains(string(body), `"from_resource_id":"`+original.FromResourceID+`"`) || !strings.Contains(string(body), `"resource_id":"`+original.ResourceID+`"`) {
				t.Fatal("Web wire projection omitted an original resource reference", err)
			}
		}
		if !found {
			t.Fatal("UI projection lost an original direction", original.ID)
		}
	}
}

// Pure UI scenarios provide their explicitly supplied report samples; formal
// handlers exercise the original index instead of treating omission as deletion.
func testProjectWebObservations(snapshot *WebSnapshot, reports []DeviceReport, now time.Time) {
	measurements := map[string][]WebObservation{}
	for _, report := range reports {
		_, until := webReportTime(report, now)
		for _, sample := range report.Observations {
			measurements[report.DeviceID] = append(measurements[report.DeviceID], WebObservation{Observation: sample, CurrentUntil: webObservationUntil(report, sample, until, now)})
		}
	}
	projectWebObservations(snapshot, reports, measurements, now)
}
