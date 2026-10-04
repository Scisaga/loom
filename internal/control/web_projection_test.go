package control

import (
	"encoding/json"
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
	snapshot := buildWebSnapshot(projection, true, true, true)
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
	readonly := buildWebSnapshot(projection, true, true, false)
	if !readonly.Capabilities.Admin || len(readonly.Capabilities.Operations) != 0 || readonly.UIState.LocalWritable {
		t.Fatal("credential manufactured local signing availability")
	}
}

func TestWebReportDoesNotManufactureGlobalBusinessHealth(t *testing.T) {
	_, _, projection := deviceContractFixture(t)
	projection.DeviceAuthorizations[0].Responsibilities = []string{"access", "internet_egress"}
	projection.NetworkIntent.Policies[0].AllowDirect = false
	projection.NetworkIntent.Policies[0].LocalEgressDevices = []string{"demo-access"}
	snapshot := buildWebSnapshot(projection, true, true, true)
	if len(snapshot.Paths) != 1 || snapshot.Paths[0].FinalExit != "demo-access" || len(snapshot.Paths[0].Chain) != 0 || snapshot.Paths[0].Selected || snapshot.Paths[0].Availability != "unknown" {
		t.Fatal("unmeasured local candidate disappeared or acquired a selection/health assertion")
	}
	report := DeviceReport{DeviceID: "demo-access", NetworkGeneration: "demo-generation", ReportedAt: 1000, ViewDigest: "demo-digest", Runtime: RuntimeReadback{State: "running", AppliedViewDigest: "demo-digest"}, Selections: []ReportSelection{{ServiceID: "demo-service", CandidateID: snapshot.Paths[0].CandidateID}}, Observations: []Observation{}}
	projectWebObservations(&snapshot, []DeviceReport{report}, time.UnixMilli(2000))
	if !snapshot.Paths[0].Selected || snapshot.Paths[0].Availability != "unknown" {
		t.Fatal("selector readback without a business probe was lost or manufactured health")
	}
	observation := Observation{Level: "service", ServiceID: "demo-service", CandidateID: snapshot.Paths[0].CandidateID, NetworkGeneration: report.NetworkGeneration, Target: "https://demo.example/", Result: "available", ObservedAt: 1000, ValidUntil: 3000}
	report.Observations = []Observation{observation}
	for _, at := range []int64{2000, 3000} {
		fresh := buildWebSnapshot(projection, true, true, true)
		projectWebObservations(&fresh, []DeviceReport{report}, time.UnixMilli(at))
		want := "available"
		if at == 3000 {
			want = "unknown"
		}
		if fresh.Paths[0].Availability != want || !fresh.Paths[0].Selected {
			t.Fatal("business observation expiry or actual selection was lost")
		}
		for _, device := range fresh.Devices {
			if device.Availability != "unknown" || device.Presence != "unknown" {
				t.Fatal("one observation was folded into unproved global health")
			}
		}
	}
	other := observation
	other.Target, other.Result = "https://other.example/", "unavailable"
	report.Observations = append(report.Observations, other)
	multiple := buildWebSnapshot(projection, true, true, true)
	projectWebObservations(&multiple, []DeviceReport{report}, time.UnixMilli(2000))
	if len(multiple.Paths) != 1 || multiple.Paths[0].Availability != "unknown" {
		t.Fatal("multiple measurements duplicated the path or invented a reduction rule")
	}
	projection.NetworkIntent.Policies[0].Action = "deny"
	withdrawn := buildWebSnapshot(projection, true, true, true)
	projectWebObservations(&withdrawn, []DeviceReport{report}, time.UnixMilli(2000))
	if len(withdrawn.Paths) != 0 {
		t.Fatal("an observation manufactured a withdrawn path")
	}
}
