package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSnapshotViewReuseDoesNotSurviveAuthorizationChanges(t *testing.T) {
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t)
	if enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)).Code != http.StatusOK {
		t.Fatal("claim failed")
	}
	send := func(sequence U64) DeviceReport {
		t.Helper()
		envelope, err := server.deviceEnvelope(invite.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: envelope.NetworkID, DeviceID: invite.DeviceID, ReportSequence: sequence, ViewDigest: envelope.ViewDigest, NetworkGeneration: "demo-generation", ReportedAt: server.now().UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: envelope.ViewDigest}}, key)
		if err != nil {
			t.Fatal(err)
		}
		if response := enrollmentHTTP(t, server, "/device/report", report, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}); response.Code != http.StatusOK {
			t.Fatal("report rejected", response.Code)
		}
		return report
	}
	read := func(wantEvidence bool) {
		t.Helper()
		response := httptest.NewRecorder()
		server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil))
		if response.Code != http.StatusOK {
			t.Fatal("snapshot failed", response.Code)
		}
		var value WebSnapshot
		if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, device := range value.Devices {
			if device.ID == invite.DeviceID {
				found = true
				if (device.Evidence != nil) != wantEvidence {
					t.Fatal("report used another request's accepted view")
				}
			}
		}
		if !found {
			t.Fatal("device disappeared")
		}
		authorization, ok := authorizationFor(server.Runtime.Authority.Snapshot(), invite.DeviceID)
		if ok && bytes.Contains(response.Body.Bytes(), []byte(authorization.RuntimeKey)) {
			t.Fatal("internal view leaked its runtime credential")
		}
	}
	send(1)
	read(true)
	projection := server.Runtime.Authority.Snapshot()
	policy := projection.NetworkIntent.Policies[0]
	policy.Action = "deny"
	target, _ := projection.CurrentTarget("policy", policy.ID)
	service, _ := projection.CurrentTarget("service", policy.ServiceID)
	dependencies := sortedUniqueDependencies(append(append([]string{}, target.MaterialIDs...), service.MaterialIDs...))
	operation := Operation{Schema: 3, RequestID: "demo-revoke-view-policy", Operation: "policy.put", TargetKind: "policy", TargetID: policy.ID, Dependencies: dependencies, Payload: policy}
	if response := localNetworkAdminHTTP(t, server, "/api/control/operations", operation); response.Code != http.StatusOK {
		t.Fatal("policy update failed", response.Code, response.Body.String())
	}
	read(false)
	report := send(2)
	read(true)
	report.Runtime.State = "stopped" // Keep the old signature: the reuse cannot authenticate this change.
	if response := enrollmentHTTP(t, server, "/device/report", report, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}); response.Code == http.StatusOK {
		t.Fatal("changed report bypassed signature verification")
	}
	read(true)
}
