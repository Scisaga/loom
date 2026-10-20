package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSnapshotColdReadDoesNotMaterializeDeviceConfiguration(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("claim failed", response.Code)
	}
	// A normal reopen removes process-local computation while retaining the
	// accepted authorization and enrollment response on disk.
	root := server.Runtime.Authority.root
	if err := server.Runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	server.Runtime = runtime
	read := func() {
		t.Helper()
		response := httptest.NewRecorder()
		server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil))
		if response.Code != http.StatusOK {
			t.Fatal("snapshot failed", response.Code, response.Body.String())
		}
		var snapshot WebSnapshot
		if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, device := range snapshot.Devices {
			found = found || device.ID == invite.DeviceID && device.Authorized
		}
		if !found || len(snapshot.Paths) == 0 {
			t.Fatal("cold snapshot lost the current authorized path projection")
		}
	}
	read()
	cache := &runtime.Authority.deviceConfigs
	cache.mu.Lock()
	entries := len(cache.items)
	materialized := false
	for _, item := range cache.items {
		materialized = materialized || len(item.Value.(*deviceConfigEntry).value.body) != 0
	}
	cache.mu.Unlock()
	if entries == 0 || materialized {
		t.Fatal("reading the UI did not retain a view-only computation")
	}

	response := enrollmentHTTP(t, server, "/device/config", map[string]any{"schema": 3}, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID})
	if response.Code != http.StatusOK {
		t.Fatal("normal configuration request failed", response.Code, response.Body.String())
	}
	var envelope DeviceViewEnvelope
	if err := DecodeCanonical(response.Body.Bytes(), &envelope, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil || envelope.View.DeviceID != invite.DeviceID {
		t.Fatal("normal configuration lost its strict signed envelope", err)
	}
	read()
	cache.mu.Lock()
	materialized = false
	for key, item := range cache.items {
		materialized = materialized || key.device == invite.DeviceID && len(item.Value.(*deviceConfigEntry).value.body) != 0
	}
	cache.mu.Unlock()
	if !materialized {
		t.Fatal("a later UI read discarded the requested signed configuration")
	}
}

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
