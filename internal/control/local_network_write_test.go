package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
)

func localNetworkWriteFixture(t *testing.T) (*Server, ed25519.PrivateKey) {
	t.Helper()
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t, func(v *Invite) {
		v.DeviceID = "demo-gateway"
		v.Name = "Demo gateway"
		v.Responsibilities = []string{"forward"}
		v.PolicyIDs = []string{}
		v.Medium = "sh"
	})
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("gateway enrollment failed", response.Body.String())
	}
	return server, key
}

func reportLocalNetworks(t *testing.T, server *Server, key ed25519.PrivateKey, sequence U64, prefixes []string) DeviceReport {
	t.Helper()
	view, err := ProjectDeviceView(server.Runtime.Authority.Snapshot(), "demo-gateway")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := DeviceViewDigest(view)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(prefixes)
	networks := make([]LocalNetworkPrefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		networks = append(networks, LocalNetworkPrefix{Prefix: prefix, LAN: prefix == "192.0.2.0/24"})
	}
	report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: view.NetworkID, DeviceID: view.DeviceID, ReportSequence: sequence, ViewDigest: digest, NetworkGeneration: "demo-network-generation", ReportedAt: server.now().UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, LocalNetworks: &networks, Runtime: RuntimeReadback{State: "unknown"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	response := enrollmentHTTP(t, server, "/device/report", report, tunnelIdentity{Mode: "device", DeviceID: view.DeviceID})
	if response.Code != http.StatusOK {
		t.Fatal("authenticated prefix report failed", response.Body.String())
	}
	return report
}

func localNetworkAdminHTTP(t *testing.T, server *Server, path string, value any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := CanonicalEncode(value)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)))
	return response
}

func previewLocalNetwork(t *testing.T, server *Server, id, request string) Operation {
	t.Helper()
	response := localNetworkAdminHTTP(t, server, "/api/control/services/local-network-allocation", LocalNetworkAllocationRequest{Schema: 3, RequestID: request, ID: id, Name: "Demo LAN", GatewayNodeID: "demo-gateway", LocalPrefix: "192.0.2.0/24"})
	if response.Code != http.StatusOK {
		t.Fatal("allocation preview failed", response.Body.String())
	}
	op, err := DecodeOperation(response.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func currentLocalNetwork(t *testing.T, server *Server, id string) Service {
	t.Helper()
	for _, value := range server.Runtime.Authority.Snapshot().NetworkIntent.Services {
		if value.ID == id {
			return value
		}
	}
	t.Fatal("missing persisted LAN Service")
	return Service{}
}

func TestLocalNetworkFormalAllocationRejectsStalePreviewAndPreservesRetry(t *testing.T) {
	server, key := localNetworkWriteFixture(t)
	reportLocalNetworks(t, server, key, 1, []string{"192.0.2.0/24"})
	op := previewLocalNetwork(t, server, "demo-lan", "demo-create-lan")
	for _, value := range server.Runtime.Authority.Snapshot().NetworkIntent.Services {
		if value.ID == op.TargetID {
			t.Fatal("read-only preview created authority")
		}
	}
	if response := localNetworkAdminHTTP(t, server, "/api/control/operations", op); response.Code != http.StatusOK {
		t.Fatal("reviewed creation failed", response.Body.String())
	}
	want := op.Payload.(Service)
	if actual := currentLocalNetwork(t, server, want.ID); !reflect.DeepEqual(actual, want) {
		t.Fatal("persisted mapping differs from reviewed exact address")
	}
	stale := previewLocalNetwork(t, server, "demo-second-lan", "demo-second-create")
	reportLocalNetworks(t, server, key, 2, []string{"192.0.2.0/24", stale.Payload.(Service).LocalNetwork.VirtualPrefix})
	if response := localNetworkAdminHTTP(t, server, "/api/control/operations", stale); response.Code != http.StatusUnprocessableEntity {
		t.Fatal("changed prefix evidence did not invalidate stale preview", response.Code)
	}
	if response := localNetworkAdminHTTP(t, server, "/api/control/operations", op); response.Code != http.StatusOK {
		t.Fatal("accepted request could not be retried after report change", response.Body.String())
	}
	root := server.Runtime.Authority.root
	server.Runtime.Close()
	var err error
	server.Runtime, err = OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Runtime.Close() })
	if actual := currentLocalNetwork(t, server, want.ID); !reflect.DeepEqual(actual, want) {
		t.Fatal("mapping changed on restart")
	}
	response := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil))
	var snapshot WebSnapshot
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &snapshot) != nil {
		t.Fatal("normal management readback failed")
	}
	found := false
	for _, service := range snapshot.Services {
		found = found || service.ID == want.ID && reflect.DeepEqual(service, want)
	}
	if !found {
		t.Fatal("management entry lost persisted mapping")
	}
}

func TestLocalNetworkConflictEvidenceCannotAuthorizeSharing(t *testing.T) {
	server, key := localNetworkWriteFixture(t)
	report := reportLocalNetworks(t, server, key, 1, []string{"192.0.2.0/24"})
	op := previewLocalNetwork(t, server, "demo-lan", "demo-create-lan")
	(*report.LocalNetworks)[0].LAN = false
	report.ReportSequence++
	report, err := SignDeviceReport(report, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := CanonicalEncode(report)
	var decoded DeviceReport
	decodeErr := DecodeCanonical(body, &decoded, materialDecodeLimits())
	if err != nil || decodeErr != nil || !reflect.DeepEqual(decoded, report) {
		t.Fatal("signed LAN report did not round trip", err, decodeErr)
	}
	if response := enrollmentHTTP(t, server, "/device/report", report, tunnelIdentity{Mode: "device", DeviceID: report.DeviceID}); response.Code != http.StatusOK {
		t.Fatal("conflict-only evidence was not accepted", response.Body.String())
	}
	request := LocalNetworkAllocationRequest{Schema: 3, RequestID: "demo-review", ID: "demo-lan", Name: "Demo LAN", GatewayNodeID: "demo-gateway", LocalPrefix: "192.0.2.0/24"}
	if response := localNetworkAdminHTTP(t, server, "/api/control/services/local-network-allocation", request); response.Code != http.StatusUnprocessableEntity {
		t.Fatal("a tunnel/conflict prefix became shareable", response.Code)
	}
	if response := localNetworkAdminHTTP(t, server, "/api/control/operations", op); response.Code != http.StatusUnprocessableEntity {
		t.Fatal("an earlier LAN preview bypassed the new non-LAN report", response.Code)
	}
}

func TestLocalNetworkBoundedReallocationAndExplicitRecovery(t *testing.T) {
	server, key := localNetworkWriteFixture(t)
	reportLocalNetworks(t, server, key, 1, []string{"192.0.2.0/24"})
	op := previewLocalNetwork(t, server, "demo-lan", "demo-create-lan")
	if response := localNetworkAdminHTTP(t, server, "/api/control/operations", op); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	for attempt := 0; attempt <= 3; attempt++ {
		current := currentLocalNetwork(t, server, "demo-lan")
		if !current.LocalNetwork.Enabled || current.LocalNetwork.AllocationAttempt != attempt {
			t.Fatal("allocation attempt changed without its signed transition")
		}
		reportLocalNetworks(t, server, key, U64(attempt+2), []string{"192.0.2.0/24", current.LocalNetwork.VirtualPrefix})
		if err := server.reconcileLocalNetworks(context.Background()); err != nil {
			t.Fatal("conflict follow-up failed", err)
		}
	}
	disabled := currentLocalNetwork(t, server, "demo-lan")
	if disabled.LocalNetwork.Enabled || disabled.LocalNetwork.AllocationAttempt != 3 {
		t.Fatal("three failed reallocations did not persist disabled mapping")
	}
	frontier := server.Runtime.Authority.Frontier()
	reportLocalNetworks(t, server, key, 6, []string{"192.0.2.0/24"})
	if err := server.reconcileLocalNetworks(context.Background()); err != nil || !reflect.DeepEqual(frontier, server.Runtime.Authority.Frontier()) {
		t.Fatal("disabled mapping automatically revived when conflict disappeared", err)
	}
	retry := previewLocalNetwork(t, server, "demo-lan", "demo-manual-recovery")
	if response := localNetworkAdminHTTP(t, server, "/api/control/operations", retry); response.Code != http.StatusOK {
		t.Fatal("explicit reviewed recovery failed", response.Body.String())
	}
	active := currentLocalNetwork(t, server, "demo-lan")
	if !active.LocalNetwork.Enabled || active.LocalNetwork.AllocationAttempt != 0 {
		t.Fatal("explicit recovery did not start a new bounded allocation round")
	}
}
