package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"testing"
)

func TestWebProbeTargetPoolPreservesUnusedValuesAndServiceScopeMatches(t *testing.T) {
	f := newMaterialFixture(t)
	p, err := Project(f.genesis, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	lan := localNetworkTestService(t, p.NetworkID, "demo-lan", "demo-node-a")
	lanAddress := netip.MustParsePrefix(lan.LocalNetwork.VirtualPrefix).Addr().Next().String()
	p.NetworkIntent.Services = []Service{
		{ID: "demo-suffix", Name: "Demo suffix", Kind: "internet", Matchers: []ServiceMatcher{{Kind: "dns_suffix", Value: "demo-service.example"}}},
		{ID: "demo-ipv6", Name: "Demo IPv6", Kind: "internet", Matchers: []ServiceMatcher{{Kind: "ip_prefix", Value: "2001:db8::/32"}}},
		{ID: "demo-ipv4", Name: "Demo IPv4", Kind: "internet", Matchers: []ServiceMatcher{{Kind: "ip_prefix", Value: "192.0.2.0/24"}}},
		{ID: "demo-exact", Name: "Demo exact", Kind: "internet", Matchers: []ServiceMatcher{{Kind: "dns_exact", Value: "demo-service.example"}}},
		lan,
	}
	p.NetworkIntent.DNSRecords = []DNSRecord{
		{ID: "demo-lan-name", ServiceID: lan.ID, Name: "demo-lan.loom", Addresses: []string{lanAddress}},
		{ID: "demo-collision-a", ServiceID: lan.ID, Name: "demo-collision.loom", Addresses: []string{lanAddress}},
		{ID: "demo-collision-b", ServiceID: lan.ID, Name: "demo-collision.loom", Addresses: []string{lanAddress}},
	}
	cases := []struct {
		id, url string
		matches []string
	}{
		{"demo-unused", "https://demo-unused.example/health", []string{}},
		{"demo-subdomain", "https://api.demo-service.example/health", []string{"demo-suffix"}},
		{"demo-overlap", "https://demo-service.example/health", []string{"demo-exact", "demo-suffix"}},
		{"demo-boundary", "https://otherdemo-service.example/health", []string{}},
		{"demo-ipv6-target", "https://[2001:db8::10]/health", []string{"demo-ipv6"}},
		{"demo-ipv4-target", "https://192.0.2.10/health", []string{"demo-ipv4"}},
		{"demo-lan-name-target", "https://demo-lan.loom/health", []string{"demo-lan"}},
		{"demo-lan-ip-target", "https://" + lanAddress + "/health", []string{"demo-lan"}},
		{"demo-lan-collision", "https://demo-collision.loom/health", []string{}},
	}
	want := map[string][]string{}
	for _, tc := range cases {
		target := BusinessProbeTarget{ID: tc.id, URL: tc.url}
		if err := target.Validate(); err != nil {
			t.Fatal(tc.id, err)
		}
		p.NetworkIntent.BusinessProbeTargets = append(p.NetworkIntent.BusinessProbeTargets, target)
		want[tc.id] = tc.matches
	}
	snapshot := buildWebSnapshot(p, true, true, true)
	if len(snapshot.Paths) != 0 || len(snapshot.BusinessProbeTargets) != len(cases) {
		t.Fatal("shared pool was inferred from device paths or observations")
	}
	for i, target := range snapshot.BusinessProbeTargets {
		if !reflect.DeepEqual(target.MatchedServiceIDs, want[target.ID]) || i > 0 && snapshot.BusinessProbeTargets[i-1].ID >= target.ID {
			t.Fatalf("target %s lost scope boundaries or stable ordering: %#v", target.ID, target)
		}
	}
	if got := buildWebSnapshot(Projection{}, true, true, true).BusinessProbeTargets; got == nil || len(got) != 0 {
		t.Fatal("empty pool must remain an explicit empty list")
	}
}

func TestWebProbeTargetScopeDoesNotGrantDevicePermission(t *testing.T) {
	_, _, p := deviceContractFixture(t)
	p.NetworkIntent.Services = append(p.NetworkIntent.Services, materialTestService("demo-unassigned"))
	p.NetworkIntent.BusinessProbeTargets = []BusinessProbeTarget{
		{ID: "demo-allowed", URL: "https://demo-service.example/health"},
		{ID: "demo-unassigned-target", URL: "https://demo-unassigned.example/health"},
		{ID: "demo-unmatched", URL: "https://demo-unmatched.example/health"},
	}
	view, err := ProjectDeviceView(p, "demo-access")
	if err != nil || len(view.Routes) != 1 || !reflect.DeepEqual(view.BusinessProbeTargets, []ServiceProbeTargets{{ServiceID: "demo-service", Targets: []string{"https://demo-service.example/health"}}}) {
		t.Fatal("shared pool widened the assigned Service authorization", err)
	}
	for _, withdraw := range []func(){
		func() { p.NetworkIntent.Policies[0].Action = "deny" },
		func() { p.DeviceAuthorizations[0].PolicyIDs = []string{} },
	} {
		p.NetworkIntent.Policies[0].Action = "allow"
		withdraw()
		snapshot := buildWebSnapshot(p, true, true, true)
		view, err = ProjectDeviceView(p, "demo-access")
		if err != nil || len(view.BusinessProbeTargets) != 0 || len(view.Routes) != 0 || len(snapshot.Paths) != 0 || len(snapshot.BusinessProbeTargets) != 3 {
			t.Fatal("withdrawal either lost the shared pool or retained device probe permission", err)
		}
	}
}

func TestWebProbeTargetFormalWriteReadbackRestartAndWithdrawal(t *testing.T) {
	server, _, _, _, _, _ := enrollmentAuthorityFixture(t)
	read := func() WebSnapshot {
		t.Helper()
		response := httptest.NewRecorder()
		server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil))
		var snapshot WebSnapshot
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &snapshot) != nil {
			t.Fatal("probe pool readback failed", response.Code)
		}
		return snapshot
	}
	target := BusinessProbeTarget{ID: "demo-probe", URL: "https://demo-service.example/health"}
	op := Operation{Schema: 3, RequestID: "demo-create-probe", Operation: "probe_target.put", TargetKind: "probe_target", TargetID: target.ID, Dependencies: []string{}, Payload: target}
	body, err := EncodeOperation(op)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.operation(response, httptest.NewRequest(http.MethodPost, "/api/control/operations", bytes.NewReader(body)))
	if response.Code != http.StatusForbidden {
		t.Fatal("probe write bypassed administrator authentication")
	}
	var accepted struct {
		MaterialID string      `json:"material_id"`
		Snapshot   WebSnapshot `json:"snapshot"`
	}
	response = localNetworkAdminHTTP(t, server, "/api/control/operations", op)
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &accepted) != nil || accepted.MaterialID == "" || len(accepted.Snapshot.BusinessProbeTargets) != 1 {
		t.Fatal("normal operation did not return the accepted pool", response.Body.String())
	}
	if submitAuthority(t, server.Runtime, op).MaterialID != accepted.MaterialID {
		t.Fatal("unchanged probe request retry created another fact")
	}
	raw, err := server.Runtime.Authority.Material(accepted.MaterialID)
	if err != nil {
		t.Fatal(err)
	}
	original, decodeErr := DecodeMaterial(raw)
	again, _, encodeErr := EncodeMaterial(original)
	if decodeErr != nil || encodeErr != nil || !bytes.Equal(raw, again) {
		t.Fatal("probe target changed its canonical signed original", decodeErr, encodeErr)
	}
	root := server.Runtime.Authority.root
	server.Runtime.Close()
	server.Runtime, err = OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { server.Runtime.Close() }()
	want := []WebBusinessProbeTarget{{ID: target.ID, URL: target.URL, MatchedServiceIDs: []string{"demo-service"}}}
	if snapshot := read(); snapshot.Schema != 3 || !reflect.DeepEqual(snapshot.BusinessProbeTargets, want) || len(snapshot.Paths) != 0 {
		t.Fatal("restart lost the unused shared target or manufactured a device path")
	}
	if after, err := server.Runtime.Authority.Material(accepted.MaterialID); err != nil || !bytes.Equal(after, raw) {
		t.Fatal("restart modified the signed target original", err)
	}
	target.URL = "https://demo-unused.example/health"
	op.RequestID, op.Payload = "demo-stale-probe", target
	if stale := localNetworkAdminHTTP(t, server, "/api/control/operations", op); stale.Code != http.StatusUnprocessableEntity || !reflect.DeepEqual(read().BusinessProbeTargets, want) {
		t.Fatal("stale probe edit overwrote the accepted target")
	}
	op.RequestID, op.Dependencies = "demo-update-probe", []string{accepted.MaterialID}
	response = localNetworkAdminHTTP(t, server, "/api/control/operations", op)
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &accepted) != nil {
		t.Fatal("reviewed probe edit failed", response.Body.String())
	}
	if got := read().BusinessProbeTargets; !reflect.DeepEqual(got, []WebBusinessProbeTarget{{ID: target.ID, URL: target.URL, MatchedServiceIDs: []string{}}}) {
		t.Fatal("unmatched edited target disappeared from the full pool")
	}
	deletion := Operation{Schema: 3, RequestID: "demo-delete-probe", Operation: "probe_target.delete", TargetKind: "probe_target", TargetID: target.ID, Dependencies: []string{accepted.MaterialID}, Payload: DeleteTarget{ID: target.ID}}
	if response := localNetworkAdminHTTP(t, server, "/api/control/operations", deletion); response.Code != http.StatusOK || len(read().BusinessProbeTargets) != 0 {
		t.Fatal("deleted target remained in the management pool", response.Body.String())
	}
	server.Runtime.Close()
	server.Runtime, err = OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, found := server.Runtime.Authority.Snapshot().CurrentTarget("probe_target", target.ID)
	if len(read().BusinessProbeTargets) != 0 || !found || !state.Deleted {
		t.Fatal("restart resurrected the deleted target or lost its reviewed baseline")
	}
	for _, flags := range []struct{ admin, writable, allowed bool }{{true, true, true}, {true, false, false}, {false, true, false}} {
		snapshot := buildWebSnapshot(server.Runtime.Authority.Snapshot(), flags.admin, false, flags.writable)
		for _, operation := range []string{"probe_target.put", "probe_target.delete"} {
			if containsString(snapshot.Capabilities.Operations, operation) != flags.allowed {
				t.Fatal("probe capability disagrees with authenticated local signing availability")
			}
		}
	}
}

func TestWebProbeTargetConflictsRemainVisibleWithoutRestoringPoolValue(t *testing.T) {
	f := newMaterialFixture(t)
	target := BusinessProbeTarget{ID: "demo-probe", URL: "https://demo-original.example/health"}
	original := f.sign(t, 0, 1, nil, "demo-original-probe", "probe_target.put", "probe_target", target.ID, target)
	id := materialTestID(t, original)
	target.URL = "https://demo-left.example/health"
	left := f.sign(t, 0, 2, &original, "demo-left-probe", "probe_target.put", "probe_target", target.ID, target, id)
	target.URL = "https://demo-right.example/health"
	right := f.sign(t, 1, 1, nil, "demo-right-probe", "probe_target.put", "probe_target", target.ID, target, id)
	for _, facts := range [][]Material{{original, left, right}, {right, left, original}} {
		p, err := Project(f.genesis, nil, facts)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := buildWebSnapshot(p, true, true, true)
		state, ok := p.CurrentTarget("probe_target", target.ID)
		if !ok || !state.Conflicted || len(snapshot.BusinessProbeTargets) != 0 || len(snapshot.UIState.Warnings) != 1 || snapshot.UIState.Warnings[0].Code != "conflicting_facts" {
			t.Fatal("probe conflict restored an ancestor or hid the conflicted target")
		}
	}
}
