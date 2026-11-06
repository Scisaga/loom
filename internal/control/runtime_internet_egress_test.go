package control

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func internetEgressDocument(t *testing.T, view DeviceView) map[string]any {
	t.Helper()
	execution, err := ProjectDeviceExecution(view, nil)
	if err != nil || execution.RuntimeProfile == nil {
		t.Fatal("node execution lacks its required physical I/O", err)
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(execution.RuntimeProfile.Config), &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func TestInternetServicesShareOnePhysicalOutboundAndKeepPolicyTargets(t *testing.T) {
	p := hy2ProjectionFixture(t)
	p.NetworkIntent.Services[0].RestrictToProbeTargets = new(true)
	p.NetworkIntent.Services[0].ProbeURLs = []string{"https://demo-one.example/health"}
	p.NetworkIntent.Policies[0].AllowDirect = new(true)
	service := p.NetworkIntent.Services[0]
	service.ID, service.Name = "demo-z-service", "Demo second service"
	p.NetworkIntent.Services = append(p.NetworkIntent.Services, service)
	policy := p.NetworkIntent.Policies[0]
	policy.ID, policy.ServiceID = "demo-z-policy", service.ID
	p.NetworkIntent.Policies = append(p.NetworkIntent.Policies, policy)
	p.DeviceAuthorizations[0].PolicyIDs = append(p.DeviceAuthorizations[0].PolicyIDs, policy.ID)
	for _, id := range []string{"demo-access", "demo-exit"} {
		view, err := ProjectDeviceView(p, id)
		if err != nil {
			t.Fatal(err)
		}
		document := internetEgressDocument(t, view)
		physical := 0
		for _, raw := range document["outbounds"].([]any) {
			entry := raw.(map[string]any)
			if entry["public_internet"] == true && entry["type"] == "direct" {
				physical++
				if entry["tag"] != "loom-internet-egress" || entry["allowed_targets"] != nil {
					t.Error("physical Internet I/O retained a Service permission copy")
				}
			}
			if access, ok := entry["access"].(map[string]any); ok {
				for _, tag := range access["egress_outbounds"].(map[string]any) {
					if tag != "loom-internet-egress" {
						t.Error("source Internet permission references a Service-specific socket adapter")
					}
				}
			}
		}
		if physical != 1 {
			t.Errorf("%s has %d synonymous Internet socket adapters", id, physical)
		}
		for _, service := range view.Services {
			legacyID, _ := digestContractValue("loom-egress-diagnostic-v3\x00", map[string]any{"network_id": view.NetworkID, "device_id": view.DeviceID, "service_id": service.ID})
			body, _ := json.Marshal(document)
			if strings.Contains(string(body), legacyID) {
				t.Error("Service-specific native measurement identity remains")
			}
		}
		if id == "demo-exit" {
			receiver, err := ReceiverExecutionOptions(view, "demo-hy2")
			if err != nil {
				t.Fatal(err)
			}
			for _, raw := range receiver["policies"].([]any) {
				permission := raw.(map[string]any)
				if permission["egress_outbound"] != "loom-internet-egress" || len(permission["allowed_targets"].([]map[string]any)) != 1 {
					t.Error("receiving Policy lost its exact targets or shared Internet adapter")
				}
			}
		}
		changed := view
		changed.Services = append([]Service{}, view.Services...)
		for i := range changed.Services {
			changed.Services[i].ProbeURLs = []string{"https://demo-one.example/other?sample=changed"}
		}
		pathOnly := internetEgressDocument(t, changed)
		before, _ := json.Marshal(document)
		after, _ := json.Marshal(pathOnly)
		if string(before) != string(after) {
			t.Error("only changing probe paths or queries changed the runtime projection")
		}
	}
}

func TestEgressProbeWithoutResourcesKeepsMinimalNativeIOAndOriginalSpec(t *testing.T) {
	p := hy2ProjectionFixture(t)
	p.NetworkIntent.Resources = []TransportResource{}
	p.DeviceAuthorizations[0].PolicyIDs = []string{}
	p.DeviceAuthorizations[1].DNSServers = []string{"192.0.2.53"}
	p.NetworkIntent.Services[0].ProbeURLs = []string{"https://demo-one.example/health"}
	view, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	probes, err := EgressProbes(view)
	if err != nil || len(probes) != 1 {
		t.Fatal("measurement responsibility depended on a resource or access consumer", err)
	}
	want, err := digestContractValue("loom-egress-probe-v3\x00", map[string]any{"network_id": view.NetworkID, "source": view.DeviceID, "target": probes[0].Target, "action": "https_request", "method": "GET", "redirect": "none", "body_limit": 4096, "tls_minimum": "TLS1.2", "timeout_ms": 8000, "dns_servers": view.DNSServers, "public_internet": true})
	if err != nil || probes[0].SpecDigest != want {
		t.Fatal("changing local I/O changed the original measurement specification", err)
	}
	encoded, _ := json.Marshal(probes[0])
	if strings.Contains(string(encoded), "diagnostic_id") {
		t.Error("measurement retained an obsolete native Service identity")
	}
	document := internetEgressDocument(t, view)
	dns, ok := document["dns"].(map[string]any)
	if !ok || dns["final"] != "loom-resolver-0" {
		t.Fatal("probe-only Internet exit lost its authenticated DNS")
	}
	for _, raw := range document["outbounds"].([]any) {
		entry := raw.(map[string]any)
		if entry["type"] == "selector" {
			t.Error("probe-only node acquired an access selector")
		}
	}
}

func TestHy2OnlyExitKeepsBusinessDNSWithoutMeasurementURLs(t *testing.T) {
	p := hy2ProjectionFixture(t)
	p.NetworkIntent.Services[0].ProbeURLs = nil
	p.DeviceAuthorizations[1].DNSServers = []string{"192.0.2.53"}
	view, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	probes, err := EgressProbes(view)
	if err != nil || len(probes) != 0 {
		t.Fatal("unconfigured measurement URL manufactured a task", err)
	}
	document := internetEgressDocument(t, view)
	dns, ok := document["dns"].(map[string]any)
	if !ok || dns["final"] != "loom-resolver-0" {
		t.Fatal("Hy2 business DNS depended on a measurement diagnostic")
	}
}

func TestEgressRuntimeRequirementTracksFirstAndLastMeasurementDuty(t *testing.T) {
	p := hy2ProjectionFixture(t)
	p.NetworkIntent.Resources = []TransportResource{}
	p.NetworkIntent.Services[0].ProbeURLs = nil
	view := func() DeviceView {
		value, err := ProjectDeviceView(p, "demo-exit")
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	empty := view()
	before, err := RuntimeExecutionDigest(empty)
	if err != nil || HasRuntime(empty) {
		t.Fatal("a node with no executable responsibility started native I/O", err)
	}
	p.NetworkIntent.Services[0].ProbeURLs = []string{"https://demo-one.example/health"}
	active := view()
	started, err := RuntimeExecutionDigest(active)
	if err != nil || !HasRuntime(active) || before == started {
		t.Error("first measurement duty did not activate its native I/O dependency", err)
	}
	p.NetworkIntent.Services[0].ProbeURLs = []string{"https://demo-two.example/other?sample=changed"}
	changed, err := RuntimeExecutionDigest(view())
	if err != nil || changed != started {
		t.Error("editing active measurement configuration replaced physical I/O", err)
	}
	p.NetworkIntent.Services[0].ProbeURLs = nil
	stopped, err := RuntimeExecutionDigest(view())
	if err != nil || stopped != before || HasRuntime(view()) {
		t.Error("last measurement duty left an unneeded runtime", err)
	}
}

func TestRestrictedLANCapturesCompleteMappingButKeepsNarrowPolicy(t *testing.T) {
	_, _, p := deviceContractFixture(t)
	p.DeviceAuthorizations[0].Responsibilities = []string{"access", "forward"}
	service := localNetworkTestService(t, p.NetworkID, "demo-lan", "demo-access")
	service.RestrictToProbeTargets = new(true)
	service.ProbeURLs = []string{"https://demo-one.loom:8443/health"}
	prefix := netip.MustParsePrefix(service.LocalNetwork.VirtualPrefix)
	p.NetworkIntent.Services = []Service{service}
	policy := materialTestPolicy("demo-policy", service.ID)
	policy.ExitScope, policy.AllowDirect, policy.LocalEgressDevices = nil, nil, nil
	p.NetworkIntent.Policies = []NetworkPolicy{policy}
	p.NetworkIntent.DNSRecords = []DNSRecord{
		{ID: "demo-one", Name: "demo-one.loom", ServiceID: service.ID, Addresses: []string{prefix.Addr().Next().String()}},
		{ID: "demo-two", Name: "demo-two.loom", ServiceID: service.ID, Addresses: []string{prefix.Addr().Next().Next().String()}},
	}
	view, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	document := internetEgressDocument(t, view)
	var capture map[string]any
	for _, raw := range document["route"].(map[string]any)["rules"].([]any) {
		entry := raw.(map[string]any)
		if entry["outbound"] == service.Scope() {
			capture = entry
		}
	}
	body, _ := json.Marshal(capture)
	if capture == nil || !strings.Contains(string(body), prefix.String()) || !strings.Contains(string(body), "demo-two.loom") || strings.Contains(string(body), `"port"`) {
		t.Error("a restrictive URL narrowed static capture instead of the current Policy")
	}
	if !targetMatchesService("https://demo-one.loom:8443/other", service, view.DNSRecords...) {
		t.Error("allowed LAN endpoint was denied")
	}
	for _, target := range []string{"https://demo-two.loom:8443/", "https://demo-one.loom:9443/", "https://" + prefix.Addr().Next().Next().String() + ":8443/"} {
		if targetMatchesService(target, service, view.DNSRecords...) {
			t.Error("capture expanded the Service's target permission")
		}
	}
	execution, err := ProjectDeviceCandidates(view, nil)
	if err != nil {
		t.Fatal(err)
	}
	permission, err := executionPolicyProjection(execution, policy)
	if err != nil || !reflect.DeepEqual(permission["allowed_targets"], []map[string]any{{"host": "demo-one.loom", "port": 8443}}) || permission["lan_prefix"] != prefix.String() {
		t.Fatal("LAN scope failed to intersect the mapping with the exact target", err)
	}
}
