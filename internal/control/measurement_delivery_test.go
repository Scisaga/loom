package control

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestMeasurementDeliveryDeltaKeepsOldSamplesOldAndResetsLostCursors(t *testing.T) {
	projection := relayProjectionFixture(t)
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := DeviceViewDigest(view)
	link := testDerivedLink(t, projection, "demo-entry", "demo-exit")
	spec, _ := LinkSpecDigest(view, link.ID)
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	observation := Observation{Level: "link", ResourceID: link.ResourceID, LinkID: link.ID, Target: net.JoinHostPort(link.ProbeTarget.Host, "53"), Action: "wireguard_echo", SpecDigest: spec, NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli(), DurationMS: new(int64(15)), RoundTripMS: new(int64(10))}
	row := DeviceLinkObservation{DeviceID: link.FromNodeID, ReportSequence: 1, ReportDigest: "sha256:" + strings.Repeat("1", 64), CurrentUntil: observation.ValidUntil, Observation: observation}
	full := DeviceLinkObservations{Schema: 3, NetworkID: view.NetworkID, DeviceID: view.DeviceID, ViewDigest: digest, Cursor: "projection", Reset: true, Removed: []string{}, Observations: []DeviceLinkObservation{row}}
	server := &Server{}
	first, err := server.issueMeasurementDelivery(full, "", measurementDeliveryOptions{0, defaultMeasurementDeliveryBounds})
	if err != nil || !first.Reset || len(first.Observations) != 1 {
		t.Fatal("first delivery", err)
	}
	cache, err := MergeMeasurementDelivery(nil, first, view)
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := first
	ambiguous.Reset = false
	id, _ := MeasurementItemID(row)
	ambiguous.Removed = []string{id}
	if _, err := MergeMeasurementDelivery(&cache, ambiguous, view); err == nil {
		t.Fatal("one delta both withdrew and replaced the same measurement")
	}
	for _, cursor := range []string{"demo cursor", "demo\n", "demo/next", strings.Repeat("x", 129)} {
		invalid := first
		invalid.Cursor = cursor
		request := DeviceLinkObservationRequest{Schema: 3, ViewDigest: digest, Cursor: cursor}
		if invalid.Validate() == nil || request.Validate() == nil {
			t.Fatal("noncanonical cursor accepted")
		}
	}
	full.Observations[0].ReportSequence = 2
	full.Observations[0].ReportDigest = "sha256:" + strings.Repeat("2", 64)
	unchanged, err := server.issueMeasurementDelivery(full, first.Cursor, measurementDeliveryOptions{0, defaultMeasurementDeliveryBounds})
	if err != nil || unchanged.Reset || len(unchanged.Observations) != 0 || len(unchanged.Removed) != 0 {
		t.Fatal("repeated report was counted as a new measurement", err)
	}
	cache, err = MergeMeasurementDelivery(&cache, unchanged, view)
	if err != nil || cache.Observations[0].Observation.ObservedAt != observation.ObservedAt || cache.Observations[0].CurrentUntil != observation.ValidUntil {
		t.Fatal("delta renewed an old sample", err)
	}
	full.Observations = []DeviceLinkObservation{}
	removed, err := server.issueMeasurementDelivery(full, unchanged.Cursor, measurementDeliveryOptions{0, defaultMeasurementDeliveryBounds})
	if err != nil || removed.Reset || len(removed.Removed) != 1 {
		t.Fatal("withdrawn sample missing from delta", err)
	}
	cache, err = MergeMeasurementDelivery(&cache, removed, view)
	if err != nil || len(cache.Observations) != 0 {
		t.Fatal("withdrawn sample survived merge", err)
	}
	restarted := &Server{}
	reset, err := restarted.issueMeasurementDelivery(full, removed.Cursor, measurementDeliveryOptions{0, defaultMeasurementDeliveryBounds})
	if err != nil || !reset.Reset {
		t.Fatal("restart reused a deleted cursor cache", err)
	}
	if _, err := MergeMeasurementDelivery(nil, removed, view); err == nil {
		t.Fatal("delta accepted without its complete cache")
	}
}

func TestEgressMeasurementConfigurationIsSharedWithoutChangingServicePermission(t *testing.T) {
	p := hy2ProjectionFixture(t)
	p.NetworkIntent.Services[0].ProbeURLs = []string{"https://demo-service.example/health"}
	service := p.NetworkIntent.Services[0]
	service.ID = "demo-second-service"
	p.NetworkIntent.Services = append(p.NetworkIntent.Services, service)
	policy := materialTestPolicy("demo-second-policy", service.ID)
	p.NetworkIntent.Policies = append(p.NetworkIntent.Policies, policy)
	p.DeviceAuthorizations[0].PolicyIDs = append(p.DeviceAuthorizations[0].PolicyIDs, policy.ID)
	view, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	values, err := EgressProbes(view)
	if err != nil || len(values) != 1 {
		t.Fatal("same egress request was expanded per consumer", len(values), err)
	}
	access, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	if probes, err := EgressProbes(access); err != nil || len(probes) != 0 {
		t.Fatal("access duty acquired exit measurement permission", err)
	}
	before, _ := RuntimeExecutionDigest(view)
	for index := range p.NetworkIntent.Services {
		p.NetworkIntent.Services[index].ProbeURLs = []string{"https://demo-service.example/other"}
	}
	after, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	next, _ := RuntimeExecutionDigest(after)
	if before != next {
		t.Fatal("changing probe URLs rebuilt the receiver's data plane")
	}
}

func TestEgressMeasurementsContinueWithoutAccessConsumers(t *testing.T) {
	p := hy2ProjectionFixture(t)
	p.NetworkIntent.Services[0].ProbeURLs = []string{"https://demo-service.example/health"}
	p.DeviceAuthorizations[0].PolicyIDs = []string{}
	p.DeviceAuthorizations[1].DNSServers = []string{"192.0.2.53"}
	view, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	probes, err := EgressProbes(view)
	if err != nil || len(probes) != 1 || len(view.PolicyIDs) != 0 || len(testDeviceExecution(view).Routes) != 0 || len(view.TransportCredentials) != 0 {
		t.Fatal("exit measurements depended on an access consumer or assigned its Policy", err)
	}
	body, err := CanonicalEncode(view)
	if err != nil || !bytes.Contains([]byte(testDeviceExecution(view).RuntimeProfile.Config), []byte("192.0.2.53")) {
		t.Fatal("probe-only exit has no certified DNS execution", err)
	}
	var decoded DeviceView
	if err := DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000}); err != nil {
		t.Fatal("probe-only exit was not a canonical executable View", err)
	}
	view.DNSRecords = append(view.DNSRecords, DNSRecord{Name: "demo-unrelated.loom"})
	unchanged, err := EgressProbes(view)
	if err != nil || len(unchanged) != 1 || unchanged[0].SpecDigest != probes[0].SpecDigest {
		t.Fatal("unrelated overlay DNS invalidated an Internet measurement", err)
	}
	view.DNSServers = []string{"192.0.2.54"}
	changed, err := EgressProbes(view)
	if err != nil || len(changed) != 1 || changed[0].SpecDigest == probes[0].SpecDigest {
		t.Fatal("actual Internet resolver changes reused an incompatible sample", err)
	}
	view.Responsibilities = []string{"forward"}
	if values, err := EgressProbes(view); err != nil || len(values) != 0 {
		t.Fatal("forward acquired Internet exit measurement duties", err)
	}
}

func TestForwardCanConsumeRelevantExitSamplesWithoutAccessPolicyAssignment(t *testing.T) {
	p := relayProjectionFixture(t)
	target := "https://demo-service.example/health"
	p.NetworkIntent.Services[0].ProbeURLs = []string{target}
	viewFor := deviceLinkViewFor(func(id string) (DeviceView, error) { return ProjectDeviceView(p, id) })
	forward, _, err := viewFor("demo-entry")
	if err != nil || len(forward.PolicyIDs) != 0 || len(testDeviceExecution(forward).Routes) != 0 || len(forward.TransportCredentials) == 0 {
		t.Fatal("fixture lacks independently authorized forwarding", err)
	}
	queries, err := deviceMeasurementQueries(p, forward, viewFor)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, query := range queries {
		if query.spec.Level == "egress" {
			count++
			if query.source != "demo-exit" || query.spec.Target != target {
				t.Fatal("forward acquired an unrelated exit measurement")
			}
		}
	}
	if count != 1 {
		t.Fatal("forward could not reuse its authorized exit's result", count)
	}
	// Removing a derived credential slice is not a Policy revocation. Shared
	// exit samples follow the forward's current Policy scope, independent of
	// how many original access devices have joined.
	p.NetworkIntent.Policies[0].Action = "deny"
	forward, err = ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	queries, err = deviceMeasurementQueries(p, forward, viewFor)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range queries {
		if query.spec.Level == "egress" {
			t.Fatal("withdrawn forwarding permission retained a remote exit query")
		}
	}
}
