package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFirstHopAdmissionReusesAnEntryAcrossExitsAndSeparatesPolicies(t *testing.T) {
	p := relayProjectionFixture(t)
	service := p.NetworkIntent.Services[0]
	service.ID = "demo-service-other"
	service.ProbeURLs = []string{"https://other.example/"}
	policy := p.NetworkIntent.Policies[0]
	policy.ID = "demo-policy-other"
	policy.ServiceID = service.ID
	p.NetworkIntent.Services = append(p.NetworkIntent.Services, service)
	p.NetworkIntent.Policies = append(p.NetworkIntent.Policies, policy)
	p.DeviceAuthorizations[0].PolicyIDs = append(p.DeviceAuthorizations[0].PolicyIDs, policy.ID)
	for index := range p.NetworkIntent.Policies {
		p.NetworkIntent.Policies[index].ExitScope = new(PolicyScope{Mode: "any", NodeIDs: []string{}})
	}
	view, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := CanonicalEncode(view)
	probes := []ResourceProbe{}
	credentials, _ := executionCredentials(view)
	for _, policyID := range view.PolicyIDs {
		execution, err := ProjectDeviceCandidates(view, []string{policyID})
		if err != nil {
			t.Fatal(err)
		}
		current, err := FirstHopProbes(execution)
		if err != nil || len(current) != 2 || len(execution.Routes) != 4 {
			t.Fatal("entry admission was expanded per final exit or inactive Policy", len(current), len(execution.Routes), err)
		}
		probes = append(probes, current...)
		refs, err := CandidateFirstHopProbes(execution)
		if err != nil {
			t.Fatal(err)
		}
		for _, route := range execution.Routes {
			probe, found := refs[route.ID]
			if !found || probe.PolicyID != route.PolicyID || probe.Credential != credentials[route.FirstResourceID] {
				t.Fatal("candidate borrowed another Policy's admission proof")
			}
		}
	}
	byResource := map[string]ResourceProbe{}
	for _, probe := range probes {
		if previous, found := byResource[probe.Resource.ID]; found && previous.PolicyID != probe.PolicyID && (previous.SpecDigest == probe.SpecDigest || previous.Credential != probe.Credential) {
			t.Fatal("Policy admission was conflated or stable sender authentication was duplicated")
		}
		byResource[probe.Resource.ID] = probe
	}
	after, _ := CanonicalEncode(view)
	if !bytes.Equal(before, after) {
		t.Fatal("measurement preparation rewrote a signed View")
	}
}

func TestResourceReportBindsExecutionAndRestartsAsRawEvidence(t *testing.T) {
	p := hy2ProjectionFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.DeviceAuthorizations[0].DevicePublicKey = base64.RawURLEncoding.EncodeToString(public)
	view, _ := ProjectDeviceView(p, "demo-access")
	probes, err := FirstHopProbes(testDeviceExecution(view))
	if err != nil || len(probes) != 1 {
		t.Fatal(err)
	}
	probe := probes[0]
	value := Observation{Level: "resource", ResourceID: probe.Resource.ID, Target: probe.Target(), Action: probe.Action(), SpecDigest: probe.SpecDigest,
		NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: 1000, ValidUntil: 601000}
	for _, change := range []func(*Observation){
		func(v *Observation) { v.Target = "192.0.2.11:443" },
		func(v *Observation) { v.ResourceID = "demo-other" },
		func(v *Observation) { v.SpecDigest = "sha256:" + strings.Repeat("f", 64) },
		func(v *Observation) { v.Action = "https_request" },
		func(v *Observation) { v.Target = "192.0.2.10:0443" },
		func(v *Observation) { v.ServiceID = "demo-service" },
	} {
		bad := value
		change(&bad)
		if bad.Validate() == nil && verifyResourceObservation(bad, probes) == nil {
			t.Fatal("false resource evidence accepted")
		}
	}
	for _, change := range []func(*Projection){
		func(p *Projection) { p.NetworkIntent.Resources[0].DialPort++ },
		func(p *Projection) { p.DeviceAuthorizations[0].DNSServers = []string{"192.0.2.53"} },
		func(p *Projection) {
			p.DeviceAuthorizations[0].RuntimeKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
		},
	} {
		changed := p
		changed.NetworkIntent.Resources = append([]TransportResource{}, p.NetworkIntent.Resources...)
		changed.DeviceAuthorizations = append([]DeviceAuthorization{}, p.DeviceAuthorizations...)
		change(&changed)
		next, err := ProjectDeviceView(changed, "demo-access")
		if err != nil {
			t.Fatal(err)
		}
		newProbes, err := FirstHopProbes(testDeviceExecution(next))
		if err != nil || verifyResourceObservation(value, newProbes) == nil {
			t.Fatal("changed execution preserved an old resource sample", err)
		}
	}
	digest, _ := DeviceViewDigest(view)
	report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: view.DeviceID, ReportSequence: 1,
		ViewDigest: digest, PolicyID: probe.PolicyID, NetworkGeneration: value.NetworkGeneration, ReportedAt: 1000, Selections: []ReportSelection{},
		Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "unknown"}, Observations: []Observation{value}}, private)
	if err != nil || verifyCurrentReport(report, p) != nil {
		t.Fatal("authorized resource report rejected", err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := testOpenObservationStore(t, root)
	if err != nil || store.Put(report, p.DeviceAuthorizations[0].DevicePublicKey) != nil {
		t.Fatal("resource report did not persist", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = testOpenObservationStore(t, root)
	if err != nil || !reflect.DeepEqual(store.Verified(p), []DeviceReport{report}) {
		t.Fatal("resource report lost its original bytes or signature", err)
	}
	snapshot := testWebSnapshotWithIntent(p, true, true, true)
	testProjectWebObservations(&snapshot, store.Verified(p), time.UnixMilli(report.ReportedAt))
	for _, device := range snapshot.Devices {
		if device.ID == view.DeviceID && (device.Availability != "unknown" || device.Evidence == nil || !reflect.DeepEqual(device.Evidence.Measurements, []WebObservation{{Observation: value}})) {
			t.Fatal("raw authentication sample became overall health or disappeared")
		}
	}
}
