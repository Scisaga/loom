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

func TestFirstHopProbeUsesAuthorizedFirstCredentialAndPreservesView(t *testing.T) {
	p := relayProjectionFixture(t)
	service := p.NetworkIntent.Services[0]
	service.ID, service.Matchers = "demo-service-other", []ServiceMatcher{{Kind: "dns_exact", Value: "other.example"}}
	policy := p.NetworkIntent.Policies[0]
	policy.ID, policy.ServiceID = "demo-policy-other", service.ID
	p.NetworkIntent.Services = append(p.NetworkIntent.Services, service)
	p.NetworkIntent.Policies = append(p.NetworkIntent.Policies, policy)
	p.DeviceAuthorizations[0].PolicyIDs = append(p.DeviceAuthorizations[0].PolicyIDs, policy.ID)
	view, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := CanonicalEncode(view)
	probes, err := FirstHopProbes(view)
	if err != nil || len(probes) != 2 || len(view.Routes) != 4 {
		t.Fatal("shared resources did not deduplicate", err)
	}
	byCandidate, err := CandidateFirstHopProbes(view)
	if err != nil {
		t.Fatal(err)
	}
	credentials, _ := profileCredentials(view)
	matchedRoutes, differentCredentials := 0, 0
	for _, route := range view.Routes {
		var sampled ResourceProbe
		for _, probe := range probes {
			if probe.Resource.ID == route.FirstResourceID {
				sampled = probe
			}
		}
		bound, found := byCandidate[route.ID]
		want := credentials[route.ID] == sampled.Credential
		if found != want || found && (bound.SpecDigest != sampled.SpecDigest || bound.Credential != credentials[route.ID]) {
			t.Fatal("one Service borrowed another credential's authentication result")
		}
		if found {
			matchedRoutes++
		} else {
			differentCredentials++
		}
	}
	if matchedRoutes != 2 || differentCredentials != 2 {
		t.Fatal("fixture did not exercise different Service credentials on shared resources")
	}
	entry, _ := ProjectDeviceView(p, "demo-entry")
	exit, _ := ProjectDeviceView(p, "demo-exit")
	for _, probe := range probes {
		matched := false
		for _, receiver := range []DeviceView{entry, exit} {
			for _, permission := range receiver.InboundCredentials {
				matched = matched || permission.ResourceID == probe.Resource.ID && permission.Credential == probe.Credential
			}
		}
		if !matched {
			t.Fatal("first hop borrowed a different receiver's credential")
		}
	}
	for _, receiver := range []DeviceView{entry, exit} {
		values, err := FirstHopProbes(receiver)
		if err != nil || len(values) != 0 {
			t.Fatal("Link-only node acquired a public first-hop probe", err)
		}
	}
	after, _ := CanonicalEncode(view)
	if !bytes.Equal(before, after) {
		t.Fatal("derived probe changed certified bytes")
	}
	p.DeviceAuthorizations[0].PolicyIDs = []string{}
	withdrawn, _ := ProjectDeviceView(p, "demo-access")
	values, err := FirstHopProbes(withdrawn)
	if err != nil || len(values) != 0 {
		t.Fatal("withdrawal retained a login projection", err)
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
	probes, err := FirstHopProbes(view)
	if err != nil || len(probes) != 1 {
		t.Fatal(err)
	}
	probe := probes[0]
	value := Observation{Level: "resource", ResourceID: probe.Resource.ID, Target: probe.Target(), Action: "hysteria2_tls", SpecDigest: probe.SpecDigest,
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
		newProbes, err := FirstHopProbes(next)
		if err != nil || verifyResourceObservation(value, newProbes) == nil {
			t.Fatal("changed execution preserved an old resource sample", err)
		}
	}
	digest, _ := DeviceViewDigest(view)
	report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: view.DeviceID, ReportSequence: 1,
		ViewDigest: digest, NetworkGeneration: value.NetworkGeneration, ReportedAt: 1000, Selections: []ReportSelection{},
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
	snapshot := buildWebSnapshot(p, true, true, true)
	projectWebObservations(&snapshot, store.Verified(p), time.UnixMilli(report.ReportedAt))
	for _, device := range snapshot.Devices {
		if device.ID == view.DeviceID && (device.Availability != "unknown" || device.Evidence == nil || !reflect.DeepEqual(device.Evidence.Measurements, []WebObservation{{Observation: value}})) {
			t.Fatal("raw authentication sample became overall health or disappeared")
		}
	}
}
