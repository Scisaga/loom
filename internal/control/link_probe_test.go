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
)

func TestLinkProbeProjectionIsPurposeIsolatedAndRevocable(t *testing.T) {
	p := relayProjectionFixture(t)
	views := map[string]DeviceView{}
	for _, id := range []string{"demo-access", "demo-entry", "demo-exit"} {
		view, err := ProjectDeviceView(p, id)
		if err != nil {
			t.Fatal(err)
		}
		body, err := CanonicalEncode(view)
		var decoded DeviceView
		if err != nil || DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000}) != nil || !reflect.DeepEqual(view, decoded) {
			t.Fatal("private Link projection did not round trip", err)
		}
		views[id] = view
	}
	from, to, access := views["demo-entry"], views["demo-exit"], views["demo-access"]
	if len(from.PolicyIDs) != 0 || from.RuntimeProfile != nil || len(from.LinkProbeCredentials) != 1 || !reflect.DeepEqual(from.LinkProbeCredentials, to.LinkProbeCredentials) || access.LinkProbeCredentials != nil {
		t.Fatal("probe borrowed a Service assignment or escaped the two Link owners")
	}
	probe := from.LinkProbeCredentials[0]
	for _, view := range views {
		for _, service := range view.InboundCredentials {
			if probe.Credential == service.Credential {
				t.Fatal("probe and forwarding credentials are interchangeable")
			}
		}
	}
	for _, change := range []func(*Projection){
		func(p *Projection) { p.NetworkIntent.Links = nil },
		func(p *Projection) { p.DeviceAuthorizations[2].Responsibilities = []string{"internet_egress"} },
		func(p *Projection) { p.DeviceAuthorizations[1].Responsibilities = []string{"internet_egress"} },
		func(p *Projection) { p.NetworkIntent.Resources = nil },
	} {
		changed := relayProjectionFixture(t)
		change(&changed)
		for _, id := range []string{"demo-entry", "demo-exit"} {
			view, err := ProjectDeviceView(changed, id)
			if err != nil || len(view.LinkProbeCredentials) != 0 {
				t.Fatal("withdrawn Link permission survived", err)
			}
		}
	}
	// Names and independent Service assignment do not rotate probe permission.
	p.DeviceAuthorizations[2].Name = "Demo renamed"
	p.DeviceAuthorizations[0].PolicyIDs = []string{}
	changed, err := ProjectDeviceView(p, "demo-entry")
	if err != nil || !reflect.DeepEqual(from.LinkProbeCredentials, changed.LinkProbeCredentials) {
		t.Fatal("unrelated display or Service changes rotated probe permission", err)
	}
	access.LinkProbeCredentials = from.LinkProbeCredentials
	if access.Validate() == nil {
		t.Fatal("third party access acquired Link credentials")
	}
	from.LinkProbeCredentials = append(from.LinkProbeCredentials, probe)
	if from.Validate() == nil {
		t.Fatal("duplicated Link credential accepted")
	}
}

func TestLinkProbePreservesPriorViewAndACLBytes(t *testing.T) {
	p := relayProjectionFixture(t)
	view, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	currentACL, err := InboundACLDigest(view, "demo-hy2")
	if err != nil {
		t.Fatal(err)
	}
	view.LinkProbeCredentials = nil
	original, err := CanonicalEncode(view)
	if err != nil || bytes.Contains(original, []byte("link_probe_credentials")) {
		t.Fatal("absent optional projection changed original View", err)
	}
	var decoded DeviceView
	if err := DecodeCanonical(original, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000}); err != nil {
		t.Fatal("original View cannot be replayed", err)
	}
	reencoded, err := CanonicalEncode(decoded)
	if err != nil || !bytes.Equal(original, reencoded) {
		t.Fatal("original View bytes were reinterpreted", err)
	}
	want, err := digestContractValue("loom-inbound-acl-v3\x00", view.InboundCredentials)
	got, e := InboundACLDigest(view, "demo-hy2")
	if err != nil || e != nil || got != want || currentACL == got {
		t.Fatal("prior ACL changed or the new probe permission was not bound", err, e)
	}
	view.LinkProbeCredentials = []LinkProbeCredential{}
	if view.Validate() == nil {
		t.Fatal("noncanonical empty optional credentials accepted")
	}
}

func TestLinkProbeViewAdditionStillRequiresAuthenticatedFactProgress(t *testing.T) {
	f, proof, _ := deviceContractFixture(t)
	view, err := ProjectDeviceView(relayProjectionFixture(t), "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	service := materialTestService("demo-service")
	first := f.sign(t, 1, 1, nil, "demo-first-service", "service.put", "service", service.ID, service)
	service.Name = "Demo renamed service"
	second := f.sign(t, 1, 2, &first, "demo-rename-service", "service.put", "service", service.ID, service, materialTestID(t, first))
	keyID, _ := KeyID(f.members[1].PublicKey)
	original := view
	original.LinkProbeCredentials = nil
	previous, err := SignDeviceViewEnvelope(DeviceViewEnvelope{Schema: 3, NetworkID: "demo-network", GenesisDigest: materialTestID(t, f.genesis),
		IssuerControlID: f.members[1].ControlID, IssuerKeyID: keyID, ControlProof: proof,
		FactFrontier: []FactFrontier{{KeyID: keyID, Sequence: 1, TipMaterialID: materialTestID(t, first)}}, View: original}, f.keys[1])
	if err != nil {
		t.Fatal(err)
	}
	next := previous
	next.View = view
	next, err = SignDeviceViewEnvelope(next, f.keys[1])
	if err != nil || CheckDeviceViewAdvance(next, previous, previous.FactFrontier) == nil {
		t.Fatal("new probe execution bypassed the same-frontier rejection", err)
	}
	next.FactFrontier = []FactFrontier{{KeyID: keyID, Sequence: 2, TipMaterialID: materialTestID(t, second)}}
	next, err = SignDeviceViewEnvelope(next, f.keys[1])
	if err != nil || CheckDeviceViewAdvance(next, previous, previous.FactFrontier) != nil {
		t.Fatal("actual signed fact progress could not advance the immutable prior View", err)
	}
}

func TestLinkObservationsBindExactSourceTargetAndEveryResource(t *testing.T) {
	p := relayProjectionFixture(t)
	view, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := LinkSpecDigest(view, "demo-link")
	if err != nil {
		t.Fatal(err)
	}
	value := Observation{Level: "link", LinkID: "demo-link", ResourceID: "demo-exit-wg", Target: "198.51.100.2:443", Action: "hysteria2_tls", SpecDigest: digest,
		NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: 1000, ValidUntil: 31000}
	if value.Validate() != nil || verifyLinkObservation(value, view) != nil {
		t.Fatal("exact probe sample rejected")
	}
	for _, change := range []func(*Observation){
		func(v *Observation) { v.Target = "198.51.100.3:443" },
		func(v *Observation) { v.Target = "198.51.100.2:444" },
		func(v *Observation) { v.ResourceID = "demo-entry-wg" },
		func(v *Observation) { v.SpecDigest = "sha256:" + strings.Repeat("a", 64) },
		func(v *Observation) { v.Action = "https_request" },
	} {
		bad := value
		change(&bad)
		if verifyLinkObservation(bad, view) == nil {
			t.Fatal("out of specification Link observation accepted")
		}
	}
	for _, id := range []string{"demo-entry-wg", "demo-exit-wg", "demo-hy2"} {
		changed := view
		changed.Resources = append([]TransportResource{}, view.Resources...)
		for i := range changed.Resources {
			if changed.Resources[i].ID == id {
				changed.Resources[i].DialHost = "203.0.113.17"
			}
		}
		if verifyLinkObservation(value, changed) == nil {
			t.Fatal("changed Link resource retained a stale observation")
		}
	}
	to, _ := ProjectDeviceView(p, "demo-exit")
	if verifyLinkObservation(value, to) == nil {
		t.Fatal("UDP initiator impersonated the directed Link's probe source")
	}
	view.LinkProbeCredentials = nil
	if verifyLinkObservation(value, view) == nil {
		t.Fatal("View without probe permission manufactured an observation")
	}
}

func TestSignedLinkReportRestartsWithoutManufacturingCurrentHealth(t *testing.T) {
	p := relayProjectionFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.DeviceAuthorizations[2].DevicePublicKey = base64.RawURLEncoding.EncodeToString(public)
	view, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	viewDigest, _ := DeviceViewDigest(view)
	spec, _ := LinkSpecDigest(view, "demo-link")
	report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: view.DeviceID, ReportSequence: 1,
		ViewDigest: viewDigest, NetworkGeneration: "demo-underlay", ReportedAt: 1000, Selections: []ReportSelection{}, Components: []ComponentReadback{},
		Runtime: RuntimeReadback{State: "unknown"}, Observations: []Observation{{Level: "link", LinkID: "demo-link", ResourceID: "demo-exit-wg", Target: "198.51.100.2:443",
			Action: "hysteria2_tls", SpecDigest: spec, NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: 1000, ValidUntil: 4102444800000}}}, private)
	if err != nil || verifyCurrentReport(report, p) != nil {
		t.Fatal("signed Link report rejected", err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(report, p.DeviceAuthorizations[2].DevicePublicKey); err != nil {
		t.Fatal(err)
	}
	store, err = OpenObservationStore(root)
	if err != nil || len(store.Verified(p)) != 1 || !reflect.DeepEqual(store.History(), []DeviceReport{report}) {
		t.Fatal("original signed Link report did not survive restart", err)
	}
	snapshot := buildWebSnapshot(p, true, true, true)
	projectWebObservations(&snapshot, store.Verified(p))
	if len(snapshot.Links) != 1 || snapshot.Links[0].Availability != "unknown" {
		t.Fatal("future device expiry manufactured current topology health")
	}
	for _, device := range snapshot.Devices {
		if device.ID == view.DeviceID && (device.Evidence == nil || !reflect.DeepEqual(device.Evidence.Measurements, report.Observations)) {
			t.Fatal("normal UI projection lost the original Link sample")
		}
	}
}
