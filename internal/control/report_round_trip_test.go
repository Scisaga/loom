package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestNativeRoundTripKeepsAbsentBytesAndBindsSuccessfulMeasurements(t *testing.T) {
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	digest := "sha256:" + strings.Repeat("0", 64)
	target := net.JoinHostPort(testDerivedLink(t, relayProjectionFixture(t), "demo-entry", "demo-exit").ProbeTarget.Host, "53")
	sample := Observation{Level: "link", LinkID: "demo-link", ResourceID: "demo-wg", Target: target, Action: "wireguard_dns", SpecDigest: digest, NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: 1000, ValidUntil: 2000, DurationMS: new(int64(30))}
	report := DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-entry", ReportSequence: 1, ViewDigest: digest, NetworkGeneration: sample.NetworkGeneration, ReportedAt: 1001, Selections: []ReportSelection{}, Observations: []Observation{sample}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}}
	original, err := SignDeviceReport(report, key)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := CanonicalEncode(original)
	var decoded DeviceReport
	if bytes.Contains(before, []byte("round_trip_ms")) || decodeStoredReport(before, &decoded) != nil || decoded.Verify(public) != nil {
		t.Fatal("absent measurement changed original report")
	}
	after, _ := CanonicalEncode(decoded)
	if !bytes.Equal(before, after) {
		t.Fatal("old report did not round trip")
	}
	for _, value := range []int64{0, 20, 30} {
		report.Observations[0].RoundTripMS = new(value)
		signed, err := SignDeviceReport(report, key)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := CanonicalEncode(signed)
		if decodeStoredReport(body, &decoded) != nil || decoded.Verify(public) != nil || !reflect.DeepEqual(signed, decoded) {
			t.Fatal("measured zero or value lost")
		}
		decoded.Observations[0].RoundTripMS = nil
		if decoded.Verify(public) == nil {
			t.Fatal("measurement was outside signature")
		}
	}
	firstHop := sample
	firstHop.Level, firstHop.LinkID, firstHop.RoundTripMS = "resource", "", new(int64(10))
	if err := firstHop.Validate(); err != nil {
		t.Fatal("native WG first-hop RTT rejected", err)
	}
	for _, change := range []func(*Observation){
		func(v *Observation) { v.RoundTripMS = new(int64(-1)) },
		func(v *Observation) { v.RoundTripMS = new(int64(31)) },
		func(v *Observation) { v.DurationMS = nil },
		func(v *Observation) { v.Result = "unavailable" },
		func(v *Observation) { v.Result = "unknown" },
		func(v *Observation) { v.Action = "hysteria2_tls" },
		func(v *Observation) { v.Level, v.LinkID, v.ResourceID = "egress", "", "" },
	} {
		value := sample
		value.RoundTripMS = new(int64(10))
		change(&value)
		if value.Validate() == nil {
			t.Fatal("unsupported round trip accepted", value)
		}
	}
	for _, raw := range []string{"null", "-1", "1.5", `"1"`} {
		body := bytes.Replace(before, []byte(`"result":"available"`), []byte(`"result":"available","round_trip_ms":`+raw), 1)
		if decodeStoredReport(body, &decoded) == nil {
			t.Fatal("noncanonical optional value accepted", raw)
		}
	}
}

func TestHy2DirectedLinkKeepsAuthenticatedRTTAndDomainTargetInSharedReport(t *testing.T) {
	p := relayProjectionFixture(t)
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	for i := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[i].ID == "demo-entry" {
			p.DeviceAuthorizations[i].DevicePublicKey = public
		}
	}
	for i := range p.NetworkIntent.Resources {
		if p.NetworkIntent.Resources[i].ID == "demo-hy2" {
			p.NetworkIntent.Resources[i].DialHost = "transport.example"
		}
	}
	view, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	links, err := DerivedViewLinks(view)
	if err != nil {
		t.Fatal(err)
	}
	var link NetworkLink
	for _, value := range links {
		if value.FromNodeID == view.DeviceID && value.ResourceID == "demo-hy2" {
			link = value
		}
	}
	spec, err := LinkSpecDigest(view, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := DeviceViewDigest(view)
	resources := []ResourceReadback{}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID != view.DeviceID {
			continue
		}
		acl, _ := InboundACLDigest(view, resource.ID)
		readback := ResourceReadback{ResourceID: resource.ID, ListenerID: resource.ListenerID, Listen: net.JoinHostPort(resource.DialHost, strconv.Itoa(resource.DialPort)), ACLDigest: acl}
		if resource.Kind == "wireguard" {
			readback.PublicKey = *resource.Authentication.PublicKey
		} else {
			readback.CertificateDigest = ReleaseDigest([]byte("demo-certificate"))
		}
		resources = append(resources, readback)
	}
	sample := Observation{Level: "link", LinkID: link.ID, ResourceID: link.ResourceID, Target: "transport.example:443", Action: "hysteria2_echo", SpecDigest: spec,
		NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: 1000, ValidUntil: 601000,
		DurationMS: new(int64(30)), RoundTripMS: new(int64(10)), HY2Transfer: &HY2Transfer{DurationNS: 20_000_000, RXBytes: 512, TXBytes: 256}}
	report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: view.NetworkID, DeviceID: view.DeviceID, ReportSequence: 1, ViewDigest: digest,
		NetworkGeneration: sample.NetworkGeneration, ReportedAt: 1001, Observations: []Observation{sample}, Selections: []ReportSelection{}, Components: []ComponentReadback{},
		Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest, Resources: &resources}}, key)
	if err != nil {
		t.Fatal("current Hy2 segment sample was rejected", err)
	}
	if err := verifyCurrentReport(report, p); err != nil {
		t.Fatal("authenticated directed measurement could not be shared", err)
	}
	body, err := CanonicalEncode(report)
	var decoded DeviceReport
	if err != nil || decodeStoredReport(body, &decoded) != nil || decoded.Verify(public) != nil || !reflect.DeepEqual(decoded, report) {
		t.Fatal("Hy2 segment report lost original measurement bytes")
	}
	for _, target := range []string{"transport.example:0443", "other.example:443"} {
		changed := report
		changed.Observations = []Observation{sample}
		changed.Observations[0].Target = target
		if changed.Validate() == nil && verifyReportViewFields(changed, view) == nil {
			t.Fatal("noncanonical or unauthorized directed target was accepted")
		}
	}
}
