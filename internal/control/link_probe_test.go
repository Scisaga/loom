package control

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestLinkProbeUsesNativeSenderWithoutServiceOrHy2Credential(t *testing.T) {
	p := relayProjectionFixture(t)
	p.DeviceAuthorizations[0].PolicyIDs = []string{}
	from, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	to, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := profileCredentials(from)
	if err != nil {
		t.Fatal(err)
	}
	_, public, err := sharedWireGuardIdentity(from, keys)
	if err != nil {
		t.Fatal(err)
	}
	if keys[wireGuardSharedCredential] != "" || len(from.PolicyIDs) != 0 || len(from.InboundCredentials) != 0 || len(to.WireGuardPeers) != 1 || to.WireGuardPeers[0].DeviceID != "demo-entry" || to.WireGuardPeers[0].PublicKey != public {
		t.Fatal("native Link transport borrowed a Service or lost its fixed sender")
	}
	body, err := CanonicalEncode(to)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("private_key")) || bytes.Contains(body, []byte("link_probe_credentials")) {
		t.Fatal("native receiver obtained another sender's private key or proxy credential")
	}
	var decoded DeviceView
	if err := DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000}); err != nil || !reflect.DeepEqual(decoded, to) {
		t.Fatal("native receiver did not round trip", err)
	}
	p.NetworkIntent.Links = []NetworkLink{}
	removed, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	if len(removed.WireGuardPeers) != 0 || bytes.Contains([]byte(removed.RuntimeProfile.Config), []byte(WireGuardBaseTag("demo-exit-wg"))) {
		t.Fatal("removed Link retained its outgoing binding")
	}
}

func TestNativeLinkObservationBindsSourceAndCurrentResourceSpec(t *testing.T) {
	p := relayProjectionFixture(t)
	from, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	to, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	link := from.Links[0]
	spec, err := LinkSpecDigest(from, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := LinkSpecDigest(to, link.ID)
	if err != nil || other != spec {
		t.Fatal("Link ends disagree on resource specification", err)
	}
	value := Observation{Level: "link", LinkID: link.ID, ResourceID: link.ResourceID, Target: net.JoinHostPort(link.ProbeTarget.Host, "53"), Action: "wireguard_dns", SpecDigest: spec, NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: 1000, ValidUntil: 2000}
	if value.Validate() != nil || verifyLinkObservation(value, from) != nil {
		t.Fatal("valid native observation rejected")
	}
	if verifyLinkObservation(value, to) == nil {
		t.Fatal("receiver forged the sender's measurement")
	}
	changed := value
	changed.Action = "hysteria2_tls"
	if verifyLinkObservation(changed, from) == nil {
		t.Fatal("old nested probe was accepted as native WG evidence")
	}
	for i := range p.NetworkIntent.Resources {
		if p.NetworkIntent.Resources[i].ID == "demo-entry-wg" {
			p.NetworkIntent.Resources[i].DialPort++
		}
	}
	current, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	if verifyLinkObservation(value, current) == nil {
		t.Fatal("old resource measurement survived a changed native segment")
	}
}
