package control

import (
	"bytes"
	"net"
	"reflect"
	"slices"
	"testing"
)

func TestLinkProbeUsesNativeSenderWithoutServiceOrHy2Credential(t *testing.T) {
	p := relayProjectionFixture(t)
	p.NetworkIntent.Services, p.NetworkIntent.Policies = []Service{}, []NetworkPolicy{}
	for i := range p.DeviceAuthorizations {
		p.DeviceAuthorizations[i].PolicyIDs = []string{}
	}
	p.NetworkIntent.Resources = slices.DeleteFunc(p.NetworkIntent.Resources, func(value TransportResource) bool { return value.Kind != "wireguard" })
	from, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	to, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := executionCredentials(from)
	if err != nil {
		t.Fatal(err)
	}
	_, public, err := sharedWireGuardIdentity(from, keys)
	if err != nil {
		t.Fatal(err)
	}
	if keys[wireGuardSharedCredential] != "" || len(from.PolicyIDs) != 0 || len(from.TransportCredentials) != 0 || len(testDeviceExecution(to).WireGuardPeers) != 1 || testDeviceExecution(to).WireGuardPeers[0].DeviceID != "demo-entry" || testDeviceExecution(to).WireGuardPeers[0].PublicKey != public {
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
	var oldExecution string
	for i := range p.NetworkIntent.Resources {
		if p.NetworkIntent.Resources[i].ID == "demo-exit-wg" {
			address, err := WireGuardAccessAddress(p.NetworkIntent.Resources[i], "")
			if err != nil {
				t.Fatal(err)
			}
			oldExecution = address.String()
			p.NetworkIntent.Resources = append(p.NetworkIntent.Resources[:i], p.NetworkIntent.Resources[i+1:]...)
			break
		}
	}
	hasBinding := func(view DeviceView) bool {
		t.Helper()
		for _, endpoint := range accessWireGuardOutbounds(t, view) {
			for _, raw := range endpoint["source_routes"].([]any) {
				if raw.(map[string]any)["execution"] == oldExecution {
					return true
				}
			}
		}
		return false
	}
	if oldExecution == "" || !hasBinding(from) {
		t.Fatal("fixture lacks the actual outgoing native binding")
	}
	if !bytes.Contains([]byte(testDeviceExecution(from).RuntimeProfile.Config), []byte(mustTransportTag("demo-exit-wg"))) {
		t.Fatal("independent Link measurement lost its complete sender resource description")
	}
	removed, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	if hasBinding(removed) {
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
	var link NetworkLink
	for _, value := range testDeviceExecution(from).Links {
		if value.FromNodeID == from.DeviceID && value.ProbeTarget.Action == "wireguard_echo" {
			link = value
		}
	}
	spec, err := LinkSpecDigest(from, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := LinkSpecDigest(to, link.ID)
	if err != nil || other != spec {
		t.Fatal("Link ends disagree on resource specification", err)
	}
	value := Observation{Level: "link", LinkID: link.ID, ResourceID: link.ResourceID, Target: net.JoinHostPort(link.ProbeTarget.Host, "53"), Action: "wireguard_echo", SpecDigest: spec, NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: 1000, ValidUntil: 2000}
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
		if p.NetworkIntent.Resources[i].ID == link.ResourceID {
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
