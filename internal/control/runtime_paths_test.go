package control

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

func relayProjectionFixture(t *testing.T) Projection {
	p := hy2ProjectionFixture(t)
	p.DeviceAuthorizations[1].Responsibilities = []string{"forward", "internet_egress"}
	entry := p.DeviceAuthorizations[1]
	entry.ID, entry.Name = "demo-entry", "Demo entry"
	p.DeviceAuthorizations = append(p.DeviceAuthorizations, entry)
	entryResource := p.NetworkIntent.Resources[0]
	entryResource.ID, entryResource.OwnerNodeID, entryResource.ListenerID, entryResource.DialHost = "demo-entry-hy2", entry.ID, "demo-entry-listener", "192.0.2.11"
	p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, entryResource)
	for i, id := range []string{"demo-entry", "demo-exit"} {
		key := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(rune('a'+i)), 32)))
		addresses := []string{[]string{"198.51.100.1/32", "198.51.100.2/32"}[i]}
		p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, TransportResource{ID: id + "-wg", Kind: "wireguard", OwnerNodeID: id, ListenerID: id + "-wg", DialHost: []string{"192.0.2.11", "192.0.2.10"}[i], DialPort: 51820, Authentication: ResourceAuthentication{PublicKey: &key, LocalAddresses: &addresses}})
	}
	p.NetworkIntent.Links = []NetworkLink{}
	p.NetworkIntent.Policies[0].EntryScope = PolicyScope{Mode: "any", NodeIDs: []string{}}
	p.NetworkIntent.Policies[0].MaxHops = 2
	sort.Slice(p.NetworkIntent.Resources, func(i, j int) bool { return p.NetworkIntent.Resources[i].ID < p.NetworkIntent.Resources[j].ID })
	registerTestWireGuardIdentities(t, &p)
	return p
}

func TestRelayTerminatesHy2AndForwardsIndependentWireGuard(t *testing.T) {
	p := relayProjectionFixture(t)
	access, err := ProjectDeviceView(p, "demo-access")
	if err != nil || len(testDeviceExecution(access).Routes) != 2 {
		t.Fatal("direct and same-exit relay must coexist", err, len(testDeviceExecution(access).Routes))
	}
	entry, err := ProjectDeviceView(p, "demo-entry")
	if err != nil || len(entry.TransportCredentials) != 3 {
		t.Fatal("entry lost stable access or forwarding permissions", err)
	}
	exit, err := ProjectDeviceView(p, "demo-exit")
	if err != nil || len(exit.TransportCredentials) != 3 {
		t.Fatal("exit lost independent path permissions", err)
	}
	if len(testDeviceExecution(exit).WireGuardPeers) == 0 {
		t.Fatal("missing actual native WG senders")
	}
	var document struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(testDeviceExecution(access).RuntimeProfile.Config), &document); err != nil {
		t.Fatal(err)
	}
	for _, outbound := range document.Outbounds {
		if outbound["type"] == "hysteria2" && outbound["detour"] != nil {
			t.Fatal("Hy2 first hop was nested into another transport")
		}
	}
	document.Outbounds, document.Endpoints = nil, nil
	if err := json.Unmarshal([]byte(testDeviceExecution(entry).RuntimeProfile.Config), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Endpoints) != 1 || document.Endpoints[0]["type"] != "wireguard" {
		t.Fatal("entry has no shared native WG sender")
	}
	for _, outbound := range document.Outbounds {
		if outbound["type"] == "hysteria2" && outbound["detour"] != nil {
			t.Fatal("forwarding Hy2 was nested in WG")
		}
	}

	for _, view := range []DeviceView{access, entry, exit} {
		body, err := CanonicalEncode(view)
		var decoded DeviceView
		if err != nil || DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000}) != nil || !reflect.DeepEqual(view, decoded) {
			t.Fatal("relay view did not round trip", err)
		}
	}
	for _, change := range []func(*Projection){
		func(p *Projection) { p.NetworkIntent.Policies[0].MaxHops = 1 },
		func(p *Projection) { p.DeviceAuthorizations[2].Responsibilities = []string{"internet_egress"} },
		func(p *Projection) {
			p.NetworkIntent.Resources = slices.DeleteFunc(p.NetworkIntent.Resources, func(resource TransportResource) bool { return resource.ID == "demo-entry-hy2" })
		},
	} {
		copy := relayProjectionFixture(t)
		change(&copy)
		view, err := ProjectDeviceView(copy, "demo-access")
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range testDeviceExecution(view).Routes {
			if candidate.EntryNodeID == "demo-entry" {
				t.Fatal("withdrawn or disallowed relay remained usable")
			}
		}
	}
}

func TestHybridStartsAtItsLinkWithoutLoopbackCredential(t *testing.T) {
	p := relayProjectionFixture(t)
	p.DeviceAuthorizations[0].ID = "demo-entry"
	p.DeviceAuthorizations[0].Responsibilities = []string{"access", "forward", "internet_egress"}
	p.DeviceAuthorizations = p.DeviceAuthorizations[:2]
	for i := range p.NetworkIntent.Resources {
		if p.NetworkIntent.Resources[i].Kind == "hysteria2" {
			p.NetworkIntent.Resources[i].LinkOnly = true
		}
	}
	registerTestWireGuardIdentities(t, &p)
	view, err := ProjectDeviceView(p, "demo-entry")
	if err != nil || len(testDeviceExecution(view).Routes) != 1 || slices.ContainsFunc(view.TransportCredentials, func(credential TransportCredential) bool {
		return slices.ContainsFunc(view.Resources, func(resource TransportResource) bool {
			return resource.ID == credential.ResourceID && resource.OwnerNodeID == credential.SenderID
		})
	}) {
		t.Fatal("hybrid Link start failed or created loopback credentials", err)
	}
	if testDeviceExecution(view).Routes[0].EntryNodeID != "demo-entry" || testDeviceExecution(view).Routes[0].FirstResourceID != "" || !strings.Contains(testDeviceExecution(view).RuntimeProfile.Config, `"type":"wireguard"`) {
		t.Fatal("composed access and forward node lost its native WG segment")
	}
	links, err := DerivedNetworkLinks(p)
	if err != nil || len(links) == 0 {
		t.Fatal("missing automatic relay segment", err)
	}
	bad := links[0]
	bad.ProbeTarget.Host = "203.0.113.2"
	resources := map[string]TransportResource{}
	for _, r := range p.NetworkIntent.Resources {
		resources[r.ID] = r
	}
	if _, _, _, err := linkResources(bad, resources); err == nil {
		t.Fatal("probe escaped its authenticated WireGuard peer")
	}
}
