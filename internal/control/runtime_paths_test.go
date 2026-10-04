package control

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
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
	p.NetworkIntent.Links = []NetworkLink{{ID: "demo-link", FromNodeID: entry.ID, ToNodeID: "demo-exit", FromResourceID: "demo-entry-wg", ResourceID: "demo-exit-wg", InitiatorNodeID: "demo-exit", Purpose: "relay", ProbeTarget: LinkProbeTarget{ResourceID: "demo-hy2", Host: "198.51.100.2", Port: 443, Action: "hysteria2_tls"}}}
	p.NetworkIntent.Policies[0].EntryScope = PolicyScope{Mode: "any", NodeIDs: []string{}}
	p.NetworkIntent.Policies[0].MaxHops = 2
	sort.Slice(p.NetworkIntent.Resources, func(i, j int) bool { return p.NetworkIntent.Resources[i].ID < p.NetworkIntent.Resources[j].ID })
	return p
}

func TestRelaySharesFinalExitButSeparatesTransportCredentials(t *testing.T) {
	p := relayProjectionFixture(t)
	access, err := ProjectDeviceView(p, "demo-access")
	if err != nil || len(access.Routes) != 2 {
		t.Fatal("one-hop and same-exit relay must coexist", err, len(access.Routes))
	}
	entry, err := ProjectDeviceView(p, "demo-entry")
	if err != nil || len(entry.InboundCredentials) != 1 || entry.InboundCredentials[0].RelayTarget == nil {
		t.Fatal("relay receiver has no exact next-hop permission", err)
	}
	exit, err := ProjectDeviceView(p, "demo-exit")
	if err != nil || len(exit.InboundCredentials) != 1 || exit.InboundCredentials[0].RelayTarget != nil {
		t.Fatal("exit must share one Service credential across paths", err)
	}
	if entry.InboundCredentials[0].Credential == exit.InboundCredentials[0].Credential {
		t.Fatal("relay and final Service credential were interchangeable")
	}
	host, port, err := RelayDialTarget(entry, *entry.InboundCredentials[0].RelayTarget, entry.DeviceID)
	if err != nil || host != "198.51.100.2" || port != 443 {
		t.Fatal("relay target widened beyond its exact peer", err)
	}
	var document struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(access.RuntimeProfile.Config), &document); err != nil {
		t.Fatal(err)
	}
	chained := 0
	for _, outbound := range document.Outbounds {
		if _, ok := outbound["detour"]; ok {
			chained++
			if outbound["server"] != host || outbound["password"] != exit.InboundCredentials[0].Credential {
				t.Fatal("relay lost the authenticated final transport")
			}
		}
	}
	if chained != 1 {
		t.Fatal("relay runtime did not consume the explicit chain")
	}
	for _, view := range []DeviceView{access, entry, exit} {
		body, err := CanonicalEncode(view)
		var decoded DeviceView
		if err != nil || DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000}) != nil || !reflect.DeepEqual(view, decoded) {
			t.Fatal("relay view did not round trip", err)
		}
	}
	for _, change := range []func(*Projection){
		func(p *Projection) { p.NetworkIntent.Links = []NetworkLink{} },
		func(p *Projection) { p.NetworkIntent.Policies[0].MaxHops = 1 },
		func(p *Projection) { p.DeviceAuthorizations[2].Responsibilities = []string{"internet_egress"} },
		func(p *Projection) {
			p.NetworkIntent.Resources = append(p.NetworkIntent.Resources[:1], p.NetworkIntent.Resources[2:]...)
		},
	} {
		copy := relayProjectionFixture(t)
		change(&copy)
		view, err := ProjectDeviceView(copy, "demo-access")
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range view.Routes {
			if len(candidate.LinkIDs) != 0 {
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
	view, err := ProjectDeviceView(p, "demo-entry")
	if err != nil || len(view.Routes) != 1 || len(view.InboundCredentials) != 0 {
		t.Fatal("hybrid Link start failed or created loopback credentials", err)
	}
	if !reflect.DeepEqual(view.Routes[0].NodeChain, []string{"demo-entry", "demo-exit"}) || !strings.Contains(view.RuntimeProfile.Config, `"bind_interface":"demo-entry-wg"`) || strings.Contains(view.RuntimeProfile.Config, `"detour"`) {
		t.Fatal("hybrid did not consume its real local WireGuard interface")
	}
	bad := p.NetworkIntent.Links[0]
	bad.ProbeTarget.Host = "203.0.113.2"
	resources := map[string]TransportResource{}
	for _, r := range p.NetworkIntent.Resources {
		resources[r.ID] = r
	}
	if _, _, _, err := linkResources(bad, resources); err == nil {
		t.Fatal("probe escaped its authenticated WireGuard peer")
	}
}
