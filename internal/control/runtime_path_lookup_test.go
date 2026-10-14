package control

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func TestNamedPathVerificationMatchesAuthorizedEnumeration(t *testing.T) {
	p := relayProjectionFixture(t)
	for i := range p.NetworkIntent.Resources {
		if p.NetworkIntent.Resources[i].Kind == "wireguard" {
			p.NetworkIntent.Resources[i].AccessEnabled = true
		}
	}
	key := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
	addresses := []string{"198.51.100.3/32"}
	middle := TransportResource{ID: "demo-middle-wg", Kind: "wireguard", OwnerNodeID: "demo-middle", ListenerID: "demo-middle-wg", DialHost: "192.0.2.12", DialPort: 51820, Authentication: ResourceAuthentication{PublicKey: &key, LocalAddresses: &addresses}}
	p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, middle)
	device := p.DeviceAuthorizations[2]
	device.ID, device.Name = "demo-middle", "Demo middle"
	p.DeviceAuthorizations = append(p.DeviceAuthorizations, device)
	links, err := DerivedNetworkLinks(p)
	if err != nil {
		t.Fatal(err)
	}
	view := DeviceView{Resources: p.NetworkIntent.Resources, Links: links}
	service, policy := p.NetworkIntent.Services[0], p.NetworkIntent.Policies[0]
	policy.MaxHops = 3
	policy.RelayScope = PolicyScope{Mode: "any", NodeIDs: []string{}}
	for _, origin := range []string{"demo-access", "demo-entry"} {
		paths, err := transportPaths(origin, origin == "demo-entry", service, policy, view.Resources, view.Links)
		if err != nil || len(paths) == 0 {
			t.Fatal("missing authorized reference paths", err)
		}
		for _, path := range paths {
			got, err := candidateTransportPath(view, origin, service, policy, path.candidate)
			if err != nil || !reflect.DeepEqual(got, path) {
				t.Fatal("named path differs from authorized enumeration", err)
			}
			changed := path.candidate
			changed.SpecDigest = "sha256:" + strings.Repeat("0", 64)
			if _, err := candidateTransportPath(view, origin, service, policy, changed); err == nil {
				t.Fatal("same candidate ID admitted a different resource/policy specification")
			}
			if len(path.candidate.NodeChain) != 3 {
				continue
			}
			for _, modify := range []func(*NetworkPolicy){
				func(p *NetworkPolicy) { p.MaxHops = 2 },
				func(p *NetworkPolicy) { p.EntryScope = PolicyScope{Mode: "none", NodeIDs: []string{}} },
				func(p *NetworkPolicy) { p.RelayScope = PolicyScope{Mode: "none", NodeIDs: []string{}} },
				func(p *NetworkPolicy) { p.ExitScope = new(PolicyScope{Mode: "none", NodeIDs: []string{}}) },
			} {
				restricted := policy
				modify(&restricted)
				resources := map[string]TransportResource{}
				for _, resource := range view.Resources {
					resources[resource.ID] = resource
				}
				// Re-signing the specification cannot legalize a path forbidden
				// by one of its entry, intermediate, exit or hop restrictions.
				forged, err := pathCandidate(service, restricted, path.candidate.NodeChain, path.hops, path.links, path.local, resources, nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := candidateTransportPath(view, origin, service, restricted, forged); err == nil {
					t.Fatal("forbidden path accepted with a matching specification")
				}
			}
		}
	}
}
