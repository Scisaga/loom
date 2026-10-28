package control

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"testing"
)

func denseRelayProjection(t *testing.T) Projection {
	t.Helper()
	p := relayProjectionFixture(t)
	for i := 0; i < 8; i++ {
		node := p.DeviceAuthorizations[1]
		node.ID, node.Name = fmt.Sprintf("demo-relay-%d", i), fmt.Sprintf("Demo relay %d", i)
		p.DeviceAuthorizations = append(p.DeviceAuthorizations, node)
		key := sha256.Sum256([]byte(node.ID))
		public := base64.RawURLEncoding.EncodeToString(key[:])
		addresses := []string{fmt.Sprintf("198.51.100.%d/32", i+10)}
		p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, TransportResource{ID: node.ID + "-wg", Kind: "wireguard", OwnerNodeID: node.ID, ListenerID: node.ID + "-wg", DialHost: fmt.Sprintf("192.0.2.%d", i+30), DialPort: 51820, AccessEnabled: true, Authentication: ResourceAuthentication{PublicKey: &public, LocalAddresses: &addresses}})
	}
	p.NetworkIntent.Policies[0].MaxHops = 0
	sort.Slice(p.NetworkIntent.Resources, func(i, j int) bool { return p.NetworkIntent.Resources[i].ID < p.NetworkIntent.Resources[j].ID })
	sort.Slice(p.DeviceAuthorizations, func(i, j int) bool { return p.DeviceAuthorizations[i].ID < p.DeviceAuthorizations[j].ID })
	return p
}

func TestDensePolicyGeneratesBoundedPathsAndMatchingReceiverPermissions(t *testing.T) {
	p := denseRelayProjection(t)
	access, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	// Ten possible public entries, with one direct exit and two paths for
	// every other entry. This graph has factorially many legal simple paths.
	if len(access.Routes) != 19 {
		t.Fatalf("dense graph produced %d candidates", len(access.Routes))
	}
	groups := map[string]int{}
	for _, r := range access.Routes {
		if len(r.NodeChain) > 3 {
			t.Fatal("dense graph retained unnecessary detours")
		}
		groups[r.FirstResourceID]++
		if groups[r.FirstResourceID] > 2 {
			t.Fatal("unbounded entry/exit group")
		}
	}
	exit, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	if len(exit.InboundCredentials) != len(access.Routes) {
		t.Fatal("sender and receiver candidate sets differ")
	}
	for _, r := range access.Routes {
		found := false
		for _, permission := range exit.InboundCredentials {
			if permission.Candidate.ID == r.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("candidate has no receiver authorization")
		}
	}
	slices.Reverse(p.NetworkIntent.Resources)
	slices.Reverse(p.DeviceAuthorizations)
	shuffled, err := ProjectDeviceView(p, "demo-access")
	if err != nil || !reflect.DeepEqual(shuffled, access) {
		t.Fatal("input order changed projection", err)
	}
}

func TestPathBudgetRetainsSparseLongChainsAndEnforcesConstraints(t *testing.T) {
	p := denseRelayProjection(t)
	policy, service := p.NetworkIntent.Policies[0], p.NetworkIntent.Services[0]
	policy.EntryScope = PolicyScope{Mode: "only", NodeIDs: []string{"demo-entry"}}
	links, err := DerivedNetworkLinks(p)
	if err != nil {
		t.Fatal(err)
	}
	chain := []string{"demo-entry", "demo-relay-0", "demo-relay-1", "demo-relay-2", "demo-exit"}
	sparse := []NetworkLink{}
	for _, link := range links {
		for i := 0; i < len(chain)-1; i++ {
			if link.FromNodeID == chain[i] && link.ToNodeID == chain[i+1] {
				sparse = append(sparse, link)
			}
		}
	}
	paths, err := transportPaths("demo-access", false, service, policy, p.NetworkIntent.Resources, sparse)
	if err != nil || len(paths) != 1 || !reflect.DeepEqual(paths[0].candidate.NodeChain, chain) {
		t.Fatal("only necessary long path was removed", err, len(paths))
	}
	policy.MaxHops = len(chain) - 1
	paths, err = transportPaths("demo-access", false, service, policy, p.NetworkIntent.Resources, sparse)
	if err != nil || len(paths) != 0 {
		t.Fatal("explicit hop bound ignored", err)
	}
	policy.MaxHops = 0
	policy.RelayScope = PolicyScope{Mode: "none", NodeIDs: []string{}}
	paths, err = transportPaths("demo-access", false, service, policy, p.NetworkIntent.Resources, sparse)
	if err != nil || len(paths) != 0 {
		t.Fatal("relay restriction ignored", err)
	}
	policy.RelayScope = PolicyScope{Mode: "any", NodeIDs: []string{}}
	paths, err = transportPaths("demo-relay-1", false, service, policy, p.NetworkIntent.Resources, sparse)
	if err != nil || len(paths) != 0 {
		t.Fatal("path loops through its originating device", err)
	}
}

func TestPathBackupIsShortestDifferentAuthorizedPath(t *testing.T) {
	p := denseRelayProjection(t)
	policy, service := p.NetworkIntent.Policies[0], p.NetworkIntent.Services[0]
	policy.EntryScope = PolicyScope{Mode: "only", NodeIDs: []string{"demo-entry"}}
	links, err := DerivedNetworkLinks(p)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := transportPaths("demo-access", false, service, policy, p.NetworkIntent.Resources, links)
	if err != nil || len(paths) != 2 {
		t.Fatal("missing bounded backup", err, len(paths))
	}
	var primary, backup transportPath
	for _, p := range paths {
		if len(p.links) == 1 {
			primary = p
		} else {
			backup = p
		}
	}
	if len(backup.links) != 2 {
		t.Fatal("backup is not shortest")
	}
	links = slices.DeleteFunc(links, func(link NetworkLink) bool { return link.ID == primary.links[0].ID })
	next, err := transportPaths("demo-access", false, service, policy, p.NetworkIntent.Resources, links)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(next, func(p transportPath) bool { return p.candidate.ID == backup.candidate.ID }) {
		t.Fatal("backup vanished when primary edge was withdrawn")
	}
}
