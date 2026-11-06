package control

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"testing"

	"loom/protocol"
)

func TestNativeCandidateIdentityMatchesCanonicalUTF8AndEscapes(t *testing.T) {
	service, policy := `demo-服务"<`, `demo-policy\&`
	choice := protocol.RouteChoice{EntryNodeID: "demo-入口😀", FirstResourceID: "demo-resource>", FinalExit: "demo-exit\u2028value"}
	const expected = "sha256:53f757a8d32707b8a9c63875eac6b3a6009013d4f56e20b72401f581b806ce7b"
	native, err := protocol.CandidateID(service, policy, choice)
	if err != nil || native != expected {
		t.Fatal("native identity changed canonical UTF-8 or escaping", err)
	}
	domain, err := digestContractValue("loom-candidate-id-v3\x00", map[string]any{"service_id": service, "policy_id": policy, "entry_node_id": choice.EntryNodeID, "first_resource_id": choice.FirstResourceID, "final_exit": choice.FinalExit})
	if err != nil || domain != expected {
		t.Fatal("domain and native canonical identity diverged", err)
	}
}

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
	registerTestWireGuardIdentities(t, &p)
	return p
}

func TestDensePolicyUsesOneEntryExitChoiceAndStableForwardPermissions(t *testing.T) {
	p := denseRelayProjection(t)
	access, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	if len(testDeviceExecution(access).Routes) != 10 {
		t.Fatalf("entry/exit choices expanded complete paths: %d", len(testDeviceExecution(access).Routes))
	}
	groups := map[string]bool{}
	for _, route := range testDeviceExecution(access).Routes {
		if groups[route.FirstResourceID] {
			t.Fatal("one entry/exit generated several chain identities")
		}
		groups[route.FirstResourceID] = true
	}
	exit, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	forwards := func(view DeviceView) []TransportCredential {
		result := []TransportCredential{}
		for _, credential := range view.TransportCredentials {
			for _, node := range view.Nodes {
				if node.ID == credential.SenderID && slices.Contains(node.Responsibilities, "forward") {
					result = append(result, credential)
				}
			}
		}
		return result
	}
	original := forwards(exit)
	added := p.DeviceAuthorizations[0]
	added.ID = "demo-new-access"
	added.Responsibilities = []string{"access"}
	added.PolicyIDs = []string{p.NetworkIntent.Policies[0].ID}
	added.WireGuardPublicKey, err = DerivedWireGuardPublicKey(p.NetworkID, added)
	if err != nil {
		t.Fatal(err)
	}
	p.DeviceAuthorizations = append(p.DeviceAuthorizations, added)
	next, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, forwards(next)) {
		t.Fatal("new access expanded or rotated shared forward permissions")
	}
	if len(next.TransportCredentials) != len(exit.TransportCredentials)+1 {
		t.Fatal("new access did not add only its public receiving permission")
	}
	p.DeviceAuthorizations = p.DeviceAuthorizations[:len(p.DeviceAuthorizations)-1]
	slices.Reverse(p.NetworkIntent.Resources)
	slices.Reverse(p.DeviceAuthorizations)
	shuffled, err := ProjectDeviceView(p, "demo-access")
	if err != nil || !reflect.DeepEqual(shuffled, access) {
		t.Fatal("input order changed the projection", err)
	}
}
func TestTopologyRetainsLongPathsAndExplicitConstraintsWithoutNewChainCredentials(t *testing.T) {
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
	stable, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	view := testDeviceExecution(stable)
	view.Policies = []NetworkPolicy{policy}
	view.Links = sparse

	routes, err := candidateEntries(view, service, policy)
	if err != nil || len(routes) != 1 {
		t.Fatal("necessary long path was removed", len(routes), err)
	}
	actual, _, err := CandidateTopologyEstimate(view, routes[0])
	if err != nil || !reflect.DeepEqual(actual, chain) {
		t.Fatal("topology estimate lost the permitted long chain", actual, err)
	}
	policy.MaxHops = len(chain) - 1
	if next, err := candidateEntries(view, service, policy); err != nil || len(next) != 0 {
		t.Fatal("explicit hop bound was ignored", err)
	}
	policy.MaxHops = 0
	policy.RelayScope = PolicyScope{Mode: "none", NodeIDs: []string{}}
	if next, err := candidateEntries(view, service, policy); err != nil || len(next) != 0 {
		t.Fatal("relay scope was ignored", err)
	}
}
func TestChangingRelayWitnessDoesNotChangeEntryExitIdentityOrCredential(t *testing.T) {
	p := denseRelayProjection(t)
	p.NetworkIntent.Policies[0].EntryScope = PolicyScope{Mode: "only", NodeIDs: []string{"demo-entry"}}
	view, err := ProjectDeviceView(p, "demo-access")
	if err != nil || len(testDeviceExecution(view).Routes) != 1 {
		t.Fatal(err)
	}
	candidate := testDeviceExecution(view).Routes[0]
	_, links, err := CandidateTopologyEstimate(testDeviceExecution(view), candidate)
	if err != nil || len(links) != 1 {
		t.Fatal(err)
	}
	changed := testDeviceExecution(view)
	changed.Links = slices.DeleteFunc(slices.Clone(changed.Links), func(link NetworkLink) bool {
		return link.FromNodeID == candidate.EntryNodeID && link.ToNodeID == candidate.FinalExit
	})
	_, alternative, err := CandidateTopologyEstimate(changed, candidate)
	if err != nil || len(alternative) < 2 {
		t.Fatal("available relay alternative was lost", err)
	}
	next, err := candidateEntries(changed, changed.Services[0], changed.Policies[0])
	if err != nil || len(next) != 1 || next[0].ID != candidate.ID || next[0].SpecDigest != candidate.SpecDigest {
		t.Fatal("relay selection rotated stable permission identity", err)
	}
}
