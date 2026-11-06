package linuxclient

import (
	"bytes"
	"encoding/base64"
	"slices"
	"testing"

	"loom/internal/control"
)

func TestWireGuardBusinessProjectionPreservesResourceIdentityWithoutHostObjects(t *testing.T) {
	view := sharedWireGuardView(t)
	view.Resources[0].ListenerID = "demo-stable-listener-identity"
	before, err := control.CanonicalEncode(view.Resources)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := projectWireGuard(view, fixtureWGExecutions(view))
	if err != nil || len(first.WireGuard) != 0 || first.ListenPort == 0 {
		t.Fatal("business resources created host geometry or lost their explicit listener", err)
	}
	after, _ := control.CanonicalEncode(view.Resources)
	if !bytes.Equal(before, after) {
		t.Fatal("host interface projection changed certified bytes")
	}
	view.Resources = slices.DeleteFunc(slices.Clone(view.Resources), func(r control.TransportResource) bool { return r.OwnerNodeID == "demo-peer-b" })
	view.Nodes = slices.DeleteFunc(slices.Clone(view.Nodes), func(n control.ViewNode) bool { return n.ID == "demo-peer-b" })
	next, _, err := projectWireGuard(view, fixtureWGExecutions(view))
	if err != nil || len(next.WireGuard) != 0 || next.ListenPort != first.ListenPort {
		t.Fatal("removing a neighbor changed local receiving facilities", err)
	}
	view.NetworkID = "demo-other-network"
	other, _, err := projectWireGuard(view, fixtureWGExecutions(view))
	if err != nil || len(other.WireGuard) != 0 {
		t.Fatal("independent network generated implicit host geometry", err)
	}
}

func sharedWireGuardView(t *testing.T) control.DeviceView {
	t.Helper()
	resource := func(id, owner, address string, key byte) control.TransportResource {
		public := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{key}, 32))
		addresses := []string{address}
		return control.TransportResource{ID: id, Kind: "wireguard", OwnerNodeID: owner, ListenerID: "wg-demo", DialHost: "192.0.2.10", DialPort: 51820,
			Authentication: control.ResourceAuthentication{PublicKey: &public, LocalAddresses: &addresses}}
	}
	view := control.DeviceView{NetworkID: "demo-network", DeviceID: "demo-local", Resources: []control.TransportResource{
		resource("demo-local-wg", "demo-local", "198.51.100.1/32", 1),
		resource("demo-peer-a-wg", "demo-peer-a", "198.51.100.2/32", 2),
		resource("demo-peer-b-wg", "demo-peer-b", "198.51.100.3/32", 3),
	}}
	view.Responsibilities = []string{"forward"}
	view.PolicyIDs = []string{}
	view.Nodes = []control.ViewNode{}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID != view.DeviceID {
			view.Nodes = append(view.Nodes, control.ViewNode{ID: resource.OwnerNodeID, Responsibilities: []string{"forward"}, PolicyIDs: []string{}, WireGuardPublicKey: *resource.Authentication.PublicKey})
		}
	}
	return view
}
