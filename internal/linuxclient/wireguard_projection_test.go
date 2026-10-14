package linuxclient

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"

	"loom/internal/control"
)

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
	p := control.Projection{NetworkID: view.NetworkID, NetworkIntent: control.EmptyNetworkIntent()}
	p.NetworkIntent.Resources = view.Resources
	for _, resource := range view.Resources {
		p.DeviceAuthorizations = append(p.DeviceAuthorizations, control.DeviceAuthorization{ID: resource.OwnerNodeID, Responsibilities: []string{"forward"}})
	}
	var err error
	view.Links, err = control.DerivedNetworkLinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return view
}

func TestWireGuardSharedResourceProjectsIndependentPeers(t *testing.T) {
	view := sharedWireGuardView(t)
	first, identity, err := projectWireGuard(view)
	if err != nil || identity == nil || len(first.WireGuard) != 2 {
		t.Fatal("shared resource did not project two peers with the reverse Link deduplicated", err)
	}
	if first.WireGuard[0].Mode != "initiator" || first.WireGuard[1].Mode != "initiator" || first.WireGuard[0].Interface != first.WireGuard[1].Interface {
		t.Fatal("both peer endpoints or the shared interface changed")
	}
	for _, peer := range first.WireGuard {
		if peer.ListenPort != 51820 || peer.PersistentKeepalive != 25 || peer.Endpoint == "" {
			t.Fatal("automatic peer lost the fixed listener or certified endpoint")
		}
	}
	groups, err := groupWireGuardLinks(first.WireGuard)
	if err != nil || len(groups) != 1 || groups[0].listenPort() != 51820 {
		t.Fatal("initiating peers lost the shared fixed listener", err)
	}
	view.Links[0], view.Links[2] = view.Links[2], view.Links[0]
	reordered, nextIdentity, err := projectWireGuard(view)
	if err != nil || !reflect.DeepEqual(first, reordered) || !reflect.DeepEqual(identity, nextIdentity) {
		t.Fatal("Link order changed projected execution", err)
	}
	for _, conflict := range []string{"key", "address"} {
		t.Run(conflict, func(t *testing.T) {
			view := sharedWireGuardView(t)
			switch conflict {
			case "key":
				view.Resources[2].Authentication.PublicKey = view.Resources[1].Authentication.PublicKey
			case "address":
				view.Resources[2].Authentication.LocalAddresses = view.Resources[1].Authentication.LocalAddresses
			}
			if _, _, err := projectWireGuard(view); err == nil {
				t.Fatal("ambiguous peer execution was accepted")
			}
		})
	}
}
