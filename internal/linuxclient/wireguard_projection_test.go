package linuxclient

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"

	"loom/internal/control"
)

func sharedWireGuardView() control.DeviceView {
	resource := func(id, owner, address string, key byte) control.TransportResource {
		public := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{key}, 32))
		addresses := []string{address}
		return control.TransportResource{ID: id, Kind: "wireguard", OwnerNodeID: owner, ListenerID: "wg-demo", DialHost: "192.0.2.10", DialPort: 51820,
			Authentication: control.ResourceAuthentication{PublicKey: &public, LocalAddresses: &addresses}}
	}
	return control.DeviceView{DeviceID: "demo-local", Resources: []control.TransportResource{
		resource("demo-local-wg", "demo-local", "198.51.100.1/32", 1),
		resource("demo-peer-a-wg", "demo-peer-a", "198.51.100.2/32", 2),
		resource("demo-peer-b-wg", "demo-peer-b", "198.51.100.3/32", 3),
	}, Links: []control.NetworkLink{
		{ID: "demo-link-a", FromNodeID: "demo-peer-a", ToNodeID: "demo-local", FromResourceID: "demo-peer-a-wg", ResourceID: "demo-local-wg", InitiatorNodeID: "demo-peer-a"},
		{ID: "demo-link-b", FromNodeID: "demo-local", ToNodeID: "demo-peer-b", FromResourceID: "demo-local-wg", ResourceID: "demo-peer-b-wg", InitiatorNodeID: "demo-local"},
		{ID: "demo-reverse-a", FromNodeID: "demo-local", ToNodeID: "demo-peer-a", FromResourceID: "demo-local-wg", ResourceID: "demo-peer-a-wg", InitiatorNodeID: "demo-peer-a"},
	}}
}

func TestWireGuardSharedResourceProjectsIndependentPeers(t *testing.T) {
	view := sharedWireGuardView()
	first, identity, err := projectWireGuard(view)
	if err != nil || identity == nil || len(first.WireGuard) != 2 {
		t.Fatal("shared resource did not project two peers with the reverse Link deduplicated", err)
	}
	if first.WireGuard[0].Mode != "acceptor" || first.WireGuard[1].Mode != "initiator" || first.WireGuard[0].Interface != first.WireGuard[1].Interface {
		t.Fatal("peer directions or the shared interface changed")
	}
	view.Links[0], view.Links[2] = view.Links[2], view.Links[0]
	reordered, nextIdentity, err := projectWireGuard(view)
	if err != nil || !reflect.DeepEqual(first, reordered) || !reflect.DeepEqual(identity, nextIdentity) {
		t.Fatal("Link order changed projected execution", err)
	}
	for _, conflict := range []string{"key", "address", "direction"} {
		t.Run(conflict, func(t *testing.T) {
			view := sharedWireGuardView()
			switch conflict {
			case "key":
				view.Resources[2].Authentication.PublicKey = view.Resources[1].Authentication.PublicKey
			case "address":
				view.Resources[2].Authentication.LocalAddresses = view.Resources[1].Authentication.LocalAddresses
			case "direction":
				view.Links[2].InitiatorNodeID = "demo-local"
			}
			if _, _, err := projectWireGuard(view); err == nil {
				t.Fatal("ambiguous peer execution was accepted")
			}
		})
	}
}
