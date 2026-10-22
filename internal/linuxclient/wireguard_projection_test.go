package linuxclient

import (
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"loom/internal/control"
)

func TestWireGuardHostNameDoesNotRewriteStableResourceIdentity(t *testing.T) {
	view := sharedWireGuardView(t)
	view.Resources[0].ListenerID = "demo-stable-listener-identity"
	before, err := control.CanonicalEncode(view.Resources)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := projectWireGuard(view)
	if err != nil || len(first.WireGuard) != 2 {
		t.Fatal("stable listener identity was treated as a Linux interface name", err)
	}
	name := first.WireGuard[0].Interface
	if len(name) != 15 || !strings.HasPrefix(name, "loom-wg") || name == view.Resources[0].ListenerID {
		t.Fatal("shared WG did not receive a neutral Linux interface name")
	}
	for _, peer := range first.WireGuard {
		if peer.Interface != name || peer.LinkID != view.Resources[0].ID {
			t.Fatal("a peer changed the shared interface or resource identity")
		}
	}
	after, _ := control.CanonicalEncode(view.Resources)
	if !bytes.Equal(before, after) {
		t.Fatal("host interface projection changed certified bytes")
	}
	links := []control.NetworkLink{}
	for _, link := range view.Links {
		if link.FromNodeID != "demo-peer-b" && link.ToNodeID != "demo-peer-b" {
			links = append(links, link)
		}
	}
	view.Links = links
	next, _, err := projectWireGuard(view)
	if err != nil || len(next.WireGuard) != 1 || next.WireGuard[0].Interface != name {
		t.Fatal("removing a neighbor renamed the shared interface", err)
	}
	view.NetworkID = "demo-other-network"
	other, _, err := projectWireGuard(view)
	if err != nil || other.WireGuard[0].Interface == name {
		t.Fatal("independent networks shared an interface name", err)
	}
}

func TestWireGuardProjectedNameRefusesAnExistingInterface(t *testing.T) {
	view := sharedWireGuardView(t)
	profile, _, err := projectWireGuard(view)
	if err != nil {
		t.Fatal(err)
	}
	options, _, _, load, save := wireGuardFixture(t)
	host := load()
	host.Link = &ipLinkDocument{Index: 17, Name: profile.WireGuard[0].Interface, Alias: "demo-unrelated-owner"}
	host.Link.Info.Kind = "tun"
	save(host)
	if _, err := prepareNativeWireGuard(view, profile, options); !errors.Is(err, ErrWireGuardOwnership) {
		t.Fatal("projected name claimed an existing interface", err)
	}
	for _, call := range load().Calls {
		if strings.Join(call, " ") != "ip -json -details link show" {
			t.Fatal("interface name collision executed a host mutation")
		}
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
