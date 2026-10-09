package linuxclient

import (
	"loom/internal/control"
	"reflect"
	"testing"
)

func TestLocalNetworksRequirePhysicalAddressesAndConnectedRoutes(t *testing.T) {
	addresses := []byte(`[
 {"ifname":"demo-lan","flags":["UP","BROADCAST"],"addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24,"scope":"global"},{"family":"inet","local":"203.0.113.10","prefixlen":24,"scope":"global"}]},
 {"ifname":"demo-wg","flags":["UP"],"linkinfo":{"info_kind":"wireguard"},"addr_info":[{"family":"inet","local":"198.51.100.1","prefixlen":24,"scope":"global"}]},
 {"ifname":"demo-tun","flags":["UP"],"linkinfo":{"info_kind":"tun"},"addr_info":[{"family":"inet","local":"203.0.113.1","prefixlen":24,"scope":"global"}]},
 {"ifname":"demo-down","flags":[],"addr_info":[{"family":"inet","local":"203.0.113.2","prefixlen":24,"scope":"global"}]}
]`)
	routes := []byte(`[
 {"dev":"demo-lan","dst":"192.0.2.0/24","scope":"link","protocol":"kernel"},
 {"dev":"demo-lan","dst":"203.0.113.0/24","scope":"link","protocol":"static"},
 {"dev":"demo-wg","dst":"198.51.100.0/24","scope":"link","protocol":"kernel"},
 {"dev":"demo-tun","dst":"203.0.113.0/24","scope":"link","protocol":"kernel"},
 {"dev":"demo-down","dst":"203.0.113.0/24","scope":"link","protocol":"kernel"}
]`)
	values, err := localNetworksFromReadback(addresses, routes, nil)
	if err != nil || !reflect.DeepEqual(values, []control.LocalNetworkPrefix{{Prefix: "192.0.2.0/24", LAN: true}, {Prefix: "198.51.100.0/24"}, {Prefix: "203.0.113.0/24"}}) {
		t.Fatal("connected prefixes lost their physical/overlay sharing distinction", values, err)
	}
	if values, err = localNetworksFromReadback([]byte(`[]`), []byte(`[]`), nil); err != nil || values == nil || len(values) != 0 {
		t.Fatal("successful empty readback was lost")
	}
	if _, err = localNetworksFromReadback([]byte(`null`), routes, nil); err == nil {
		t.Fatal("failed readback became a successful empty observation")
	}
}
