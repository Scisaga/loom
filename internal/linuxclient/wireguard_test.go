package linuxclient

import "testing"

func TestParseWireGuardActualKeepsDirectionReadback(t *testing.T) {
	body := []byte("wg-demo-peer\tprivate\tlocal-public\t51820\toff\n" +
		"wg-demo-peer\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t(none)\t192.0.2.10:51820\t10.0.0.2/32\t1\t2\t3\t25\n")
	actual, err := parseWireGuardActual(body)
	if err != nil {
		t.Fatal(err)
	}
	peer := actual["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
	if peer.Interface != "wg-demo-peer" || peer.ListenPort != 51820 || peer.Endpoint != "192.0.2.10:51820" ||
		peer.AllowedIPs != "10.0.0.2/32" || peer.Keepalive != 25 {
		t.Fatalf("WireGuard readback lost a certified field: %+v", peer)
	}
}

func TestParseWireGuardActualAcceptsKernelOffKeepalive(t *testing.T) {
	body := []byte("wg-demo-peer\tprivate\tlocal-public\t51820\toff\n" +
		"wg-demo-peer\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t(none)\t(none)\t10.0.0.2/32\t0\t0\t0\toff\n")
	actual, err := parseWireGuardActual(body)
	if err != nil || actual["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="].Keepalive != 0 {
		t.Fatalf("acceptor dump=%+v err=%v", actual, err)
	}
}

func TestLinuxWireGuardDefaultsStayInsideUbuntuAppArmorBoundary(t *testing.T) {
	options := Options{}
	options.defaults()
	if options.WireGuardPrivateKey != "/etc/wireguard/node.key" {
		t.Fatalf("WireGuard key path %q is outside the wg AppArmor boundary", options.WireGuardPrivateKey)
	}
}

func TestWireGuardEndpointReadbackRequiresResolvedAddressAndPort(t *testing.T) {
	if !endpointMatches("192.0.2.20:51820", "192.0.2.20:51820") {
		t.Fatal("exact endpoint was rejected")
	}
	if endpointMatches("relay.example:51820", "192.0.2.20:51820") ||
		endpointMatches("relay.example:51820", "relay.example:51820") ||
		endpointMatches("192.0.2.20:51820", "192.0.2.20:51821") ||
		endpointMatches("192.0.2.10:51820", "192.0.2.20:51820") {
		t.Fatal("endpoint drift was accepted")
	}
}
