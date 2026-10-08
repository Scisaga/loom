package linuxclient

import (
	"testing"
)

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
