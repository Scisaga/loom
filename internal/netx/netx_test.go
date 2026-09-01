package netx

import (
	"net/netip"
	"testing"
)

func TestIsPublicGlobalUnicastRejectsLocalReservedAndDocumentationRanges(t *testing.T) {
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !IsPublicGlobalUnicast(netip.MustParseAddr(value)) {
			t.Errorf("public address %s rejected", value)
		}
	}
	for _, value := range []string{
		"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1", "192.0.2.1",
		"198.18.0.1", "198.51.100.1", "203.0.113.1", "240.0.0.1", "::1", "2001:db8::1",
	} {
		if IsPublicGlobalUnicast(netip.MustParseAddr(value)) {
			t.Errorf("non-public address %s accepted", value)
		}
	}
}

func TestNormalizePublicEndpointCanonicalizesDNSAndIP(t *testing.T) {
	for input, want := range map[string]string{
		" Edge.Example.NET ":          "edge.example.net",
		"2606:4700:4700:0:0:0:0:1111": "2606:4700:4700::1111",
	} {
		if got, ok := NormalizePublicEndpoint(input); !ok || got != want {
			t.Errorf("NormalizePublicEndpoint(%q)=(%q,%v), want %q", input, got, ok, want)
		}
	}
	for _, input := range []string{"10.0.0.1", "203.0.113.1", "https://edge.example.net", "edge", "bad_.example"} {
		if got, ok := NormalizePublicEndpoint(input); ok {
			t.Errorf("invalid endpoint %q normalized to %q", input, got)
		}
	}
}
