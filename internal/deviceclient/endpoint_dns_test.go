package deviceclient

import (
	"context"
	"reflect"
	"testing"

	"loom/internal/control"
)

func TestEndpointDialAddressesPreservesLiteralAndLegacyAddress(t *testing.T) {
	for _, test := range []struct {
		address string
		dns     []string
	}{
		{address: "192.0.2.10:443", dns: []string{"not-an-ip"}},
		{address: "control.example:443"},
	} {
		got, err := endpointDialAddresses(context.Background(), test.address, test.dns)
		if err != nil || !reflect.DeepEqual(got, []string{test.address}) {
			t.Fatalf("endpointDialAddresses(%q) = %v, %v", test.address, got, err)
		}
	}
}

func TestEndpointRouteExclusionsAreExactCertifiedHostPrefixes(t *testing.T) {
	endpoints := []control.EndpointReference{
		{EndpointID: "demo-serving", Generation: 1, State: "serving", Preference: 1, Address: "192.0.2.10:443"},
		{EndpointID: "demo-draining", Generation: 1, State: "draining", Preference: 2, Address: "192.0.2.20:443"},
	}
	got, err := EndpointRouteExclusions(context.Background(), endpoints, nil)
	if err != nil || !reflect.DeepEqual(got, []string{"192.0.2.10/32"}) {
		t.Fatalf("EndpointRouteExclusions = %v, %v", got, err)
	}
}

func TestCanonicalEndpointAddressesPrefersIPv4AndRejectsNonAddresses(t *testing.T) {
	got, err := canonicalEndpointAddresses([]string{"2001:db8::2", "192.0.2.2", "192.0.2.2", "invalid"}, "443")
	want := []string{"192.0.2.2:443", "[2001:db8::2]:443"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("canonicalEndpointAddresses = %v, %v; want %v", got, err, want)
	}
	if _, err := canonicalEndpointAddresses([]string{"invalid"}, "443"); err == nil {
		t.Fatal("canonicalEndpointAddresses accepted an empty resolved address set")
	}
}
