package deviceclient

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
)

func TestBootstrapReferenceUsesOnlyFrozenUnderlayHostAndPreservesIdentity(t *testing.T) {
	invite, _ := schema3Fixture(t, "linux", func(value *control.Invite) {
		value.Endpoint.Host = "demo-entry.example"
		value.DNSServers = []string{"192.0.2.53"}
	})
	reference, err := control.ReferenceForInvite(invite)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity")
	store, err := OpenReference(path, reference)
	if err != nil {
		t.Fatal(err)
	}
	public, request := store.PublicKey(), store.ClaimRequestID()
	var endpoints atomic.Int32
	stopTLS := errors.New("demo endpoint reached")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = control.WithEndpointDialer(ctx, func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "demo-entry.example:443" {
			t.Error("bootstrap changed frozen endpoint")
		}
		endpoints.Add(1)
		return nil, stopTLS
	})
	for _, attempt := range []func(context.Context, IdentityStore) (control.EnrollmentResponse, error){Claim, Resume} {
		if _, err := attempt(ctx, store); !errors.Is(err, stopTLS) {
			t.Fatal(err)
		}
		store, err = Load(path)
		if err != nil || store.PublicKey() != public || store.ClaimRequestID() != request || store.state.Invite != nil || store.LKG() != nil {
			t.Fatal("failed bootstrap or reopen replaced pending identity", err)
		}
	}
	if endpoints.Load() != 2 {
		t.Fatal("unexpected endpoint attempts")
	}
}

func TestEndpointDialAddressesPreservesCertifiedLiteral(t *testing.T) {
	for _, test := range []struct {
		address string
		dns     []string
	}{
		{address: "192.0.2.10:443", dns: []string{"not-an-ip"}},
	} {
		got, err := endpointDialAddresses(context.Background(), test.address, test.dns)
		if err != nil || !reflect.DeepEqual(got, []string{test.address}) {
			t.Fatalf("endpointDialAddresses(%q) = %v, %v", test.address, got, err)
		}
	}
}

func TestEndpointRouteExclusionsAreExactCertifiedHostPrefixes(t *testing.T) {
	endpoints := []control.EndpointGeneration{
		{ID: "demo-serving", Generation: 1, State: "serving", Preference: 1, Host: "192.0.2.10", Port: 443},
		{ID: "demo-draining", Generation: 1, State: "draining", Preference: 2, Host: "192.0.2.20", Port: 443},
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
