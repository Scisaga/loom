package deviceclient

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"loom/internal/control"
)

func TestBootstrapClaimAndResumeUseSignedDNSWithoutReplacingIdentity(t *testing.T) {
	invite, _ := schema3Fixture(t, "linux", func(value *control.Invite) {
		value.Endpoint.Host = "demo-entry.example"
		value.DNSServers = []string{"192.0.2.53"}
	})
	path := filepath.Join(t.TempDir(), "identity")
	store, err := OpenForPlatform(path, invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	public, request := store.PublicKey(), store.ClaimRequestID()
	queries, endpoints := 0, 0
	stopTLS := errors.New("demo endpoint reached")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = control.WithEndpointDialer(ctx, func(_ context.Context, network, address string) (net.Conn, error) {
		if network == "tcp" && address == "192.0.2.8:443" {
			endpoints++
			return nil, stopTLS
		}
		if network != "udp" || address != "192.0.2.53:53" {
			t.Errorf("bootstrap bypassed its signed resolver: %s %s", network, address)
			return nil, errors.New("unexpected underlay dial")
		}
		queries++
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			query := make([]byte, 512)
			n, err := server.Read(query)
			if err != nil {
				return
			}
			answer := append([]byte{}, query[:n]...)
			binary.BigEndian.PutUint16(answer[2:4], 0x8180)
			if binary.BigEndian.Uint16(query[n-4:n-2]) == 1 {
				binary.BigEndian.PutUint16(answer[6:8], 1)
				answer = append(answer, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 8)
			}
			_, _ = server.Write(answer)
		}()
		return client, nil
	})
	for _, attempt := range []func(context.Context, IdentityStore) (control.EnrollmentResponse, error){Claim, Resume} {
		if _, err := attempt(ctx, store); !errors.Is(err, stopTLS) {
			t.Fatal("signed DNS did not supply the bootstrap TLS address", err)
		}
		store, err = Load(path)
		if err != nil || store.PublicKey() != public || store.ClaimRequestID() != request || store.LKG() != nil {
			t.Fatal("failed bootstrap or restart replaced the pending identity", err)
		}
	}
	if queries != 4 || endpoints != 2 {
		t.Fatalf("unexpected DNS/endpoint attempts: %d/%d", queries, endpoints)
	}
}

type bootstrapInviteOverride struct {
	IdentityStore
	invite control.BootstrapInvite
}

func (store bootstrapInviteOverride) Invite() control.BootstrapInvite { return store.invite }

func TestBootstrapRejectsUnsignedDNSAndHostResolverFallback(t *testing.T) {
	invite, _ := schema3Fixture(t, "linux", func(value *control.Invite) { value.Endpoint.Host = "localhost" })
	store, err := OpenForPlatform(filepath.Join(t.TempDir(), "identity"), invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	ctx := control.WithEndpointDialer(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		t.Error("unconfigured or unauthenticated DNS reached the network")
		return nil, errors.New("unexpected underlay access")
	})
	if _, err := Claim(ctx, store); err == nil {
		t.Fatal("bootstrap used host-local resolution")
	}
	tampered := invite
	payload := invite.Material.Payload.(control.Invite)
	payload.DNSServers = []string{"192.0.2.53"}
	tampered.Material.Payload = payload
	if _, err := Claim(ctx, bootstrapInviteOverride{IdentityStore: store, invite: tampered}); err == nil {
		t.Fatal("bootstrap consumed DNS before authenticating the Invite")
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
