package clientv2

import (
	"testing"
	"time"

	"loom/internal/wire"
)

const routeHash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestDialOrderPreferredThenAdvertisedNeverDraining(t *testing.T) {
	generation := func(number int64, state string) wire.ListenerGenerationV2 {
		return wire.ListenerGenerationV2{
			Schema: 2, ListenerGeneration: number, PublishedState: state, DialTargetFQDN: "edge.example.test",
			PublicPort: 443 + number, AddressFamilies: []string{"ipv4"}, TransportIdentityRefs: []string{"spki:v1"},
			CredentialGeneration: number, CertificateIdentityProjectionHash: routeHash, PublicProfileGeneration: 1,
			IntroducedRevision: number, ValidFrom: "2026-01-01T00:00:00Z", ValidUntil: "2027-01-01T00:00:00Z",
			RotationOperationHash: routeHash,
		}
	}
	endpoint := wire.DataIngressEndpointV2{EndpointID: "edge", LogicalServerID: "server", Transport: "hysteria2", ListenerGenerations: []wire.ListenerGenerationV2{generation(1, "advertised"), generation(2, "preferred"), generation(3, "draining")}}
	order, err := DialOrder(endpoint, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0].ListenerGeneration != 2 || order[1].ListenerGeneration != 1 {
		t.Fatalf("unexpected order: %#v", order)
	}
}

func TestFixedRemovedFailsClosedAndDirectNeedsNoEndpoint(t *testing.T) {
	if err := ValidateMode(ModeDirect, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMode(ModeFixed, "removed", []string{"authorized"}); err == nil {
		t.Fatal("removed fixed egress silently fell back")
	}
}
