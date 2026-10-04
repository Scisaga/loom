package linuxclient

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestWireGuardCertifiedDNSAndAddressChanges(t *testing.T) {
	answers := []byte{20, 10}
	queries := 0
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "192.0.2.53:53" {
			return nil, errors.New("unexpected DNS destination")
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
			response := append([]byte{}, query[:n]...)
			binary.BigEndian.PutUint16(response[2:4], 0x8180)
			if binary.BigEndian.Uint16(query[n-4:n-2]) == 1 {
				binary.BigEndian.PutUint16(response[6:8], uint16(len(answers)))
				for _, last := range answers {
					response = append(response, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, last)
				}
			}
			_, _ = server.Write(response)
		}()
		return client, nil
	}
	desired := wireGuardExecution{WireGuard: []wireGuardExecutionLink{
		{LinkID: "demo-resource-a", PeerPublicKey: "demo-key-a", Mode: "initiator", Endpoint: "demo-relay.example:51820"},
		{LinkID: "demo-resource-b", PeerPublicKey: "demo-key-b", Mode: "initiator", Endpoint: "demo-relay.example:51821"},
		{LinkID: "demo-resource-c", Mode: "acceptor"},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	initial, err := resolveWireGuardEndpoints(ctx, desired, wireGuardExecution{}, []string{"192.0.2.53"}, dial)
	if err != nil || queries != 2 || initial.WireGuard[0].Endpoint != "192.0.2.10:51820" || initial.WireGuard[1].Endpoint != "192.0.2.10:51821" || desired.WireGuard[0].Endpoint != "demo-relay.example:51820" {
		t.Fatalf("certified DNS projection failed: %+v, queries=%d, err=%v", initial, queries, err)
	}
	initial.WireGuard[0].Endpoint = "192.0.2.20:51820"
	stable, err := resolveWireGuardEndpoints(ctx, desired, initial, []string{"192.0.2.53"}, dial)
	if err != nil || !reflect.DeepEqual(stable, initial) {
		t.Fatalf("still valid current endpoint changed: %+v, %v", stable, err)
	}
	answers = []byte{30}
	changed, err := resolveWireGuardEndpoints(ctx, desired, initial, []string{"192.0.2.53"}, dial)
	if err != nil || changed.WireGuard[0].Endpoint != "192.0.2.30:51820" {
		t.Fatalf("new DNS address not projected: %+v, %v", changed, err)
	}
	view := control.DeviceView{Links: []control.NetworkLink{{ID: "demo-link", FromResourceID: "demo-resource-a"}}, Routes: []control.RouteCandidate{
		{ID: "demo-candidate-relay", LinkIDs: []string{"demo-link"}}, {ID: "demo-candidate-direct", LinkIDs: []string{}},
	}}
	state := LocalState{Observations: []clientmodel.Observation{{CandidateID: "demo-candidate-direct"}, {CandidateID: "demo-candidate-relay"}}}
	invalidated := invalidateWireGuardObservations(state, view, initial, changed)
	if len(invalidated.Observations) != 1 || invalidated.Observations[0].CandidateID != "demo-candidate-direct" || len(state.Observations) != 2 {
		t.Fatal("DNS change failed to invalidate only the affected path")
	}
}

func TestWireGuardDNSRefusesHostFallbackAndKernelResolution(t *testing.T) {
	profile := wireGuardExecution{WireGuard: []wireGuardExecutionLink{{Mode: "initiator", Endpoint: "localhost:51820"}}}
	if _, err := resolveWireGuardEndpoints(context.Background(), profile, wireGuardExecution{}, nil, nil); err == nil {
		t.Fatal("host resolver was used without authenticated DNS")
	}
	if _, err := applyWireGuard(&profile, nil, &wireGuardIdentity{}, Options{}); err == nil {
		t.Fatal("unresolved hostname reached the kernel adapter")
	}
	profile.WireGuard[0].Endpoint = "192.0.2.10:51820"
	result, err := resolveWireGuardEndpoints(context.Background(), profile, wireGuardExecution{}, nil, func(context.Context, string, string) (net.Conn, error) {
		t.Error("literal address used DNS")
		return nil, errors.New("unexpected DNS")
	})
	if err != nil || !reflect.DeepEqual(profile, result) {
		t.Fatalf("literal projection changed: %+v, %v", result, err)
	}
}
