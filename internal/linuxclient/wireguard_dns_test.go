package linuxclient

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/control"
)

func TestWireGuardPeerCoordinatesDoNotReplaceHostOwnership(t *testing.T) {
	before := wireGuardExecution{WireGuard: []wireGuardExecutionLink{{LinkID: "demo-resource", Interface: "demo-wg", LocalAddress: "192.0.2.1/32", PeerID: "demo-peer", PeerPublicKey: "demo-key", AllowedIP: "192.0.2.2/32", Endpoint: "192.0.2.10:51820", ListenPort: 51820, PersistentKeepalive: 25}}}
	after := wireGuardExecution{WireGuard: slices.Clone(before.WireGuard)}
	after.WireGuard[0].Endpoint, after.WireGuard[0].PersistentKeepalive = "192.0.2.11:51821", 0
	if !sameWireGuardHostInputs(before, after) || before.WireGuard[0].Endpoint != "192.0.2.10:51820" {
		t.Fatal("peer coordinate replaced or mutated host ownership")
	}
	rebound := wireGuardExecution{WireGuard: slices.Clone(after.WireGuard)}
	rebound.WireGuard[0].ListenPort++
	if !sameWireGuardHostInputs(after, rebound) {
		t.Fatal("UDP port rebind replaced host interface ownership")
	}
	for _, change := range []func(*wireGuardExecutionLink){
		func(link *wireGuardExecutionLink) { link.Interface = "demo-other" },
		func(link *wireGuardExecutionLink) { link.LocalAddress = "192.0.2.3/32" },
		func(link *wireGuardExecutionLink) { link.AllowedIP = "192.0.2.4/32" },
		func(link *wireGuardExecutionLink) { link.PeerPublicKey = "demo-other-key" },
	} {
		next := wireGuardExecution{WireGuard: slices.Clone(after.WireGuard)}
		change(&next.WireGuard[0])
		if sameWireGuardHostInputs(before, next) {
			t.Fatal("peer update accepted changed host ownership")
		}
	}
}

func TestLinuxWireGuardCoordinateChangeRebuildsOnlyNativePeers(t *testing.T) {
	p, keys, input, at := nativeProjectionFixture(t)
	before, err := control.ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	executions, err := prepareResourceExecutions(before, input, at)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := projectWireGuard(before, executions)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Capture: "mixed", DeviceState: filepath.Join(t.TempDir(), "demo-state.json"), WireGuardPrivateKey: keys["demo-exit"]}
	connected := []string{}
	config, server, err := rebuildReceivingConfigs(before, options, "demo-secret", nil, executions, clientadapter.WebsiteAccess{}, &connected, nil, first, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range p.NetworkIntent.Resources {
		if p.NetworkIntent.Resources[i].ID == "demo-entry-wg" {
			p.NetworkIntent.Resources[i].DialHost = "192.0.2.99"
		}
	}
	after, err := control.ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	next, _, err := projectWireGuard(after, executions)
	if err != nil || !sameWireGuardHostInputs(first, next) {
		t.Fatal("coordinate changed the host ownership projection", err)
	}
	updated, updatedServer, err := rebuildReceivingConfigs(after, options, "demo-secret", nil, executions, clientadapter.WebsiteAccess{}, &connected, nil, next, nil)
	if err != nil {
		t.Fatal(err)
	}
	changes, hot, err := clientadapter.ReceiverChanges(config, updated)
	if err != nil || !hot || len(changes) != 1 || server != updatedServer {
		t.Fatal("Linux rendered coordinate change required instance replacement", hot, err)
	}
}

func TestWireGuardCertifiedDNSAndAddressChanges(t *testing.T) {
	answers := []byte{20, 10}
	var queries atomic.Int32
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "192.0.2.53:53" {
			return nil, errors.New("unexpected DNS destination")
		}
		queries.Add(1)
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
	if err != nil || queries.Load() < 1 || queries.Load() > 2 || initial.WireGuard[0].Endpoint != "192.0.2.10:51820" || initial.WireGuard[1].Endpoint != "192.0.2.10:51821" || desired.WireGuard[0].Endpoint != "demo-relay.example:51820" {
		t.Fatalf("certified DNS projection failed: %+v, queries=%d, err=%v", initial, queries.Load(), err)
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

}

func TestWireGuardDNSRefusesHostFallbackAndKernelResolution(t *testing.T) {
	profile := wireGuardExecution{WireGuard: []wireGuardExecutionLink{{Mode: "initiator", Endpoint: "localhost:51820"}}}
	if _, err := resolveWireGuardEndpoints(context.Background(), profile, wireGuardExecution{}, nil, nil); err == nil {
		t.Fatal("host resolver was used without authenticated DNS")
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
