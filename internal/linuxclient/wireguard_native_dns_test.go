package linuxclient

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"loom/internal/control"
)

// The adapter can resolve this certified name; the child has no DNS server at
// the fixture address. Actual startup and business must consume the answer.
func nativePeerTestDNS(t *testing.T) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	return func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "192.0.2.53:53" {
			return nil, errors.New("unexpected DNS destination")
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			query := make([]byte, 512)
			n, err := server.Read(query)
			if err != nil || n < 16 {
				return
			}
			response := append([]byte{}, query[:n]...)
			binary.BigEndian.PutUint16(response[2:4], 0x8180)
			if binary.BigEndian.Uint16(query[n-4:n-2]) == 1 {
				binary.BigEndian.PutUint16(response[6:8], 1)
				response = append(response, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 12)
			}
			_, _ = server.Write(response)
		}()
		return client, nil
	}
}

func serveNativePeerTestDNS(t *testing.T) {
	t.Helper()
	listener, err := net.ListenPacket("udp", "192.0.2.53:53")
	if err != nil {
		t.Fatal(err)
	}
	dial := nativePeerTestDNS(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var query, response [2048]byte
		for {
			n, peer, err := listener.ReadFrom(query[:])
			if err != nil {
				return
			}
			conn, err := dial(context.Background(), "udp", "192.0.2.53:53")
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, writeErr := conn.Write(query[:n])
			n, readErr := conn.Read(response[:])
			_ = conn.Close()
			if writeErr == nil && readErr == nil {
				_, _ = listener.WriteTo(response[:n], peer)
			}
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
}

func TestNativeReceiverKeepsSenderDNSInResourcePreparation(t *testing.T) {
	p, keys, input, at := nativeProjectionFixture(t)
	for i := range p.DeviceAuthorizations {
		p.DeviceAuthorizations[i].DNSServers = []string{"192.0.2.53"}
	}
	for i := range p.NetworkIntent.Resources {
		if p.NetworkIntent.Resources[i].ID == "demo-exit-wg" {
			p.NetworkIntent.Resources[i].DialHost = "demo-peer.example"
		}
	}
	view, err := control.ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	original, err := control.CanonicalEncode(view)
	if err != nil {
		t.Fatal(err)
	}
	executions, err := prepareResourceExecutions(view, input, at)
	if err != nil {
		t.Fatal(err)
	}
	config, err := nodeRuntimeConfig(view, "demo-local", nil, "mixed", executions)
	if err != nil {
		t.Fatal(err)
	}
	profile, _, err := projectWireGuard(view, executions)
	if err != nil || len(profile.WireGuard) != 0 {
		t.Fatal("relay generated host management peers", err)
	}
	actual, err := appendNativeWireGuard(config, view, profile, nil, keys["demo-entry"])
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(actual), &document); err != nil || len(document.Endpoints) != 1 {
		t.Fatal(err)
	}
	endpoint := document.Endpoints[0]
	if endpoint["system"] == true || endpoint["name"] != nil || endpoint["host_sources"] != nil || endpoint["stack_address"] != nil {
		t.Fatal("sender DNS preparation created host geometry")
	}
	if !strings.Contains(actual, "demo-peer.example") {
		t.Fatal("sender description lost its certified name")
	}
	after, _ := control.CanonicalEncode(view)
	if string(after) != string(original) {
		t.Fatal("runtime preparation changed the authenticated View")
	}
}
