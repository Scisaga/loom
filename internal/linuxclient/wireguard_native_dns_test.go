package linuxclient

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

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

func TestNativeReceiversConsumeResolvedManagementAddress(t *testing.T) {
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
	executions, err := prepareHY2Executions(view, input, at)
	if err != nil {
		t.Fatal(err)
	}
	config, err := nodeRuntimeConfig(view, "demo-local", nil, "mixed", executions)
	if err != nil {
		t.Fatal(err)
	}
	profile, _, err := projectWireGuard(view)
	if err != nil || len(profile.WireGuard) != 1 {
		t.Fatal("missing management peer", err)
	}
	for _, endpoint := range []string{"192.0.2.12:51822", "[2001:db8::12]:51822"} {
		t.Run(endpoint, func(t *testing.T) {
			resolved := wireGuardExecution{WireGuard: append([]wireGuardExecutionLink{}, profile.WireGuard...)}
			resolved.WireGuard[0].Endpoint = endpoint
			actual, err := appendNativeReceivers(config, view, resolved, nil, keys["demo-entry"])
			if err != nil {
				t.Fatal(err)
			}
			var document struct {
				Endpoints []struct {
					Peers []struct {
						PublicKey string `json:"public_key"`
						Address   string `json:"address"`
						Port      uint16 `json:"port"`
					} `json:"peers"`
				} `json:"endpoints"`
			}
			if err := json.Unmarshal([]byte(actual), &document); err != nil {
				t.Fatal(err)
			}
			address := netip.MustParseAddrPort(endpoint)
			found := false
			for _, resource := range document.Endpoints {
				for _, peer := range resource.Peers {
					if peer.PublicKey == profile.WireGuard[0].PeerPublicKey {
						found = true
						if peer.Address != address.Addr().String() || peer.Port != address.Port() {
							t.Fatal("native peer discarded the resolved endpoint")
						}
					}
				}
			}
			if !found || strings.Contains(actual, "demo-peer.example") {
				t.Fatal("native endpoint still depends on resolving the original name")
			}
			after, _ := control.CanonicalEncode(view)
			if string(after) != string(original) || profile.WireGuard[0].Endpoint != "demo-peer.example:51822" {
				t.Fatal("runtime address overwrote the certified name")
			}
		})
	}
	if _, err := appendNativeReceivers(config, view, profile, nil, keys["demo-entry"]); err == nil {
		t.Fatal("unresolved management address reached the native receiver")
	}
	missing := wireGuardExecution{WireGuard: append([]wireGuardExecutionLink{}, profile.WireGuard...)}
	missing.WireGuard[0].Endpoint = "192.0.2.12:51822"
	missing.WireGuard[0].PeerPublicKey = "demo-missing-peer"
	if _, err := appendNativeReceivers(config, view, missing, nil, keys["demo-entry"]); err == nil {
		t.Fatal("resolved address without its authenticated peer was accepted")
	}
}
