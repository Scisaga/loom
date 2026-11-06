package clientadapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"loom/internal/control"
	"loom/protocol"
)

func TestNativeEchoExcludesConnectionAndRequiresMatchingResponse(t *testing.T) {
	public := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	resource := control.TransportResource{ID: "demo-wg", Kind: "wireguard", OwnerNodeID: "demo-node", ListenerID: "demo-wg", DialHost: "192.0.2.1", DialPort: 12345, Authentication: control.ResourceAuthentication{PublicKey: &public, LocalAddresses: new([]string{})}}

	for _, mode := range []string{"success", "wrong-response", "cancel", "metric-unknown"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			finished := make(chan error, 1)
			const connectDelay = 150 * time.Millisecond
			const responseDelay = 20 * time.Millisecond
			go func() {
				finished <- func() error {
					defer server.Close()
					_ = server.SetDeadline(time.Now().Add(3 * time.Second))
					read := func(n int) ([]byte, error) {
						body := make([]byte, n)
						_, err := io.ReadFull(server, body)
						return body, err
					}
					connect, err := http.ReadRequest(bufio.NewReader(server))
					if err != nil {
						return err
					}
					address, _ := control.WireGuardAccessAddress(resource, "")
					key, _ := protocol.ConnectionTargetKey("tcp", address.String(), 53)
					if connect.Method != http.MethodConnect || connect.URL.Path != "/loom/probe" || connect.Header.Get("Authorization") != "Bearer demo-secret" || connect.Header.Get("X-Loom-Target") != key || connect.Header.Get("X-Loom-Scope") != "" {
						return errors.New("probe escaped exact authenticated execution target")
					}
					time.Sleep(connectDelay)
					if _, err = io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
						return err
					}
					preface, err := read(len(protocol.WireGuardPreface))
					if err != nil || !bytes.Equal(preface, []byte(protocol.WireGuardPreface)) {
						return errors.New("missing native WG frame")
					}
					body, err := protocol.ReadFrame(server, 1024)
					if err != nil {
						return err
					}
					request, err := protocol.UnmarshalRequest(body, 1)
					if err != nil || request.Operation != protocol.TransportEcho {
						return errors.New("wrong transport echo")
					}
					if mode == "cancel" {
						cancel()
						return nil
					}
					response := protocol.Response{Nonce: request.Nonce, Status: protocol.Accepted}
					if mode == "wrong-response" {
						response.Nonce[0] ^= 1
					}
					if mode == "metric-unknown" {
						response.ProcessingNanos = ^uint64(0)
					}
					raw, err := response.Marshal()
					if err != nil {
						return err
					}
					time.Sleep(responseDelay)
					return protocol.WriteFrame(server, raw)

				}()
			}()
			diagnostic, err := NativeDiagnosticContext(ctx, "demo-secret", func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != "127.0.0.1:61800" {
					return nil, errors.New("wrong local execution entry")
				}
				return client, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			roundTrip, err := ProbeWireGuard(diagnostic, "demo-network", resource)
			complete := time.Since(started)
			if serverErr := <-finished; serverErr != nil {
				t.Fatal(serverErr)
			}
			if mode == "success" {
				if err != nil || roundTrip == nil || *roundTrip < responseDelay || complete-*roundTrip < connectDelay {
					t.Fatalf("connection or response timing mixed: complete=%s roundTrip=%s err=%v", complete, roundTrip, err)
				}
			} else if mode == "metric-unknown" {
				if err != nil || roundTrip != nil {
					t.Fatal("incomparable processing time became a failure or zero RTT", err)
				}
			} else if err == nil || roundTrip != nil {
				t.Fatal("failed or cancelled response produced RTT", roundTrip, err)
			}
		})
	}
	if value, err := ProbeWireGuard(context.Background(), "demo-network", resource); err == nil || value != nil {
		t.Fatal("missing native execution produced RTT")
	}
}

func TestWGAdmissionInflightReuseCannotBorrowAnotherPolicyOrSpecification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	budget, _ := NewMeasurementBudget(MeasurementLimits{Window: time.Minute, Requests: 8, Concurrent: 3, Bytes: 64 << 10, Timeout: 3 * time.Second}, time.Now)
	ctx = WithMeasurementBudget(ctx, budget)
	entered, release := make(chan string, 3), make(chan struct{})
	servers := make(chan error, 3)
	diagnostic, err := NativeDiagnosticContext(ctx, "demo-secret", func(_ context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			servers <- func() error {
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(4 * time.Second))
				read := func(n int) ([]byte, error) {
					body := make([]byte, n)
					_, err := io.ReadFull(server, body)
					return body, err
				}
				connect, err := http.ReadRequest(bufio.NewReader(server))
				if err != nil {
					return err
				}
				if connect.Method != http.MethodConnect || connect.URL.Path != "/loom/probe" || connect.Header.Get("Authorization") != "Bearer demo-secret" {
					return errors.New("diagnostic did not authenticate its local socket")
				}
				if _, err := io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
					return err
				}
				prefix, err := read(len(protocol.WireGuardPreface))
				if err != nil || string(prefix) != protocol.WireGuardPreface {
					return errors.New("missing native admission frame")
				}
				body, err := protocol.ReadFrame(server, 1024)
				if err != nil {
					return err
				}
				request, err := protocol.UnmarshalRequest(body, 1)
				if err != nil || request.Operation != protocol.AdmissionEcho {
					return errors.New("wrong admission operation")
				}
				entered <- request.PolicyID
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
				status := protocol.Accepted
				if request.PolicyID == "demo-policy-b" {
					status = protocol.Denied
				}
				response, err := (protocol.Response{Nonce: request.Nonce, Status: status}).Marshal()
				if err != nil {
					return err
				}
				return protocol.WriteFrame(server, response)
			}()
		}()
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	resource := control.TransportResource{ID: "demo-wg", Kind: "wireguard", OwnerNodeID: "demo-node", ListenerID: "demo-wg", DialHost: "192.0.2.1", DialPort: 12345, Authentication: control.ResourceAuthentication{PublicKey: &public, LocalAddresses: new([]string{})}}
	done := make(chan error, 3)
	for i, policy := range []string{"demo-policy-a", "demo-policy-a", "demo-policy-b"} {
		go func() {
			probe := control.ResourceProbe{NetworkID: "demo-network", Resource: resource, DiagnosticID: "entry:demo-source", PolicyID: policy, SpecDigest: "sha256:" + strings.Repeat(string(rune('a'+i)), 64)}
			_, err := ProbeWireGuardAdmission(diagnostic, probe)
			if policy == "demo-policy-b" {
				if err == nil {
					err = errors.New("denied Policy borrowed another admission success")
				} else {
					err = nil
				}
			}
			done <- err
		}()
	}
	counts := map[string]int{}
	for range 3 {
		select {
		case policy := <-entered:
			counts[policy]++
		case <-ctx.Done():
			t.Fatal("different actual measurement specifications coalesced")
		}
	}
	close(release)
	for range 3 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := <-servers; err != nil {
			t.Fatal("real diagnostic exchange failed", err)
		}
	}
	if counts["demo-policy-a"] != 2 || counts["demo-policy-b"] != 1 {
		t.Fatal("native admission lost the Policy or specification boundary")
	}
}
