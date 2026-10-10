package clientadapter

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"loom/internal/control"
)

func TestNativeDNSRoundTripExcludesConnectionAndRequiresMatchingResponse(t *testing.T) {
	public := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	resource := control.TransportResource{ID: "demo-wg", Kind: "wireguard", OwnerNodeID: "demo-node", ListenerID: "demo-wg", DialHost: "192.0.2.1", DialPort: 12345, Authentication: control.ResourceAuthentication{PublicKey: &public, LocalAddresses: new([]string{})}}
	pool, err := control.WireGuardTargetPrefix("demo-network", resource)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "wrong-response", "cancel"} {
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
					hello, err := read(2)
					if err != nil {
						return err
					}
					if _, err = read(int(hello[1])); err != nil {
						return err
					}
					if _, err = server.Write([]byte{5, 2}); err != nil {
						return err
					}
					auth, err := read(2)
					if err != nil {
						return err
					}
					user, err := read(int(auth[1]))
					if err != nil {
						return err
					}
					length, err := read(1)
					if err != nil {
						return err
					}
					password, err := read(int(length[0]))
					if err != nil {
						return err
					}
					if string(user) != resource.ID || string(password) != "demo-secret" {
						return errors.New("wrong execution identity")
					}
					if _, err = server.Write([]byte{1, 0}); err != nil {
						return err
					}
					if _, err = read(3); err != nil {
						return err
					}
					target, err := readSOCKSAddress(server)
					if err != nil {
						return err
					}
					address, _ := control.WireGuardAccessAddress(resource, "")
					if target != net.JoinHostPort(address.String(), "53") {
						return errors.New("probe escaped native DNS target")
					}
					time.Sleep(connectDelay)
					if _, err = server.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
						return err
					}
					length, err = read(2)
					if err != nil {
						return err
					}
					body, err := read(int(binary.BigEndian.Uint16(length)))
					if err != nil {
						return err
					}
					if mode == "cancel" {
						cancel()
						return nil
					}
					var query dnsmessage.Message
					if err := query.Unpack(body); err != nil {
						return err
					}
					query.Header.Response = true
					if mode == "wrong-response" {
						query.Header.ID++
					}
					query.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AAAAResource{AAAA: pool.Addr().Next().As16()}}}
					body, err = query.Pack()
					if err != nil {
						return err
					}
					binary.BigEndian.PutUint16(length, uint16(len(body)))
					time.Sleep(responseDelay)
					_, err = server.Write(append(length, body...))
					return err
				}()
			}()
			diagnostic, err := NativeDiagnosticContext(ctx, "demo-secret", func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != NativeProbeAddress {
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
				if err != nil || roundTrip < responseDelay || complete-roundTrip < connectDelay {
					t.Fatalf("connection or response timing mixed: complete=%s roundTrip=%s err=%v", complete, roundTrip, err)
				}
			} else if err == nil || roundTrip != 0 {
				t.Fatal("failed or cancelled response produced RTT", roundTrip, err)
			}
		})
	}
	if value, err := ProbeWireGuard(context.Background(), "demo-network", resource); err == nil || value != 0 {
		t.Fatal("missing native execution produced RTT")
	}
}
