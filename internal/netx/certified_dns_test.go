package netx

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestCertifiedDNSUsesOnlySuppliedUnderlayAndHandlesTruncation(t *testing.T) {
	var transports []string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "192.0.2.53:53" {
			return nil, errors.New("unexpected resolver")
		}
		transports = append(transports, network)
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			query := make([]byte, 512)
			if network == "tcp" {
				var length [2]byte
				if _, err := io.ReadFull(server, length[:]); err != nil {
					return
				}
				query = make([]byte, binary.BigEndian.Uint16(length[:]))
				if _, err := io.ReadFull(server, query); err != nil {
					return
				}
			} else {
				n, err := server.Read(query)
				if err != nil {
					return
				}
				query = query[:n]
			}
			answer := append([]byte(nil), query...)
			binary.BigEndian.PutUint16(answer[2:4], 0x8180)
			kind := binary.BigEndian.Uint16(query[len(query)-4:])
			if kind == 1 && network == "udp" {
				binary.BigEndian.PutUint16(answer[2:4], 0x8380)
			}
			if kind == 1 && network == "tcp" {
				binary.BigEndian.PutUint16(answer[6:8], 1)
				answer = append(answer, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 8)
			}
			if network == "tcp" {
				framed := make([]byte, 2)
				binary.BigEndian.PutUint16(framed, uint16(len(answer)))
				answer = append(framed, answer...)
			}
			_, _ = server.Write(answer)
		}()
		return client, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	addresses, err := ResolveCertifiedIPs(ctx, "demo-entry.example", []string{"192.0.2.53"}, dial)
	if err != nil || !reflect.DeepEqual(addresses, []netip.Addr{netip.MustParseAddr("192.0.2.8")}) || !reflect.DeepEqual(transports, []string{"udp", "tcp", "udp"}) {
		t.Fatalf("DNS exchange: %v %v %v", addresses, transports, err)
	}
}

func TestCertifiedDNSNeverFallsBackToHostResolution(t *testing.T) {
	calls := 0
	dial := func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("demo resolver unavailable")
	}
	for _, servers := range [][]string{nil, {"demo-resolver.example"}, {"192.0.2.53"}} {
		if _, err := ResolveCertifiedIPs(context.Background(), "localhost", servers, dial); err == nil {
			t.Fatal("used host-local resolution")
		}
	}
	if calls != 2 {
		t.Fatalf("unexpected resolver attempts: %d", calls)
	}
	addresses, err := ResolveCertifiedIPs(context.Background(), "192.0.2.8", nil, dial)
	if err != nil || len(addresses) != 1 || calls != 2 {
		t.Fatal("literal needed DNS")
	}
}
