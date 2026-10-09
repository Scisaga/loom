package clientadapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"loom/internal/netx"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

type socksProbeRequest struct {
	command byte
	target  string
}

type probeSOCKSOptions struct {
	wrongDNS      bool
	addresses     []netip.Addr
	rejectConnect string
	dropDNS       bool
}

func testProbeSOCKS(t *testing.T, httpsEndpoint string, options probeSOCKSOptions) (string, <-chan socksProbeRequest) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close(); udp.Close() })
	requests := make(chan socksProbeRequest, 32)
	if options.addresses == nil {
		options.addresses = []netip.Addr{netip.MustParseAddr("192.0.2.8")}
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				hello := make([]byte, 3)
				if _, err := io.ReadFull(connection, hello); err != nil || !bytes.Equal(hello, []byte{5, 1, 0}) {
					return
				}
				_, _ = connection.Write([]byte{5, 0})
				header := make([]byte, 3)
				if _, err := io.ReadFull(connection, header); err != nil {
					return
				}
				target, err := readSOCKSAddress(connection)
				if err != nil {
					return
				}
				requests <- socksProbeRequest{command: header[1], target: target}
				if header[1] == 3 {
					bound, _ := socksAddress(udp.LocalAddr().String())
					_, _ = connection.Write(append([]byte{5, 0, 0}, bound...))
					_, _ = io.Copy(io.Discard, connection)
					return
				}
				if header[1] != 1 {
					return
				}
				if target == options.rejectConnect {
					_, _ = connection.Write([]byte{5, 5, 0})
					return
				}
				upstream, err := net.DialTimeout("tcp", httpsEndpoint, time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				bound, _ := socksAddress(listener.Addr().String())
				_, _ = connection.Write(append([]byte{5, 0, 0}, bound...))
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, connection); close(copied) }()
				_, _ = io.Copy(connection, upstream)
				_ = connection.Close()
				<-copied
			}()
		}
	}()
	go func() {
		buffer := make([]byte, 2048)
		for {
			count, peer, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			if count < 4 || !bytes.Equal(buffer[:3], []byte{0, 0, 0}) {
				continue
			}
			reader := bytes.NewReader(buffer[3:count])
			target, err := readSOCKSAddress(reader)
			if err != nil {
				continue
			}
			requests <- socksProbeRequest{command: 0, target: target}
			if options.dropDNS {
				continue
			}
			query, _ := io.ReadAll(reader)
			if len(query) < 12 || !bytes.Contains(query, []byte("\x07example\x03com\x00")) {
				continue
			}
			binary.BigEndian.PutUint16(query[2:4], 0x8180)
			kind := binary.BigEndian.Uint16(query[len(query)-4:])
			answers := 0
			for _, address := range options.addresses {
				if kind == 1 && address.Is4() || kind == 28 && address.Is6() {
					data := address.AsSlice()
					query = append(query, 0xc0, 0x0c, 0, byte(kind), 0, 1, 0, 0, 0, 60, 0, byte(len(data)))
					query = append(query, data...)
					answers++
				}
			}
			binary.BigEndian.PutUint16(query[6:8], uint16(answers))
			if options.wrongDNS {
				target = "192.0.2.54:53"
			}
			address, _ := socksAddress(target)
			_, _ = udp.WriteTo(append(append([]byte{0, 0, 0}, address...), query...), peer)
		}
	}()
	return listener.Addr().String(), requests
}

func TestBusinessProbeCarriesDNSAndHTTPSOverLocalSOCKS(t *testing.T) {
	served := make(chan bool, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		served <- request.Host == "example.com" && request.URL.Path == "/demo-probe" && request.TLS.ServerName == "example.com"
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	proxy, requests := testProbeSOCKS(t, strings.TrimPrefix(server.URL, "https://"), probeSOCKSOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := probeDNS(ctx, proxy, "192.0.2.53", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	trust := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	if err := probeHTTPS(ctx, proxy, "https://example.com/demo-probe", addresses, trust); err != nil {
		t.Fatal(err)
	}
	for _, want := range []socksProbeRequest{{3, "0.0.0.0:0"}, {0, "192.0.2.53:53"}, {3, "0.0.0.0:0"}, {0, "192.0.2.53:53"}, {1, "192.0.2.8:443"}} {
		select {
		case got := <-requests:
			if got != want {
				t.Fatalf("proxy request = %+v, want %+v", got, want)
			}
		case <-ctx.Done():
			t.Fatal("expected probe did not enter the local proxy")
		}
	}
	if !<-served {
		t.Fatal("proxied HTTPS changed the certified target")
	}
}

func TestBusinessProbeRejectsWrongResolverAndHasNoDirectFallback(t *testing.T) {
	proxy, _ := testProbeSOCKS(t, "", probeSOCKSOptions{wrongDNS: true})
	probe, err := BusinessProbe(proxy, "192.0.2.53", "https://example.com/demo-probe")
	if err != nil {
		t.Fatal(err)
	}
	result := probe(context.Background())
	if result.Available || result.Action != "https_request" || !strings.Contains(result.Description, "differs from the certified resolver") {
		t.Fatalf("wrong-resolver outcome = %+v", result)
	}
	credentialed := (&url.URL{Scheme: "https", Host: "example.com", User: url.UserPassword("demo-user", "demo-password")}).String()
	for _, target := range []string{"", "http://example.com/", credentialed, "https://example.com/#fragment"} {
		if _, err := BusinessProbe(proxy, "192.0.2.53", target); err == nil {
			t.Fatal("invalid certified HTTPS target was accepted")
		}
	}
	if _, err := BusinessProbe("192.0.2.1:1080", "192.0.2.53", "https://example.com/"); err == nil {
		t.Fatal("non-local proxy was accepted")
	}
	if _, _, err := socksRequest(context.Background(), "invalid", 1, "example.com:443"); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("missing local SOCKS proxy did not fail closed")
	}
}

func TestBusinessProbeOrdersCertifiedAddressesAndPreservesTLSIdentityOnFallback(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.TLS.ServerName != "example.com" || request.Host != "example.com:8443" {
			t.Error("certified HTTPS identity changed")
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	first, second, ipv6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("2001:db8::8")
	proxy, requests := testProbeSOCKS(t, strings.TrimPrefix(server.URL, "https://"), probeSOCKSOptions{
		addresses: []netip.Addr{ipv6, second, first, second}, rejectConnect: "192.0.2.1:8443",
	})
	if _, err := BusinessProbe(proxy, "192.0.2.53", "https://example.com:8443/demo-probe"); err != nil {
		t.Fatalf("canonical non-default HTTPS port was rejected: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := probeDNS(ctx, proxy, "192.0.2.53", "example.com")
	if err != nil || !reflect.DeepEqual(addresses, []netip.Addr{first, second, ipv6}) {
		t.Fatalf("addresses = %v, %v", addresses, err)
	}
	trust := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	if err := probeHTTPS(ctx, proxy, "https://example.com:8443/demo-probe", addresses, trust); err != nil {
		t.Fatal(err)
	}
	var connects []string
	for range 6 {
		select {
		case request := <-requests:
			if request.command == 1 {
				connects = append(connects, request.target)
			}
		case <-ctx.Done():
			t.Fatal("missing address attempts")
		}
	}
	if !reflect.DeepEqual(connects, []string{"192.0.2.1:8443", "192.0.2.9:8443"}) {
		t.Fatalf("CONNECT addresses = %v", connects)
	}
	if err := probeHTTPS(ctx, proxy, "https://demo-invalid.example:8443/demo-probe", []netip.Addr{second}, trust); err == nil {
		t.Fatal("certified DNS address replaced HTTPS certificate identity")
	}
}

func TestBusinessDNSCancellationStopsPendingSOCKSIO(t *testing.T) {
	proxy, requests := testProbeSOCKS(t, "", probeSOCKSOptions{dropDNS: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := probeDNS(ctx, proxy, "192.0.2.53", "example.com"); done <- err }()
	for range 2 {
		select {
		case <-requests:
		case <-time.After(time.Second):
			t.Fatal("DNS did not enter SOCKS")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled DNS succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled DNS did not close pending I/O")
	}
}

func TestBusinessDNSAnswersRejectMismatchAndUnrelatedAddress(t *testing.T) {
	query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	answer := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(answer[2:4], 0x8180)
	binary.BigEndian.PutUint16(answer[6:8], 1)
	answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 8)
	if addresses, err := netx.DNSAnswers(query, answer, 1); err != nil || len(addresses) != 1 || addresses[0].String() != "192.0.2.8" {
		t.Fatalf("valid answer: %v %v", addresses, err)
	}
	for _, change := range []func([]byte) []byte{
		func(b []byte) []byte { b[0] ^= 1; return b },
		func(b []byte) []byte { b[2] |= 2; return b },
		func(b []byte) []byte { b[3] |= 3; return b },
		func(b []byte) []byte { b[13] = 'x'; return b },
		func(b []byte) []byte { b[len(query)+1] = byte(len(query)); return b },
		func(b []byte) []byte { return b[:len(b)-1] },
	} {
		if _, err := netx.DNSAnswers(query, change(append([]byte(nil), answer...)), 1); err == nil {
			t.Fatal("accepted invalid DNS response")
		}
	}
	unrelated := append([]byte(nil), answer[:len(query)]...)
	unrelated = append(unrelated, 5, 'o', 't', 'h', 'e', 'r', 0xc0, 0x14)
	unrelated = append(unrelated, answer[len(query)+2:]...)
	if addresses, err := netx.DNSAnswers(query, unrelated, 1); err != nil || len(addresses) != 0 {
		t.Fatalf("unrelated answer supplied target: %v %v", addresses, err)
	}
	cname := append([]byte(nil), answer[:len(query)]...)
	binary.BigEndian.PutUint16(cname[6:8], 2)
	cname = append(cname, 0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 8, 5, 'a', 'l', 'i', 'a', 's', 0xc0, 0x0c)
	cname = append(cname, 0xc0, byte(len(query)+12))
	cname = append(cname, answer[len(query)+2:]...)
	if addresses, err := netx.DNSAnswers(query, cname, 1); err != nil || len(addresses) != 1 || addresses[0].String() != "192.0.2.8" {
		t.Fatalf("certified CNAME answer = %v %v", addresses, err)
	}
}
