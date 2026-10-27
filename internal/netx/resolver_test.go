package netx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestResolverCanonicalValuesAndTransportIsolation(t *testing.T) {
	for _, value := range []string{"192.0.2.53", "2001:db8::53", "https://192.0.2.53/dns-query", "https://[2001:db8::53]:8443/dns-query"} {
		if _, err := ParseDNSResolver(value); err != nil {
			t.Fatal(value, err)
		}
	}
	for _, value := range []string{"https://demo.example/dns-query", "http://192.0.2.53/dns-query", "https://192.0.2.53", "https://192.0.2.53:443/dns-query", "https://192.0.2.53:0444/dns-query", "https://192.0.2.53/dns-query?", "https://192.0.2.53/dns-query#", "https://demo@192.0.2.53/dns-query", "https://192.0.2.53/a/../dns-query", "https://192.0.2.53/%64ns-query", "https://192.0.2.053/dns-query", "https://0.0.0.0/dns-query", "https://[::ffff:192.0.2.53]/dns-query", "192.0.2.53:53"} {
		if _, err := ParseDNSResolver(value); err == nil {
			t.Fatal("accepted noncanonical resolver", value)
		}
	}
	if ValidateDNSResolvers([]string{"192.0.2.53", "https://192.0.2.54/dns-query"}) == nil {
		t.Fatal("mixed encryption permits downgrade")
	}
}

func dohTestServer(t *testing.T, response func(http.ResponseWriter, *http.Request, []byte)) (*tls.Config, func(context.Context, string, string) (net.Conn, error)) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), IPAddresses: []net.IP{net.ParseIP("192.0.2.53")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil || r.Method != http.MethodPost || r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" || r.Header.Get("Accept") != "application/dns-message" {
			t.Error("nonstandard DoH request")
			w.WriteHeader(400)
			return
		}
		response(w, r, query)
	}))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}
	s.StartTLS()
	t.Cleanup(s.Close)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "192.0.2.53:443" && address != "192.0.2.54:443" {
			return nil, errors.New("unexpected DNS transport or endpoint")
		}
		return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
	}
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, dial
}

func TestDoHUsesProtectedDialerAndVerifiesResponseAndTLSIdentity(t *testing.T) {
	for _, mode := range []string{"success", "wrong-ip", "untrusted", "status", "type", "redirect", "oversized", "mismatched", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			tlsConfig, dial := dohTestServer(t, func(w http.ResponseWriter, r *http.Request, q []byte) {
				w.Header().Set("Content-Type", "application/dns-message")
				switch mode {
				case "status":
					w.WriteHeader(503)
					return
				case "type":
					w.Header().Set("Content-Type", "text/plain")
				case "redirect":
					w.Header().Set("Location", "https://demo.example/dns-query")
					w.WriteHeader(302)
					return
				case "oversized":
					_, _ = io.WriteString(w, strings.Repeat("x", 65536))
					return
				}
				answer := certifiedDNSTestAnswer(q, "192.0.2.8", "2001:db8::8")
				if mode == "mismatched" {
					answer[0] ^= 1
				}
				if mode == "truncated" {
					answer[2] |= 2
				}
				_, _ = w.Write(answer)
			})
			endpoint := "https://192.0.2.53/dns-query"
			if mode == "wrong-ip" {
				endpoint = "https://192.0.2.54/dns-query"
			}
			if mode == "untrusted" {
				tlsConfig = nil
			}
			var calls atomic.Int32
			protected := func(ctx context.Context, network, address string) (net.Conn, error) {
				calls.Add(1)
				return dial(ctx, network, address)
			}
			got, err := resolveCertifiedIPs(t.Context(), "demo-entry.example", []string{endpoint}, protected, tlsConfig)
			if mode == "success" {
				want := []netip.Addr{netip.MustParseAddr("192.0.2.8"), netip.MustParseAddr("2001:db8::8")}
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatal(got, err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid DoH result")
			}
			if calls.Load() == 0 {
				t.Fatal("bypassed supplied underlay dialer")
			}
		})
	}
}

func TestDoHFallbackAndCancellationNeverUsePlaintext(t *testing.T) {
	var block atomic.Bool
	tlsConfig, dial := dohTestServer(t, func(w http.ResponseWriter, r *http.Request, q []byte) {
		if block.Load() {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(certifiedDNSTestAnswer(q, "192.0.2.8"))
	})
	var active atomic.Int32
	protected := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			t.Error("DoH downgraded transport")
			return nil, errors.New("plaintext forbidden")
		}
		if address == "192.0.2.52:443" {
			return nil, errors.New("demo encrypted endpoint unavailable")
		}
		c, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		active.Add(1)
		return &certifiedDNSTestConnection{Conn: c, active: &active}, nil
	}
	values := []string{"https://192.0.2.52/dns-query", "https://192.0.2.53/dns-query"}
	if got, err := resolveCertifiedIPs(t.Context(), "demo-entry.example", values, protected, tlsConfig); err != nil || len(got) != 1 || active.Load() != 0 {
		t.Fatal(got, err, active.Load())
	}
	block.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
	defer cancel()
	_, err := resolveCertifiedIPs(ctx, "demo-entry.example", values, protected, tlsConfig)
	if err == nil || active.Load() != 0 {
		t.Fatal("unfinished or successful stalled DoH", err, active.Load())
	}
	ctx, cancel = context.WithCancel(t.Context())
	cancel()
	if _, err := resolveCertifiedIPs(ctx, "demo-entry.example", values, protected, tlsConfig); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
