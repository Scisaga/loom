package enrollmenttransport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/bootstrapaccess"
	"loom/internal/wire"
)

func TestAuthenticatedIngressCarriesInnerTLSWithoutExposingClaim(t *testing.T) {
	now := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	capability, ingressHash := verifiedRelayCapability(t, now)
	serverCert, roots := relayTestCertificate(t, false)
	ingressCert, _ := relayTestCertificate(t, true)
	privateAddress := net.JoinHostPort(capability.Body().AllowedDestinationIP, "7444")
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := NewListener(&privateTestListener{Listener: raw, address: privateAddress},
		&tls.Config{Certificates: []tls.Certificate{serverCert}},
		func(_ context.Context, peer []byte, id string) (wire.VerifiedBootstrapCapabilityV1, error) {
			if !bytes.Equal(peer, ingressCert.Certificate[0]) || id != capability.CapabilityID() {
				return wire.VerifiedBootstrapCapabilityV1{}, errors.New("untrusted ingress")
			}
			return capability, nil
		}, time.Second, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requestBody := "demo-private-claim-material"
	received := make(chan bool, 1)
	server := &http.Server{ConnContext: BindConnection, Handler: Handler(func(w http.ResponseWriter, r *http.Request, got wire.VerifiedBootstrapCapabilityV1) {
		body, err := io.ReadAll(r.Body)
		received <- err == nil && string(body) == requestBody && got.CapabilityID() == capability.CapabilityID() && r.TLS != nil && r.TLS.HandshakeComplete
		_, _ = w.Write([]byte("completed"))
	})}
	defer server.Close()
	go func() {
		_ = server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13}))
	}()
	manager, err := bootstrapaccess.Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientSide, ingressSide := net.Pipe()
	defer clientSide.Close()
	dial := Dialer(func(_ context.Context, address string) (*tls.Config, error) {
		if address != privateAddress {
			return nil, errors.New("wrong tuple")
		}
		return &tls.Config{RootCAs: roots, ServerName: "relay.example", Certificates: []tls.Certificate{ingressCert}}, nil
	}, func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", raw.Addr().String())
	})
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- manager.RelayTCP(ctx, capability, "demo-session", ingressHash, "tcp", privateAddress, ingressSide, dial)
	}()
	inner := tls.Client(clientSide, &tls.Config{RootCAs: roots, ServerName: "relay.example", MinVersion: tls.VersionTLS13})
	if err := inner.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, "https://relay.example/v2/enrollment/claim", strings.NewReader(requestBody))
	request.Close = true
	transport := &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return inner, nil }}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "completed" || !<-received {
		t.Fatalf("private claim did not cross authenticated inner TLS: %v", err)
	}
	_ = inner.Close()
	select {
	case <-relayDone:
	case <-ctx.Done():
		t.Fatal("relay did not release connection")
	}
}

func TestRelayCannotBeOpenedWithoutVerifiedOuterSession(t *testing.T) {
	called := false
	dial := Dialer(func(context.Context, string) (*tls.Config, error) { called = true; return nil, nil }, nil)
	if _, err := dial(context.Background(), "tcp", "127.0.0.1:1"); err == nil || called {
		t.Fatal("anonymous dial reached private trust/dial boundary")
	}
	handler := Handler(func(http.ResponseWriter, *http.Request, wire.VerifiedBootstrapCapabilityV1) {
		t.Fatal("anonymous HTTP reached enrollment")
	})
	request := httptest.NewRequest(http.MethodPost, "https://relay.example/v2/enrollment/claim", nil)
	request.Header.Set("X-Capability-ID", wire.EmptyHashV1)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatal("header created verified connection context")
	}
}

func TestRelayListenerRejectsWrongIngressAndDoesNotBlockOtherHandshakes(t *testing.T) {
	certificate, roots := relayTestCertificate(t, false)
	ingress, _ := relayTestCertificate(t, true)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	verified := make(chan struct{}, 1)
	listener, err := NewListener(raw, &tls.Config{Certificates: []tls.Certificate{certificate}},
		func(context.Context, []byte, string) (wire.VerifiedBootstrapCapabilityV1, error) {
			verified <- struct{}{}
			return wire.VerifiedBootstrapCapabilityV1{}, errors.New("revoked ingress")
		}, time.Second, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	slow, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	client, err := tls.Dial("tcp", raw.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "relay.example", Certificates: []tls.Certificate{ingress}, NextProtos: []string{relayALPN}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	frame := append([]byte{0, byte(len(wire.EmptyHashV1))}, []byte(wire.EmptyHashV1)...)
	if err := writeAll(client, frame); err != nil {
		t.Fatal(err)
	}
	var response [1]byte
	if _, err := io.ReadFull(client, response[:]); err == nil {
		t.Fatal("revoked ingress obtained accepted tunnel")
	}
	select {
	case <-verified:
	case <-time.After(time.Second):
		t.Fatal("slow handshake blocked independent ingress")
	}
}

type privateTestAddr string

func (address privateTestAddr) Network() string { return "tcp" }
func (address privateTestAddr) String() string  { return string(address) }

type privateTestConn struct {
	net.Conn
	address string
}

func (connection *privateTestConn) LocalAddr() net.Addr { return privateTestAddr(connection.address) }

type privateTestListener struct {
	net.Listener
	address string
}

func (listener *privateTestListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &privateTestConn{Conn: connection, address: listener.address}, nil
}

func relayTestCertificate(t *testing.T, client bool) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.ExtKeyUsageServerAuth
	if client {
		usage = x509.ExtKeyUsageClientAuth
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-relay"}, DNSNames: []string{"relay.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, roots
}
