package bootstrapaccess

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestTrojanTLSServerRelaysCertifiedCapabilityToExactEnrollmentTuple(t *testing.T) {
	fixture := newTrojanServerFixture(t, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dialer 尚未安装")
	})
	outgoing, enrollment := net.Pipe()
	fixture.server.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp4" || address != "10.30.0.1:7444" {
			t.Errorf("Trojan relay 拨错 tuple=%s/%s", network, address)
		}
		return outgoing, nil
	}
	fixture.start(t)
	connection := fixture.connect(t, fixture.serverName)
	request := []byte("ping")
	if _, err := connection.Write(trojanRequest(fixture.credential, trojanCommandTCP,
		net.ParseIP("10.30.0.1"), 7444, request)); err != nil {
		t.Fatal(err)
	}
	gotRequest := make([]byte, len(request))
	if _, err := io.ReadFull(enrollment, gotRequest); err != nil || !bytes.Equal(gotRequest, request) {
		t.Fatalf("Enrollment 收到=%q err=%v", gotRequest, err)
	}
	response := []byte("pong!!")
	writeDone := make(chan error, 1)
	go func() {
		_, err := enrollment.Write(response)
		writeDone <- err
	}()
	gotResponse := make([]byte, len(response))
	if _, err := io.ReadFull(connection, gotResponse); err != nil || !bytes.Equal(gotResponse, response) {
		t.Fatalf("客户端收到=%q err=%v", gotResponse, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	_ = enrollment.Close()
	fixture.stop(t)
	usage := fixture.manager.SnapshotUsage()
	if len(usage) != 1 || usage[0].ConnectionAttempts != 1 ||
		usage[0].TransferredBytes != int64(len(request)+len(response)) {
		t.Fatalf("Trojan durable usage=%#v", usage)
	}
}

func TestTrojanTLSServerFailsClosedBeforeEnrollmentDial(t *testing.T) {
	tests := []struct {
		name        string
		credential  string
		command     byte
		address     net.IP
		port        uint16
		wantAttempt int64
	}{
		{name: "wrong credential", credential: "wrong", command: trojanCommandTCP, address: net.ParseIP("10.30.0.1"), port: 7444},
		{name: "udp command", command: 3, address: net.ParseIP("10.30.0.1"), port: 7444, wantAttempt: 1},
		{name: "wrong private port", command: trojanCommandTCP, address: net.ParseIP("10.30.0.1"), port: 22, wantAttempt: 1},
		{name: "wrong private ip", command: trojanCommandTCP, address: net.ParseIP("10.30.0.2"), port: 7444, wantAttempt: 1},
		{name: "public ip", command: trojanCommandTCP, address: net.ParseIP("192.0.2.10"), port: 7444, wantAttempt: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var dialCalls atomic.Int64
			fixture := newTrojanServerFixture(t, func(context.Context, string, string) (net.Conn, error) {
				dialCalls.Add(1)
				return nil, errors.New("不应拨号")
			})
			fixture.start(t)
			connection := fixture.connect(t, fixture.serverName)
			credential := test.credential
			if credential == "" {
				credential = fixture.credential
			}
			if _, err := connection.Write(trojanRequest(credential, test.command, test.address, test.port, nil)); err != nil {
				t.Fatal(err)
			}
			_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
			var response [1]byte
			if _, err := connection.Read(response[:]); err == nil {
				t.Fatal("被拒绝的 Trojan 请求仍保持连接")
			}
			_ = connection.Close()
			fixture.stop(t)
			if dialCalls.Load() != 0 {
				t.Fatalf("越权请求触发 Enrollment dial %d 次", dialCalls.Load())
			}
			usage := fixture.manager.SnapshotUsage()
			if test.wantAttempt == 0 {
				if len(usage) != 0 {
					t.Fatalf("未知 credential 产生 usage=%#v", usage)
				}
			} else if len(usage) != 1 || usage[0].ConnectionAttempts != test.wantAttempt {
				t.Fatalf("已认证畸形请求未消耗 attempt:%#v", usage)
			}
		})
	}
}

func TestTrojanTLSServerRequiresExactSNIAndTLS13(t *testing.T) {
	fixture := newTrojanServerFixture(t, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("不应拨号")
	})
	fixture.start(t)
	for _, serverName := range []string{"wrong.example", ""} {
		raw, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", fixture.listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		client := tls.Client(raw, &tls.Config{RootCAs: fixture.roots, ServerName: serverName,
			MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13})
		if err := client.Handshake(); err == nil {
			t.Fatalf("错误 SNI %q 完成 outer TLS", serverName)
		}
		_ = client.Close()
	}
	raw, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", fixture.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tls12 := tls.Client(raw, &tls.Config{RootCAs: fixture.roots, ServerName: fixture.serverName,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	if err := tls12.Handshake(); err == nil {
		t.Fatal("TLS 1.2 完成 Trojan outer handshake")
	}
	_ = tls12.Close()
	fixture.stop(t)
	if usage := fixture.manager.SnapshotUsage(); len(usage) != 0 {
		t.Fatalf("无 bearer 的 outer probe 产生 usage=%#v", usage)
	}
}

func TestNewTrojanTLSServerRejectsUncertifiedConfiguration(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	verified, ingressHash := verifiedCapability(t, instant)
	manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return instant })
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewCredentialRegistry(ingressHash, []wire.VerifiedBootstrapCapabilityV1{verified})
	if err != nil {
		t.Fatal(err)
	}
	_, certificate, _ := trojanCertificate(t, "bootstrap.example")
	_, wrongCertificate, _ := trojanCertificate(t, "other.example")
	base := TrojanTLSServerOptions{ServerName: "bootstrap.example", TLSConfig: certificate,
		HandshakeTimeout: 5 * time.Second, MaximumConcurrentConnections: 4,
		Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") }}
	invalid := []TrojanTLSServerOptions{
		{ServerName: "192.0.2.10", TLSConfig: base.TLSConfig, HandshakeTimeout: base.HandshakeTimeout,
			MaximumConcurrentConnections: base.MaximumConcurrentConnections, Dial: base.Dial},
		{ServerName: "Bootstrap.example", TLSConfig: base.TLSConfig, HandshakeTimeout: base.HandshakeTimeout,
			MaximumConcurrentConnections: base.MaximumConcurrentConnections, Dial: base.Dial},
		{ServerName: base.ServerName, TLSConfig: &tls.Config{}, HandshakeTimeout: base.HandshakeTimeout,
			MaximumConcurrentConnections: base.MaximumConcurrentConnections, Dial: base.Dial},
		{ServerName: base.ServerName, TLSConfig: wrongCertificate, HandshakeTimeout: base.HandshakeTimeout,
			MaximumConcurrentConnections: base.MaximumConcurrentConnections, Dial: base.Dial},
	}
	for index, options := range invalid {
		if _, err := NewTrojanTLSServer(manager, registry, options); err == nil {
			t.Fatalf("无效 Trojan/TLS 配置 #%d 被接受", index)
		}
	}
}

type trojanServerFixture struct {
	serverName  string
	credential  string
	manager     *Manager
	server      *TrojanTLSServer
	listener    net.Listener
	roots       *x509.CertPool
	certificate *x509.Certificate
	cancel      context.CancelFunc
	serveDone   chan error
}

func newTrojanServerFixture(t *testing.T, dial DialContext) *trojanServerFixture {
	t.Helper()
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	verified, ingressHash := verifiedCapability(t, instant)
	manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return instant })
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewCredentialRegistry(ingressHash, []wire.VerifiedBootstrapCapabilityV1{verified})
	if err != nil {
		t.Fatal(err)
	}
	serverName := "bootstrap.example"
	roots, tlsConfig, certificate := trojanCertificate(t, serverName)
	server, err := NewTrojanTLSServer(manager, registry, TrojanTLSServerOptions{
		ServerName: serverName, TLSConfig: tlsConfig, HandshakeTimeout: 5 * time.Second,
		MaximumConcurrentConnections: 8, Dial: dial, Random: cryptorand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return &trojanServerFixture{serverName: serverName, credential: verified.TransportCredential(),
		manager: manager, server: server, listener: listener, roots: roots, certificate: certificate}
}

func (fixture *trojanServerFixture) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	fixture.cancel = cancel
	fixture.serveDone = make(chan error, 1)
	go func() { fixture.serveDone <- fixture.server.Serve(ctx, fixture.listener) }()
}

func (fixture *trojanServerFixture) stop(t *testing.T) {
	t.Helper()
	fixture.cancel()
	if err := <-fixture.serveDone; err != nil {
		t.Fatal(err)
	}
}

func (fixture *trojanServerFixture) connect(t *testing.T, serverName string) *tls.Conn {
	t.Helper()
	raw, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", fixture.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	connection := tls.Client(raw, &tls.Config{RootCAs: fixture.roots, ServerName: serverName,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if err := connection.Handshake(); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	return connection
}

func trojanCertificate(t *testing.T, serverName string) (*x509.CertPool, *tls.Config, *x509.Certificate) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: serverName}, DNSNames: []string{serverName},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return roots, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}}}, parsed
}

func trojanRequest(credential string, command byte, address net.IP, port uint16, payload []byte) []byte {
	key := trojanCredentialKey(credential)
	result := append([]byte(nil), key[:]...)
	result = append(result, '\r', '\n', command)
	if ipv4 := address.To4(); ipv4 != nil {
		result = append(result, trojanAddressIPv4)
		result = append(result, ipv4...)
	} else {
		result = append(result, trojanAddressIPv6)
		result = append(result, net.ParseIP(address.String())...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	result = append(result, portBytes[:]...)
	result = append(result, '\r', '\n')
	return append(result, payload...)
}
