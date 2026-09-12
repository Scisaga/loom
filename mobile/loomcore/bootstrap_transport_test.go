package loomcore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	"loom/internal/wire"
)

type androidBootstrapNetworkFixture struct {
	mu        sync.Mutex
	addresses map[string]string
	protected int
	attempts  []int64
}

func (fixture *androidBootstrapNetworkFixture) ProtectAndBindSocket(_ int64) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.protected++
	return nil
}

func (fixture *androidBootstrapNetworkFixture) ResolveHost(host string) (string, error) {
	value, ok := fixture.addresses[host]
	if !ok {
		return "", errors.New("fixture host 未授权")
	}
	return value, nil
}

func (fixture *androidBootstrapNetworkFixture) RecordConnectionAttempt(_ string, attempt int64) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.attempts = append(fixture.attempts, attempt)
	return nil
}

func (fixture *androidBootstrapNetworkFixture) UnderlayIdentity() string {
	return "fixture-network-1"
}

func (fixture *androidBootstrapNetworkFixture) snapshot() (int, []int64) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.protected, append([]int64(nil), fixture.attempts...)
}

func TestAndroidBootstrapCapabilityUsesWireTCPValue(t *testing.T) {
	body := wire.BootstrapTunnelCapabilityBodyV1{
		Mode: "initial_claim", AllowedIngressSetHash: "ingress-1", AllowedInsideTransport: "tcp",
	}
	if err := validateAndroidBootstrapCapabilityMode(body, "initial_claim", "ingress-1"); err != nil {
		t.Fatalf("wire 规范的 tcp 被拒绝: %v", err)
	}
	body.AllowedInsideTransport = "tls_tcp"
	if err := validateAndroidBootstrapCapabilityMode(body, "initial_claim", "ingress-1"); err == nil {
		t.Fatal("wire schema 不存在的 tls_tcp 被接受")
	}
}

func TestAndroidBootstrapChallengeUsesDescriptorForActiveMode(t *testing.T) {
	initial := &AndroidV2BootstrapSession{inputs: androidEnrollmentInputsV2{
		descriptor: wire.InviteBootstrapDescriptorV2{EnrollmentServiceRef: wire.PrivateEnrollmentServiceRefV1{
			ServiceID: "initial-service",
		}},
	}}
	if got := initial.enrollmentServiceID(); got != "initial-service" {
		t.Fatalf("initial service=%q", got)
	}
	resume := &AndroidV2BootstrapSession{resume: &androidEnrollmentResumeInputsV1{
		descriptor: wire.EnrollmentResumeDescriptorV1{EnrollmentServiceRef: wire.PrivateEnrollmentServiceRefV1{
			ServiceID: "resume-service",
		}},
	}}
	if got := resume.enrollmentServiceID(); got != "resume-service" {
		t.Fatalf("resume service=%q", got)
	}
}

func TestAndroidTrojanProbeIsTokenFreeAndActualDialIsJournaled(t *testing.T) {
	serverTLS, roots, pin := androidBootstrapTLSFixture(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	credential := "sha256:" + hex.EncodeToString(androidBootstrapBytes(0x42, sha256.Size))
	destination := "10.30.0.1:7443"
	wantHeader, err := androidTrojanBootstrapRequest(credential, destination)
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		for attempt := 0; attempt < 2; attempt++ {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				serverDone <- acceptErr
				return
			}
			tlsConnection := connection.(*tls.Conn)
			if handshakeErr := tlsConnection.Handshake(); handshakeErr != nil {
				_ = connection.Close()
				serverDone <- handshakeErr
				return
			}
			if attempt == 0 {
				_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
				var probeByte [1]byte
				if count, readErr := connection.Read(probeByte[:]); count != 0 ||
					(readErr != io.EOF && !errors.Is(readErr, net.ErrClosed)) {
					_ = connection.Close()
					serverDone <- errors.New("token-free probe 在 TLS handshake 后发送了 bearer/payload")
					return
				}
				_ = connection.Close()
				continue
			}
			header := make([]byte, len(wantHeader))
			if _, readErr := io.ReadFull(connection, header); readErr != nil || !bytes.Equal(header, wantHeader) {
				_ = connection.Close()
				serverDone <- errors.New("Trojan header 未绑定 capability credential/exact tuple")
				return
			}
			payload := make([]byte, 5)
			if _, readErr := io.ReadFull(connection, payload); readErr != nil || string(payload) != "hello" {
				_ = connection.Close()
				serverDone <- errors.New("Trojan relay payload 无效")
				return
			}
			_, writeErr := connection.Write([]byte("world"))
			_ = connection.Close()
			serverDone <- writeErr
			return
		}
	}()

	network := &androidBootstrapNetworkFixture{addresses: map[string]string{"bootstrap.example": "127.0.0.1"}}
	now := time.Now().UTC()
	dialer := &androidBootstrapDialer{
		network: network, credential: credential, capabilityID: "capability-1", destination: destination,
		maximumAttempts: 3, maximumSession: time.Minute, maximumTotalBytes: 1 << 20,
		roots: roots, timeout: 3 * time.Second, notBefore: now.Add(-time.Hour), expiresAt: now.Add(time.Hour),
		candidates: []androidBootstrapCandidate{{
			endpointID: "trojan-a", transport: "trojan_tls", listenerGeneration: 1,
			serverName: "bootstrap.example", publicPort: int64(listener.Addr().(*net.TCPAddr).Port),
			addressFamilies: []string{"ipv4"}, spkiPins: []string{pin}, preferred: true,
		}},
	}
	dialer.trustedNow.Store(now.UnixNano())
	plan, err := dialer.probe(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	selection := plan.Selected
	if selection.Transport != "trojan_tls" || selection.EndpointID != "trojan-a" {
		t.Fatalf("probe selection=%+v", selection)
	}
	if protected, attempts := network.snapshot(); protected != 1 || len(attempts) != 0 {
		t.Fatalf("probe protect/attempt=%d/%v", protected, attempts)
	}
	connection, err := dialer.DialContext(context.Background(), "tcp", destination)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(connection, reply); err != nil || string(reply) != "world" {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if protected, attempts := network.snapshot(); protected != 2 || !equalAndroidAttempts(attempts, []int64{1}) {
		t.Fatalf("actual protect/attempt=%d/%v", protected, attempts)
	}
}

func TestAndroidHysteria2ProbeAndActualDialShareProtectedUnderlay(t *testing.T) {
	serverTLS, roots, pin := androidBootstrapTLSFixture(t)
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS = http3.ConfigureTLSConfig(serverTLS)
	listener, err := quic.Listen(packet, serverTLS, &quic.Config{EnableDatagrams: false})
	if err != nil {
		_ = packet.Close()
		t.Fatal(err)
	}
	defer listener.Close()
	defer packet.Close()
	credential := "sha256:" + hex.EncodeToString(androidBootstrapBytes(0x52, sha256.Size))
	destination := "10.30.0.1:7443"
	serverDone := make(chan error, 1)
	go func() {
		probeConnection, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		<-probeConnection.Context().Done()
		connection, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost || request.Host != androidBootstrapHysteriaAuthHost ||
				request.URL.Path != androidBootstrapHysteriaAuthPath ||
				request.Header.Get(androidBootstrapHysteriaAuthHeader) != credential {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			writer.Header().Set("Hysteria-UDP", "false")
			writer.WriteHeader(androidBootstrapHysteriaAuthOK)
		})
		server := &http3.Server{Handler: handler, EnableDatagrams: false,
			StreamHijacker: func(frameType http3.FrameType, _ quic.ConnectionTracingID,
				stream quic.Stream, frameErr error,
			) (bool, error) {
				if frameErr != nil || uint64(frameType) != androidBootstrapHysteriaTCPFrame {
					return false, nil
				}
				go func() {
					defer stream.Close()
					addressLength, readErr := quicvarint.Read(quicvarint.NewReader(stream))
					if readErr != nil || addressLength != uint64(len(destination)) {
						serverDone <- errors.New("Hysteria2 destination length 无效")
						return
					}
					address := make([]byte, addressLength)
					if _, readErr = io.ReadFull(stream, address); readErr != nil || string(address) != destination {
						serverDone <- errors.New("Hysteria2 destination 未绑定 exact tuple")
						return
					}
					padding, readErr := quicvarint.Read(quicvarint.NewReader(stream))
					if readErr != nil || padding != 0 {
						serverDone <- errors.New("Hysteria2 request padding 无效")
						return
					}
					payload := make([]byte, 5)
					if _, readErr = io.ReadFull(stream, payload); readErr != nil || string(payload) != "hello" {
						serverDone <- errors.New("Hysteria2 relay payload 无效")
						return
					}
					response := []byte{0}
					response = quicvarint.Append(response, 0)
					response = quicvarint.Append(response, 0)
					response = append(response, "world"...)
					serverDone <- androidBootstrapWriteFull(stream, response)
				}()
				return true, nil
			},
		}
		_ = server.ServeQUICConn(connection)
	}()

	network := &androidBootstrapNetworkFixture{addresses: map[string]string{"bootstrap.example": "127.0.0.1"}}
	now := time.Now().UTC()
	dialer := &androidBootstrapDialer{
		network: network, credential: credential, capabilityID: "capability-2", destination: destination,
		maximumAttempts: 3, maximumSession: time.Minute, maximumTotalBytes: 1 << 20,
		roots: roots, timeout: 3 * time.Second, notBefore: now.Add(-time.Hour), expiresAt: now.Add(time.Hour),
		candidates: []androidBootstrapCandidate{{
			endpointID: "hy2-a", transport: "hysteria2", listenerGeneration: 2,
			serverName: "bootstrap.example", publicPort: int64(packet.LocalAddr().(*net.UDPAddr).Port),
			addressFamilies: []string{"ipv4"}, spkiPins: []string{pin}, preferred: true,
		}},
	}
	dialer.trustedNow.Store(now.UnixNano())
	plan, err := dialer.probe(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	selection := plan.Selected
	if selection.Transport != "hysteria2" || selection.ListenerGeneration != 2 {
		t.Fatalf("probe selection=%+v", selection)
	}
	connection, err := dialer.DialContext(context.Background(), "tcp", destination)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(connection, reply); err != nil || string(reply) != "world" {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if protected, attempts := network.snapshot(); protected != 2 || !equalAndroidAttempts(attempts, []int64{1}) {
		t.Fatalf("HY2 protect/attempt=%d/%v", protected, attempts)
	}
}

func TestAndroidBootstrapResolverRejectsUnauthorizedAddressFamily(t *testing.T) {
	if _, err := androidBootstrapResolvedAddresses("2001:db8::1", []string{"ipv4"}); err == nil {
		t.Fatal("listener 未授权的 IPv6 address 被接受")
	}
	addresses, err := androidBootstrapResolvedAddresses("192.0.2.1\n192.0.2.1", []string{"ipv4"})
	if err != nil || len(addresses) != 1 || addresses[0].String() != "192.0.2.1" {
		t.Fatalf("canonical resolver 去重失败: %v %v", addresses, err)
	}
}

func TestAndroidBootstrapRestoresPersistedPlanWithoutReprobing(t *testing.T) {
	network := &androidBootstrapNetworkFixture{addresses: map[string]string{
		"hy2.example":    "192.0.2.10",
		"trojan.example": "192.0.2.20",
	}}
	now := time.Now().UTC()
	dialer := &androidBootstrapDialer{
		network: network, notBefore: now.Add(-time.Hour), expiresAt: now.Add(time.Hour),
		candidates: []androidBootstrapCandidate{
			{endpointID: "hy2-a", transport: "hysteria2", listenerGeneration: 2,
				serverName: "hy2.example", addressFamilies: []string{"ipv4"}},
			{endpointID: "trojan-a", transport: "trojan_tls", listenerGeneration: 1,
				serverName: "trojan.example", addressFamilies: []string{"ipv4"}},
		},
	}
	plan := androidBootstrapProbePlan{
		Schema: 1,
		Selected: androidBootstrapSelection{
			Schema: 1, EndpointID: "hy2-a", Transport: "hysteria2",
			ListenerGeneration: 2, ProbeRTTMillis: 9,
		},
		Viable: []androidBootstrapSelection{
			{Schema: 1, EndpointID: "hy2-a", Transport: "hysteria2", ListenerGeneration: 2, ProbeRTTMillis: 9},
			{Schema: 1, EndpointID: "trojan-a", Transport: "trojan_tls", ListenerGeneration: 1, ProbeRTTMillis: 4},
		},
	}
	if err := dialer.restoreProbe(plan, now); err != nil {
		t.Fatal(err)
	}
	restored, err := dialer.probe(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Selected != plan.Selected || len(restored.Viable) != len(plan.Viable) {
		t.Fatalf("restored plan=%+v", restored)
	}
	if protected, attempts := network.snapshot(); protected != 0 || len(attempts) != 0 {
		t.Fatalf("恢复 plan 不得执行 outer probe/attempt: %d/%v", protected, attempts)
	}
	changed := plan
	changed.Selected = changed.Viable[1]
	changed.Viable = append([]androidBootstrapSelection(nil), changed.Viable...)
	changed.Viable[0], changed.Viable[1] = changed.Viable[1], changed.Viable[0]
	if err := dialer.restoreProbe(changed, now); err == nil {
		t.Fatal("同一 session 接受了替换后的 persisted plan")
	}
}

func androidBootstrapTLSFixture(t *testing.T) (*tls.Config, *x509.CertPool, string) {
	t.Helper()
	now := time.Now().UTC()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "Android bootstrap test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject: pkix.Name{CommonName: "bootstrap.example"}, DNSNames: []string{"bootstrap.example"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, rootCertificate,
		&serverKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{serverDER, rootDER}, PrivateKey: serverKey}
	certificate.Leaf, _ = x509.ParseCertificate(serverDER)
	roots := x509.NewCertPool()
	roots.AddCert(rootCertificate)
	digest := sha256.Sum256(certificate.Leaf.RawSubjectPublicKeyInfo)
	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13},
		roots, "sha256:" + hex.EncodeToString(digest[:])
}

func androidBootstrapBytes(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func equalAndroidAttempts(left, right []int64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
