//go:build linux

package clientv2

import (
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

func TestLinuxBootstrapCandidatesPreferHY2AndCurrentPreferred(t *testing.T) {
	now := time.Now().UTC()
	listener := func(generation int64, state string) wire.ListenerGenerationV2 {
		return wire.ListenerGenerationV2{
			Schema: 2, ListenerGeneration: generation, PublishedState: state,
			DialTargetFQDN: "bootstrap.example", PublicPort: 443,
			AddressFamilies: []string{"ipv4"}, TransportIdentityRefs: []string{
				"profile:webpki-v1", bootstrapTunnelTestHash(byte(generation)),
			},
			CredentialGeneration: generation, CertificateIdentityProjectionHash: bootstrapTunnelTestHash(0x30),
			PublicProfileGeneration: 1, IntroducedRevision: 1,
			ValidFrom: now.Add(-time.Hour).Format(time.RFC3339), ValidUntil: now.Add(time.Hour).Format(time.RFC3339),
			RotationOperationHash: bootstrapTunnelTestHash(0x31),
		}
	}
	catalog := &wire.BootstrapEndpointCatalogV1{BootstrapIngressSet: wire.BootstrapIngressEndpointSetV1{
		Endpoints: []wire.BootstrapIngressEndpointV1{
			{EndpointID: "hy2-b", Transport: "hysteria2", HintRank: 2,
				ListenerGenerations: []wire.ListenerGenerationV2{listener(1, "preferred")}},
			{EndpointID: "hy2-a", Transport: "hysteria2", HintRank: 1,
				ListenerGenerations: []wire.ListenerGenerationV2{listener(1, "advertised"), listener(2, "preferred")}},
			{EndpointID: "tcp-a", Transport: "trojan_tls", HintRank: 0,
				ListenerGenerations: []wire.ListenerGenerationV2{listener(1, "preferred")}},
		},
	}}
	candidates, err := linuxBootstrapCandidates(catalog, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []LinuxBootstrapSelection{
		{EndpointID: "hy2-a", Transport: "hysteria2", ListenerGeneration: 2},
		{EndpointID: "hy2-a", Transport: "hysteria2", ListenerGeneration: 1},
		{EndpointID: "hy2-b", Transport: "hysteria2", ListenerGeneration: 1},
		{EndpointID: "tcp-a", Transport: "trojan_tls", ListenerGeneration: 1},
	}
	if len(candidates) != len(want) {
		t.Fatalf("candidate count=%d want=%d", len(candidates), len(want))
	}
	for index := range want {
		if candidates[index].selection != want[index] {
			t.Fatalf("candidate[%d]=%#v want=%#v", index, candidates[index].selection, want[index])
		}
	}
}

func TestLinuxBootstrapProbeRunsOnceInParallelAndKeepsHY2Preference(t *testing.T) {
	candidates := []linuxBootstrapCandidate{
		{selection: LinuxBootstrapSelection{EndpointID: "hy2-b", Transport: "hysteria2", ListenerGeneration: 1}, hintRank: 2},
		{selection: LinuxBootstrapSelection{EndpointID: "tcp-a", Transport: "trojan_tls", ListenerGeneration: 1}},
		{selection: LinuxBootstrapSelection{EndpointID: "hy2-a", Transport: "hysteria2", ListenerGeneration: 1}, hintRank: 1},
	}
	started := make(chan struct{}, len(candidates))
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	var mu sync.Mutex
	calls := make(map[string]int)
	dialer := &LinuxBootstrapTunnelDialer{
		candidates: candidates, timeout: time.Second, probeTimeout: 500 * time.Millisecond,
		probeCandidate: func(ctx context.Context, candidate linuxBootstrapCandidate) error {
			mu.Lock()
			calls[candidate.selection.EndpointID]++
			mu.Unlock()
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			if candidate.selection.EndpointID == "hy2-b" {
				return errors.New("synthetic unreachable HY2")
			}
			return nil
		},
	}
	type probeOutcome struct {
		results []linuxBootstrapProbeResult
		err     error
	}
	done := make(chan probeOutcome, 1)
	go func() {
		results, err := dialer.probeCandidates(context.Background())
		done <- probeOutcome{results: results, err: err}
	}()
	for range candidates {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("Linux bootstrap transport probe 仍在串行等待候选")
		}
	}
	releaseOnce.Do(func() { close(release) })
	outcome := <-done
	if outcome.err != nil {
		t.Fatal(outcome.err)
	}
	if len(outcome.results) != 2 || outcome.results[0].candidate.selection.EndpointID != "hy2-a" ||
		outcome.results[1].candidate.selection.EndpointID != "tcp-a" {
		t.Fatalf("viable probe order=%#v", outcome.results)
	}
	if _, err := dialer.probeCandidates(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, candidate := range candidates {
		if calls[candidate.selection.EndpointID] != 1 {
			t.Fatalf("endpoint %q probe calls=%d", candidate.selection.EndpointID, calls[candidate.selection.EndpointID])
		}
	}
}

func TestLinuxTrojanBootstrapTunnelUsesPinnedTLSAndExactTuple(t *testing.T) {
	serverTLS, roots, pin := bootstrapTunnelTLSFixture(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	credential := "sha256:" + hex.EncodeToString(bytesOf(0x42, sha256.Size))
	destination := "10.30.0.1:7443"
	wantRequest, err := trojanBootstrapRequest(credential, destination)
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		header := make([]byte, len(wantRequest))
		if _, readErr := io.ReadFull(connection, header); readErr != nil {
			serverDone <- readErr
			return
		}
		if string(header) != string(wantRequest) {
			serverDone <- errors.New("Trojan header 未绑定 exact credential/destination")
			return
		}
		payload := make([]byte, 5)
		if _, readErr := io.ReadFull(connection, payload); readErr != nil || string(payload) != "hello" {
			serverDone <- errors.New("Trojan relay payload 无效")
			return
		}
		_, writeErr := connection.Write([]byte("world"))
		serverDone <- writeErr
	}()
	dialer := &LinuxBootstrapTunnelDialer{
		credential: credential, destination: destination, roots: roots, timeout: 3 * time.Second,
		tcpDial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "bootstrap.example:443" {
				return nil, errors.New("拨号目标不是 certified tuple")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		},
	}
	candidate := linuxBootstrapCandidate{serverName: "bootstrap.example", publicPort: 443, spkiPins: []string{pin}}
	connection, err := dialer.dialTrojan(context.Background(), candidate)
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
}

func TestLinuxHysteria2BootstrapTunnelInteroperatesWithWireProtocol(t *testing.T) {
	serverTLS, roots, pin := bootstrapTunnelTLSFixture(t)
	packetConnection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS = http3.ConfigureTLSConfig(serverTLS)
	listener, err := quic.Listen(packetConnection, serverTLS, &quic.Config{EnableDatagrams: false})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer packetConnection.Close()
	credential := "sha256:" + hex.EncodeToString(bytesOf(0x52, sha256.Size))
	destination := "10.30.0.1:7443"
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost || request.Host != linuxBootstrapHysteriaAuthHost ||
				request.URL.Path != linuxBootstrapHysteriaAuthPath ||
				request.Header.Get(linuxBootstrapHysteriaAuthHeader) != credential {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			writer.Header().Set("Hysteria-UDP", "false")
			writer.WriteHeader(linuxBootstrapHysteriaAuthOK)
		})
		server := &http3.Server{Handler: handler, EnableDatagrams: false,
			StreamHijacker: func(frameType http3.FrameType, _ quic.ConnectionTracingID,
				stream quic.Stream, frameErr error) (bool, error) {
				if frameErr != nil || uint64(frameType) != linuxBootstrapHysteriaTCPFrame {
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
					serverDone <- writeLinuxBootstrapFull(stream, response)
				}()
				return true, nil
			},
		}
		_ = server.ServeQUICConn(connection)
	}()
	dialer := &LinuxBootstrapTunnelDialer{
		credential: credential, destination: destination, roots: roots, timeout: 3 * time.Second,
		quicDial: func(ctx context.Context, address string, tlsConfig *tls.Config,
			config *quic.Config) (quic.Connection, error) {
			if address != "bootstrap.example:443" {
				return nil, errors.New("拨号目标不是 certified tuple")
			}
			if config.InitialPacketSize != linuxBootstrapQUICInitialPacket {
				return nil, errors.New("HY2 Initial packet 未约束到小 MTU 安全值")
			}
			return quic.DialAddr(ctx, packetConnection.LocalAddr().String(), tlsConfig, config)
		},
	}
	candidate := linuxBootstrapCandidate{serverName: "bootstrap.example", publicPort: 443, spkiPins: []string{pin}}
	connection, err := dialer.dialHysteria2(context.Background(), candidate)
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
}

func bootstrapTunnelTLSFixture(t *testing.T) (*tls.Config, *x509.CertPool, string) {
	t.Helper()
	now := time.Now().UTC()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "Loom bootstrap test root"},
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

func bootstrapTunnelTestHash(fill byte) string {
	return "sha256:" + hex.EncodeToString(bytesOf(fill, sha256.Size))
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
