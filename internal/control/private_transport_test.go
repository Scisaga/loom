package control

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type transportCA struct {
	certificate *x509.Certificate
	key         ed25519.PrivateKey
	file        string
}

func testTransportCA(t *testing.T, root string) transportCA {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Demo transport trust"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "demo-trust.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return transportCA{certificate: certificate, key: key, file: file}
}
func testTransportIdentity(t *testing.T, root, name string, serial int64, key crypto.Signer, ca transportCA, usages []x509.ExtKeyUsage) (TLSFiles, tls.Certificate, *x509.Certificate) {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"demo.example", "control.loom"}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.certificate.Raw})...)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificateFile := filepath.Join(root, name+"-certificate.pem")
	keyFile := filepath.Join(root, name+"-key.pem")
	if err := os.WriteFile(certificateFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return TLSFiles{CertificateFile: certificateFile, KeyFile: keyFile, TrustFile: ca.file}, pair, leaf
}
func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func testLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func TestPrivateMemberDeltaAndBrowserTLSUseCurrentAuthority(t *testing.T) {
	parent := t.TempDir()
	ca := testTransportCA(t, parent)
	keys := []ed25519.PrivateKey{testKey(t), testKey(t)}
	members := []Member{}
	configs := []NodeConfig{}
	for index, name := range []string{"demo-control-a", "demo-control-b"} {
		member := Member{ControlID: name, NodeID: "demo-node-" + string(rune('a'+index)), PublicKey: base64.RawURLEncoding.EncodeToString(keys[index].Public().(ed25519.PublicKey))}
		members = append(members, member)
		peer, _, _ := testTransportIdentity(t, parent, name, int64(10+index), keys[index], ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
		browser, _, _ := testTransportIdentity(t, parent, name+"-browser", int64(20+index), testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		configs = append(configs, NodeConfig{Schema: 3, NetworkID: "demo-network", ControlID: member.ControlID, NodeID: member.NodeID, SigningKeyFile: peer.KeyFile, PeerTLS: &peer, BrowserTLS: &browser})
	}
	_, adminPair, adminLeaf := testTransportIdentity(t, parent, "demo-admin", 30, testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	initial := ControlConfig{Schema: 3, NetworkID: "demo-network", Operation: "genesis", Members: members, SealedKeys: []ControlSealedKey{}}
	keyID, _ := KeyID(members[0].PublicKey)
	genesis, err := SignMaterial(Material{Schema: 3, NetworkID: "demo-network", IssuerControlID: members[0].ControlID, IssuerKeyID: keyID, Operation: "genesis", Payload: Genesis{ControlConfig: initial, NetworkIntent: EmptyNetworkIntent(), AdminCertificates: []AdminCertificate{{ID: "demo-admin", CertificateDER: base64.RawURLEncoding.EncodeToString(adminLeaf.Raw)}}}}, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	genesisID, _ := MaterialID(genesis)
	roots := []string{filepath.Join(parent, "demo-authority-a"), filepath.Join(parent, "demo-authority-b")}
	for index := range configs {
		configs[index].GenesisID = genesisID
		if _, err := InitializeAuthority(roots[index], configs[index], genesis); err != nil {
			t.Fatal(err)
		}
	}
	first, err := OpenPrivateChannel(PrivateChannelConfig{Schema: 3, Node: members[0].NodeID, Listen: []string{testLoopbackAddress(t)}, Peers: []PrivatePeer{}}, configs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenPrivateChannel(PrivateChannelConfig{Schema: 3, Node: members[1].NodeID, Listen: []string{testLoopbackAddress(t)}, Peers: []PrivatePeer{{Node: members[0].NodeID, Addresses: first.ListenAddresses()}}}, configs[1])
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	first.config.Peers = []PrivatePeer{{Node: members[1].NodeID, Addresses: second.ListenAddresses()}}
	runtimes := []*Runtime{}
	for index, channel := range []*PrivateChannel{first, second} {
		runtime, err := OpenRuntime(roots[index], channel)
		if err != nil {
			t.Fatal(err)
		}
		defer runtime.Close()
		runtimes = append(runtimes, runtime)
		server := &Server{Runtime: runtime, Channel: channel, Config: configs[index]}
		httpServer := &http.Server{Handler: server.Handler(), ConnContext: controlConnContext, ReadHeaderTimeout: time.Second}
		defer httpServer.Close()
		go httpServer.Serve(channel.ControlListener())
	}
	accepted := submitAuthority(t, runtimes[0], authorityService("demo-synced-service", "demo-member-write"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtimes[1].reconcilePeer(ctx, members[0]); err != nil {
		t.Fatal(err)
	}
	original, err := runtimes[0].Authority.Material(accepted.MaterialID)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := runtimes[1].Authority.Material(accepted.MaterialID)
	if err != nil || !bytes.Equal(original, copied) {
		t.Fatal("private delta changed the original signed fact")
	}
	if len(runtimes[1].Authority.Snapshot().NetworkIntent.Services) != 1 {
		t.Fatal("private member did not consume the signed fact")
	}
	t.Run("unresponsive relay does not block authenticated delta", func(t *testing.T) {
		files, _, _ := testTransportIdentity(t, parent, "relay-demo-relay", 51, testKey(t), ca,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
		identity := RelayIdentity{Schema: 3, Node: "demo-relay", TLS: files}
		relay := func(targetAddress string) *PrivateChannel {
			t.Helper()
			channel, err := OpenPrivateRelay(PrivateChannelConfig{Schema: 3, Node: identity.Node,
				Listen: []string{testLoopbackAddress(t)}, Peers: []PrivatePeer{{Node: members[0].NodeID, Addresses: []string{targetAddress}}}}, identity)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { channel.Close() })
			return channel
		}
		good := relay(first.ListenAddresses()[0])
		stallTLS, err := relayTLSConfig(identity)
		if err != nil {
			t.Fatal(err)
		}
		stalled, closed := testStalledPrivateRelay(t, stallTLS)
		root := filepath.Join(parent, "demo-authority-recovery")
		authority, err := InitializeAuthority(root, configs[1], genesis)
		if err != nil {
			t.Fatal(err)
		}
		channel := &PrivateChannel{peerTLS: second.peerTLS, config: PrivateChannelConfig{Schema: 3,
			Node: members[1].NodeID, Peers: []PrivatePeer{
				{Node: "demo-relay-a", Addresses: []string{stalled}},
				{Node: "demo-relay-b", Addresses: good.ListenAddresses()},
			}}}
		channel.AttachAuthority(authority)
		reports, err := OpenObservationStore(root)
		if err != nil {
			t.Fatal(err)
		}
		recovery := &Runtime{Config: configs[1], Authority: authority, Reports: reports, Channel: channel}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := recovery.reconcilePeer(ctx, members[0]); err != nil {
			t.Fatalf("available relay did not sync past stalled relay: %v", err)
		}
		reopened, err := OpenAuthority(root)
		if err != nil {
			t.Fatal(err)
		}
		copied, err := reopened.Material(accepted.MaterialID)
		if err != nil || !bytes.Equal(original, copied) || len(reopened.Snapshot().NetworkIntent.Services) != 1 {
			t.Fatal("relay delta did not persist the exact signed fact and projection")
		}
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("losing relay connection remained open")
		}

		t.Run("all routes stalled honor cancellation", func(t *testing.T) {
			address, closed := testStalledPrivateRelay(t, stallTLS)
			caller := &PrivateChannel{peerTLS: second.peerTLS, config: PrivateChannelConfig{
				Peers: []PrivatePeer{{Node: "demo-relay-a", Addresses: []string{address}}}}}
			caller.AttachAuthority(authority)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			finished := make(chan error, 1)
			go func() {
				connection, err := caller.dialMemberTLS(ctx, members[0].NodeID, controlALPN, controlRelayALPN, 100*time.Millisecond)
				if connection != nil {
					connection.Close()
				}
				finished <- err
			}()
			select {
			case err := <-finished:
				if err == nil || !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "i/o timeout") {
					t.Fatalf("stalled relay did not return a deadline error: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("relay status read escaped the connection timeout")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("timed-out relay connection remained open")
			}
			cancel()
			if _, err := caller.dialMemberTLS(ctx, members[0].NodeID, controlALPN, controlRelayALPN, time.Second); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled caller started another connection: %v", err)
			}
		})
		t.Run("relay cannot substitute another member", func(t *testing.T) {
			wrong := relay(second.ListenAddresses()[0])
			caller := &PrivateChannel{peerTLS: second.peerTLS, config: PrivateChannelConfig{
				Peers: []PrivatePeer{{Node: "demo-relay-a", Addresses: wrong.ListenAddresses()}}}}
			caller.AttachAuthority(authority)
			connection, err := caller.dialMemberTLS(context.Background(), members[0].NodeID, controlALPN, controlRelayALPN, time.Second)
			if connection != nil {
				connection.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "not the configured member") {
				t.Fatalf("relay target identity check was bypassed: %v", err)
			}
		})
	})

	pool := x509.NewCertPool()
	pool.AddCert(ca.certificate)
	request := func(pair *tls.Certificate, path string) int {
		config := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
		if pair != nil {
			config.Certificates = []tls.Certificate{*pair}
		}
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: config, Proxy: nil, DisableKeepAlives: true}}
		response, err := client.Get("https://" + first.ListenAddresses()[0] + path)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}
	if status := request(nil, "/"); status != http.StatusOK {
		t.Fatalf("ordinary entry page rejected: %d", status)
	}
	if status := request(nil, "/api/control/ui/snapshot"); status != http.StatusForbidden {
		t.Fatalf("missing admin leaf accessed authority: %d", status)
	}
	if status := request(&adminPair, "/api/control/ui/snapshot"); status != http.StatusOK {
		t.Fatalf("exact admin leaf rejected: %d", status)
	}

	_, foreign, _ := testTransportIdentity(t, parent, "demo-foreign", 40, testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	rogue := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{foreign}, MinVersion: tls.VersionTLS13, NextProtos: []string{controlALPN}}}}
	response, err := rogue.Get("https://" + first.ListenAddresses()[0] + "/internal/frontier")
	if err == nil {
		defer response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Fatal("transport CA alone granted member facts")
		}
	}
}

// The relay authenticates but never acknowledges its target. EOF proves the
// caller cancelled the socket, rather than merely abandoning a dial goroutine.
func testStalledPrivateRelay(t *testing.T, config *tls.Config) (string, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{}, 32)
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for connection := range connections {
			connection.Close()
		}
	})
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[raw] = true
			mu.Unlock()
			go func() {
				defer raw.Close()
				connection := tls.Server(raw, config)
				if connection.Handshake() == nil {
					var length uint16
					if binary.Read(connection, binary.BigEndian, &length) == nil {
						_, _ = io.CopyN(io.Discard, connection, int64(length))
						_, _ = io.Copy(io.Discard, connection)
					}
				}
				mu.Lock()
				delete(connections, raw)
				mu.Unlock()
				select {
				case closed <- struct{}{}:
				default:
				}
			}()
		}
	}()
	return listener.Addr().String(), closed
}

func TestLocalPeerTLSRejectsCertificateIdentityMismatch(t *testing.T) {
	root, config, _ := authorityFixture(t)
	parent := filepath.Dir(root)
	ca := testTransportCA(t, parent)
	peerRoot := filepath.Join(parent, "demo-peer-identity")
	if err := os.Mkdir(peerRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	peer, _, _ := testTransportIdentity(t, peerRoot, config.ControlID, 10, testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	config.PeerTLS = &peer
	if _, err := peerTLSConfig(config); err == nil {
		t.Fatal("peer TLS accepted a leaf with another identity key")
	}
}

func TestRelayIdentityUsesCurrentCanonicalReader(t *testing.T) {
	root := t.TempDir()
	ca := testTransportCA(t, root)
	files, _, _ := testTransportIdentity(t, root, "relay-demo-relay", 50, testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	value := RelayIdentity{Schema: 3, Node: "demo-relay", TLS: files}
	body, err := CanonicalEncode(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "identity.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := LoadRelayIdentity(root, []string{"127.0.0.1:18443"})
	if err != nil || identity.Node != value.Node {
		t.Fatalf("canonical relay identity: %v", err)
	}
	for _, rejected := range [][]byte{append(append([]byte{}, body...), '\n'), bytes.Replace(body, []byte(`"schema":3`), []byte(`"schema":2`), 1), bytes.Replace(body, []byte(`"node":`), []byte(`"unknown":false,"node":`), 1)} {
		if err := os.WriteFile(path, rejected, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRelayIdentity(root, []string{"127.0.0.1:18443"}); err == nil {
			t.Fatal("noncanonical or old relay identity accepted")
		}
	}
}
