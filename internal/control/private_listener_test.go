package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestLocalAdministrationSurvivesUnavailablePrivateTransport(t *testing.T) {
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	private := PrivateChannelConfig{Schema: 3, Node: config.NodeID, Listen: []string{testLoopbackAddress(t)}, Peers: []PrivatePeer{{Node: "demo-peer", Addresses: []string{"demo.example:443"}}}}
	runtime, err := openRuntime(root, func(node NodeConfig) (*PrivateChannel, error) {
		return openPrivateChannel(private, node, func(string, string) (net.Listener, error) { return nil, syscall.EADDRNOTAVAIL }, time.Millisecond*10)
	})
	if err != nil {
		t.Fatal("unavailable network inputs blocked authority", err)
	}
	defer runtime.Close()
	defer runtime.Channel.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(root, "admin.sock")
	server := &Server{Runtime: runtime, Channel: runtime.Channel, Config: runtime.Config, AdminSocket: path}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	deadline := time.Now().Add(3 * time.Second)
	for {
		response, err := client.Get("http://localhost/api/control/ui/snapshot")
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("local administration did not become available", err)
		}
		time.Sleep(time.Millisecond * 10)
	}
	body, err := EncodeOperation(authorityService("demo-local-repair", "demo-local-repair-create"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Post("http://localhost/api/control/operations", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("local repair write failed", response.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenAuthority(root)
	if err != nil || len(reopened.Snapshot().NetworkIntent.Services) != 1 {
		t.Fatal("ordinary local write did not survive reopen", err)
	}
}

func TestPrivateListenerRecoveryAndPurposeIsolation(t *testing.T) {
	for _, unavailable := range []string{"browser", "member"} {
		t.Run(unavailable, func(t *testing.T) {
			root, config, genesis := authorityFixture(t)
			ca := testTransportCA(t, filepath.Dir(root))
			key, err := config.PrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			peer, peerPair, _ := testTransportIdentity(t, filepath.Dir(root), config.ControlID, 10, key, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
			browser, _, _ := testTransportIdentity(t, filepath.Dir(root), "demo-browser", 11, testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
			config.PeerTLS, config.BrowserTLS = &peer, &browser
			if unavailable == "browser" {
				config.BrowserTLS = &TLSFiles{CertificateFile: filepath.Join(filepath.Dir(root), "demo-missing-certificate.pem"), KeyFile: browser.KeyFile, TrustFile: browser.TrustFile}
			} else {
				config.PeerTLS = nil
			}
			authority, err := InitializeAuthority(root, config, genesis)
			if err != nil {
				t.Fatal(err)
			}
			available, recovering := testLoopbackAddress(t), testLoopbackAddress(t)
			addresses := []string{available, recovering}
			sort.Strings(addresses)
			var restored atomic.Bool
			channel, err := openPrivateChannel(PrivateChannelConfig{Schema: 3, Node: config.NodeID, Listen: addresses, Peers: []PrivatePeer{}}, config,
				func(network, address string) (net.Listener, error) {
					if address == recovering && !restored.Load() {
						return nil, syscall.EADDRNOTAVAIL
					}
					return net.Listen(network, address)
				}, 10*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			defer channel.Close()
			channel.AttachAuthority(authority)
			roots := x509.NewCertPool()
			roots.AddCert(ca.certificate)
			dial := func(address string, member bool) (*tls.Conn, error) {
				config := &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}
				if member {
					config.NextProtos = []string{controlALPN}
					config.Certificates = []tls.Certificate{peerPair}
				}
				return tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, config)
			}
			member := unavailable == "browser"
			connection, err := dial(available, member)
			if err != nil {
				t.Fatal("another purpose/address became unavailable", err)
			}
			connection.Close()
			if denied, err := dial(available, !member); err == nil {
				denied.Close()
				t.Fatal("unavailable TLS purpose fell back to another identity")
			}
			restored.Store(true)
			deadline := time.Now().Add(time.Second)
			for {
				connection, err := dial(recovering, member)
				if err == nil {
					connection.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("listener did not recover after its address returned", err)
				}
				time.Sleep(time.Millisecond * 10)
			}
			// A peer that sends no ClientHello must not hold shutdown open.
			slow, err := net.Dial("tcp", available)
			if err != nil {
				t.Fatal(err)
			}
			defer slow.Close()
			closed := make(chan error, 1)
			go func() { closed <- channel.Close() }()
			select {
			case err := <-closed:
				if err != nil && !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("private transport shutdown retained an accepted connection")
			}
			for _, address := range addresses {
				listener, err := net.Listen("tcp", address)
				if err != nil {
					t.Fatal("shutdown retained an owned listener", err)
				}
				listener.Close()
			}
		})
	}
}

func TestPrivatePeerUnderlayAddressValidation(t *testing.T) {
	linkLocal := make(net.IP, net.IPv6len)
	linkLocal[0], linkLocal[1], linkLocal[15] = 0xfe, 0x80, 1
	for _, address := range []string{"192.0.2.1:443", "[2001:db8::1]:443", "10.0.0.1:443", "127.0.0.1:443", "demo.example:443"} {
		config := PrivateChannelConfig{Schema: 3, Node: "demo-local", Listen: []string{"127.0.0.1:443"}, Peers: []PrivatePeer{{Node: "demo-peer", Addresses: []string{address}}}}
		if err := config.Validate(); err != nil {
			t.Fatal("canonical unicast peer input rejected", address, err)
		}
		if address == "192.0.2.1:443" || address == "[2001:db8::1]:443" || address == "demo.example:443" {
			config.Listen = []string{address}
			if config.Validate() == nil {
				t.Fatal("public address became an allowed listener")
			}
		}
		config.Listen = []string{"127.0.0.1:443"}
		body, err := CanonicalEncode(config)
		var roundtrip PrivateChannelConfig
		if err != nil || DecodeCanonical(body, &roundtrip, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 16, MaxItems: 1024}) != nil {
			t.Fatal("private inputs did not retain canonical roundtrip", err)
		}
		encoded, err := CanonicalEncode(roundtrip)
		if err != nil || !bytes.Equal(body, encoded) {
			t.Fatal("private input bytes changed after canonical roundtrip", err)
		}
	}
	for _, address := range []string{"0.0.0.0:443", "[::]:443", net.JoinHostPort(net.IPv4(224, 0, 0, 1).String(), "443"), net.JoinHostPort(net.IPv6linklocalallnodes.String(), "443"), net.JoinHostPort(linkLocal.String()+"%demo-zone", "443"), "[2001:0db8::1]:443", "192.0.2.1:0443", "Demo.example:443", "demo.example.:443", "[demo.example]:443", "192.00.2.1:443", "demo_example:443", "[::ffff:192.0.2.1]:443", "192.0.2.1:0"} {
		config := PrivateChannelConfig{Schema: 3, Node: "demo-local", Listen: []string{"127.0.0.1:443"}, Peers: []PrivatePeer{{Node: "demo-peer", Addresses: []string{address}}}}
		if config.Validate() == nil {
			t.Fatal("noncanonical or non-unicast peer input accepted", address)
		}
	}
}
