package deviceclient

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
)

type deviceTunnelChallenge struct {
	Schema int    `json:"schema"`
	Nonce  string `json:"nonce"`
}

func testDeviceTunnel(t *testing.T, publicKey string) (control.EndpointGeneration, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"demo.example"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	digest := func(body []byte) string { sum := sha256.Sum256(body); return "sha256:" + hex.EncodeToString(sum[:]) }
	endpoint := control.EndpointGeneration{ID: "demo-b", Generation: 1, OwnerControlID: "demo-control-b", Host: "192.0.2.2", Port: 443,
		ServerName: "demo.example", SPKISHA256: digest(parsed.RawSubjectPublicKeyInfo), CertificateDigest: digest(der), Modes: []string{"device"}, State: "serving"}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"loom-tunnel/3"}, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	var connections sync.Map
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Store(connection, true)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				defer connections.Delete(connection)
				reader := bufio.NewReader(connection)
				read := func(value any) error {
					var header [4]byte
					if _, err := io.ReadFull(reader, header[:]); err != nil {
						return err
					}
					size := binary.BigEndian.Uint32(header[:])
					if size == 0 || size > 8<<20 {
						return errors.New("invalid demo frame")
					}
					body := make([]byte, size)
					if _, err := io.ReadFull(reader, body); err != nil {
						return err
					}
					return control.DecodeCanonical(body, value, control.ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20})
				}
				write := func(value any) error {
					body, err := control.CanonicalEncode(value)
					if err != nil {
						return err
					}
					var header [4]byte
					binary.BigEndian.PutUint32(header[:], uint32(len(body)))
					if _, err := connection.Write(header[:]); err != nil {
						return err
					}
					_, err = connection.Write(body)
					return err
				}
				var hello control.TunnelHello
				if err := read(&hello); err != nil || hello.Mode != "device" {
					t.Log("demo tunnel hello rejected", err)
					return
				}
				challenge := deviceTunnelChallenge{3, base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
				if err := write(challenge); err != nil {
					t.Log("demo tunnel challenge failed", err)
					return
				}
				var proof control.TunnelProof
				if err := read(&proof); err != nil {
					t.Log("demo tunnel proof failed", err)
					return
				}
				message, err := control.CanonicalEncode(struct {
					Hello     control.TunnelHello   `json:"hello"`
					Challenge deviceTunnelChallenge `json:"challenge"`
				}{hello, challenge})
				key, _ := base64.RawURLEncoding.DecodeString(publicKey)
				signature, _ := base64.RawURLEncoding.DecodeString(proof.Signature)
				if err != nil || !ed25519.Verify(key, append([]byte("loom-device-tunnel-proof-v3\x00"), message...), signature) {
					t.Log("demo tunnel signature rejected", err)
					return
				}
				if write(struct {
					Schema int    `json:"schema"`
					Status string `json:"status"`
				}{3, "ready"}) != nil {
					return
				}
				_, _ = io.Copy(connection, reader)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-acceptDone
		connections.Range(func(key, _ any) bool { _ = key.(net.Conn).Close(); return true })
		workers.Wait()
	})
	return endpoint, listener.Addr().String()
}

func TestDeviceConnectionBypassesFirstBlackHoleAndPreservesAuthenticatedWinner(t *testing.T) {
	invite, makeView := schema3Fixture(t, "linux")
	store, err := OpenForPlatform(filepath.Join(t.TempDir(), "identity"), invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	healthy, address := testDeviceTunnel(t, store.PublicKey())
	blackHole := healthy
	blackHole.ID, blackHole.Host = "demo-a", "192.0.2.1"
	view := makeView(store.PublicKey(), 7, func(view *control.DeviceView) { view.Endpoints = []control.EndpointGeneration{blackHole, healthy} })
	if err := store.SaveLKG(view); err != nil {
		t.Fatal(err)
	}
	created := make(chan struct{})
	var losing atomic.Pointer[trackedDeviceConnection]
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx = control.WithEndpointDialer(ctx, func(ctx context.Context, _, target string) (net.Conn, error) {
		if strings.HasPrefix(target, "192.0.2.1:") {
			client, server := net.Pipe()
			connection := &trackedDeviceConnection{Conn: client}
			losing.Store(connection)
			close(created)
			go func() { defer server.Close(); _, _ = io.Copy(io.Discard, server) }()
			return connection, nil
		}
		select {
		case <-created:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	})
	connection, err := deviceConnection(ctx, store)
	if err != nil {
		t.Fatal("first black hole consumed the healthy member's budget", err)
	}
	defer connection.Close()
	if connection := losing.Load(); connection == nil || !connection.closed.Load() {
		t.Fatal("losing TLS handshake was not closed before returning")
	}
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err := connection.Write([]byte("demo-business")); err != nil {
		t.Fatal(err)
	}
	result := make([]byte, len("demo-business"))
	if _, err := io.ReadFull(connection, result); err != nil || string(result) != "demo-business" || store.LKG().ViewDigest != view.ViewDigest {
		t.Fatal("winner was closed by attempt cancellation or changed accepted authority", err)
	}
}

type trackedDeviceConnection struct {
	net.Conn
	closed atomic.Bool
}

func (connection *trackedDeviceConnection) Close() error {
	connection.closed.Store(true)
	return connection.Conn.Close()
}

func TestDeviceEndpointCancellationClosesLateSuccessAndBoundsConcurrency(t *testing.T) {
	endpoints := []control.EndpointGeneration{{ID: "demo-a"}, {ID: "demo-b"}, {ID: "demo-c"}}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 2)
	var active, maximum atomic.Int32
	var connections sync.Map
	returned := make(chan error, 1)
	go func() {
		_, err := connectDeviceEndpoints(ctx, endpoints, "demo-device", nil, func(ctx context.Context, _ control.EndpointGeneration, _ control.TunnelHello, _ ed25519.PrivateKey) (net.Conn, error) {
			count := active.Add(1)
			defer active.Add(-1)
			for prior := maximum.Load(); count > prior && !maximum.CompareAndSwap(prior, count); prior = maximum.Load() {
			}
			started <- struct{}{}
			<-ctx.Done()
			client, server := net.Pipe()
			server.Close()
			connection := &trackedDeviceConnection{Conn: client}
			connections.Store(connection, true)
			return connection, nil
		})
		returned <- err
	}()
	<-started
	<-started
	cancel()
	if err := <-returned; !errors.Is(err, context.Canceled) || active.Load() != 0 || maximum.Load() != 2 {
		t.Fatal("cancellation left attempts or exceeded its concurrency bound", err)
	}
	connections.Range(func(key, _ any) bool {
		if !key.(*trackedDeviceConnection).closed.Load() {
			t.Error("late successful connection was orphaned")
		}
		return true
	})
}
