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
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
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

// Most tunnel fixtures record a complete response. Explicit Flush also supports
// actual streaming, so download deadline tests exercise bytes on the connection.
type deviceTunnelResponse struct {
	*httptest.ResponseRecorder
	connection net.Conn
	flushed    bool
	err        error
}

func (response *deviceTunnelResponse) Write(body []byte) (int, error) {
	if response.err != nil {
		return 0, response.err
	}
	if response.flushed {
		return response.connection.Write(body)
	}
	return response.ResponseRecorder.Write(body)
}

func (response *deviceTunnelResponse) Flush() {
	if response.flushed {
		return
	}
	response.flushed = true
	writer := bufio.NewWriter(response.connection)
	_, response.err = fmt.Fprintf(writer, "HTTP/1.1 %d %s\r\n", response.Code, http.StatusText(response.Code))
	response.Header().Set("Connection", "close")
	if response.err == nil {
		response.err = response.Header().Write(writer)
	}
	if response.err == nil {
		_, response.err = writer.WriteString("\r\n")
	}
	if response.err == nil {
		_, response.err = writer.Write(response.Body.Bytes())
	}
	if response.err == nil {
		response.err = writer.Flush()
	}
}

func testDeviceTunnel(t *testing.T, publicKey string, handlers ...http.HandlerFunc) (control.EndpointGeneration, string) {
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
				if len(handlers) == 0 {
					_, _ = io.Copy(connection, reader)
					return
				}
				request, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				defer request.Body.Close()
				response := &deviceTunnelResponse{ResponseRecorder: httptest.NewRecorder(), connection: connection}
				handlers[0](response, request)
				if response.flushed {
					return
				}
				result := response.Result()
				defer result.Body.Close()
				if result.Header.Get("Content-Length") == "" {
					result.ContentLength = int64(response.Body.Len())
				}
				result.Close = true
				_ = result.Write(connection)
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

func TestDeviceRequestBypassesFirstBlackHoleAndCompletesAuthenticatedBusiness(t *testing.T) {
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
	result, err := requestDevice(ctx, store, store.LKG(), 2, deviceRequestTimeout, func(_ context.Context, connection net.Conn) (string, error) {
		if _, err := connection.Write([]byte("demo-business")); err != nil {
			return "", err
		}
		body := make([]byte, len("demo-business"))
		_, err := io.ReadFull(connection, body)
		return string(body), err
	})
	if err != nil {
		t.Fatal("first black hole consumed the healthy member's budget", err)
	}
	if connection := losing.Load(); connection == nil || !connection.closed.Load() {
		t.Fatal("losing TLS handshake was not closed before returning")
	}
	if result != "demo-business" || store.LKG().ViewDigest != view.ViewDigest {
		t.Fatal("business did not complete or changed accepted authority")
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
