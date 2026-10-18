package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEndpointEdgeReleasesBackpressuredHalfClosedBackend(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	edge, err := OpenEndpointEdge("127.0.0.1:0", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { edge.Close() })
	client, err := net.Dial("tcp", edge.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
	backend, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	_ = backend.(*net.TCPConn).SetReadBuffer(1024)
	deadline := time.Now().Add(time.Second)
	var outgoing *net.TCPConn
	for outgoing == nil && time.Now().Before(deadline) {
		edge.mu.Lock()
		for connection := range edge.conns {
			if connection.RemoteAddr().String() == listener.Addr().String() {
				outgoing = connection.(*net.TCPConn)
			}
		}
		edge.mu.Unlock()
		if outgoing == nil {
			time.Sleep(time.Millisecond)
		}
	}
	if outgoing == nil {
		t.Fatal("edge did not establish its backend connection")
	}
	_ = outgoing.SetWriteBuffer(1024)
	_ = client.(*net.TCPConn).SetWriteBuffer(1024)
	var sent atomic.Int64
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		payload := make([]byte, 1024)
		for {
			n, err := client.Write(payload)
			sent.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { client.Close(); <-writeDone })
	for sent.Load() < 64<<10 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sent.Load() < 64<<10 {
		t.Fatal("client did not supply enough bytes to backpressure the unread backend")
	}
	// The backend ends its response but keeps its read side open and unread.
	// Closing only the incoming client cannot cancel an outgoing blocked write.
	if err := backend.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("backend EOF did not close the client response")
	} else if network, ok := err.(net.Error); ok && network.Timeout() {
		t.Fatal("backend EOF left the client response open", err)
	}
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		edge.mu.Lock()
		remaining := len(edge.conns)
		edge.mu.Unlock()
		if remaining == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("completed response retained backpressured edge connections")
}

func edgeTestHello(t *testing.T, protocols []string) []byte {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tls.Client(client, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "demo.example", NextProtos: protocols}).HandshakeContext(ctx)
	}()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	got, original, err := readEdgeClientHello(server)
	_ = server.Close()
	<-done
	if err != nil || !reflect.DeepEqual(got, protocols) {
		t.Fatal("ordinary TLS ClientHello was not preserved", got, err)
	}
	return original
}

func TestSharedEndpointEdgePreservesFragmentedHelloAndRejectsMalformedInput(t *testing.T) {
	original := edgeTestHello(t, []string{tunnelALPN})
	// Fragment the handshake header itself as well as the extension body.
	payload := original[5:]
	var fragmented []byte
	for len(payload) != 0 {
		size := min(7, len(payload))
		header := []byte{22, 3, 1, 0, 0}
		binary.BigEndian.PutUint16(header[3:], uint16(size))
		fragmented = append(fragmented, header...)
		fragmented = append(fragmented, payload[:size]...)
		payload = payload[size:]
	}
	protocols, retained, err := readEdgeClientHello(bytes.NewReader(fragmented))
	if err != nil || !reflect.DeepEqual(protocols, []string{tunnelALPN}) || !bytes.Equal(retained, fragmented) {
		t.Fatal("fragmented ClientHello bytes changed", err)
	}
	for _, bad := range [][]byte{
		[]byte("GET / HTTP/1.1\r\n"),
		{22, 3, 1, 0xff, 0xff},
		{22, 3, 1, 0, 4, 1, 0xff, 0xff, 0xff},
		original[:len(original)-1],
	} {
		if _, _, err := readEdgeClientHello(bytes.NewReader(bad)); err == nil {
			t.Fatal("malformed or oversized ClientHello was accepted")
		}
	}
}

func TestSharedEndpointEdgeRoutesTLSWithoutTerminatingOrChangingBytes(t *testing.T) {
	root := t.TempDir()
	ca := testTransportCA(t, root)
	_, certificate, _ := testTransportIdentity(t, root, "demo-edge-backend", 93, testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	roots := x509.NewCertPool()
	roots.AddCert(ca.certificate)
	var workers sync.WaitGroup
	backend := func(label string, protocols []string) string {
		t.Helper()
		listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: protocols})
		if err != nil {
			t.Fatal(err)
		}
		acceptDone := make(chan struct{})
		go func() {
			defer close(acceptDone)
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer connection.Close()
					_ = connection.SetDeadline(time.Now().Add(time.Second))
					request := make([]byte, 4)
					if _, err := io.ReadFull(connection, request); err == nil && string(request) == "demo" {
						_, _ = io.WriteString(connection, label)
					}
				}()
			}
		}()
		t.Cleanup(func() { listener.Close(); <-acceptDone; workers.Wait() })
		return listener.Addr().String()
	}
	device := backend("device", []string{tunnelALPN})
	website := backend("website", []string{"http/1.1"})
	member := backend("member", []string{controlALPN, controlRelayALPN})
	edge, err := OpenSharedEndpointEdge("127.0.0.1:0", device, website, member)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { edge.Close() })
	for _, test := range []struct {
		protocols []string
		want      string
	}{
		{[]string{tunnelALPN}, "device"},
		{[]string{controlALPN}, "member"},
		{[]string{controlRelayALPN}, "member"},
		{[]string{"http/1.1"}, "website"},
		{nil, "website"},
	} {
		connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", edge.listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "demo.example", NextProtos: test.protocols})
		if err != nil {
			t.Fatal("backend TLS did not authenticate through opaque edge", test.want, err)
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(connection, "demo")
		response := make([]byte, len(test.want))
		_, err = io.ReadFull(connection, response)
		connection.Close()
		if err != nil || string(response) != test.want {
			t.Fatal("TLS bytes reached the wrong backend", test.want, string(response), err)
		}
	}
	if connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", edge.listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "demo.example", NextProtos: []string{tunnelALPN, controlALPN}}); err == nil {
		connection.Close()
		t.Fatal("ambiguous private purposes were accepted")
	}
	// Close must interrupt a partial hello, not wait for its read deadline.
	partial, err := net.Dial("tcp", edge.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = partial.Write([]byte{22})
	done := make(chan error, 1)
	go func() { done <- edge.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("edge did not cancel its ClientHello read")
	}
	partial.Close()
}
