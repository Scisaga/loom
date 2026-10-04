package control

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestEndpointEdgeForwardsOpaqueBytes(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		connection, err := target.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(connection, connection)
	}()
	edge, err := OpenEndpointEdge("127.0.0.1:0", target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer edge.Close()
	connection, err := net.DialTimeout("tcp", edge.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	payload := []byte("demo opaque TLS bytes")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("edge changed opaque transport bytes")
	}
}
func TestEndpointEdgeRejectsPublicTarget(t *testing.T) {
	if edge, err := OpenEndpointEdge("127.0.0.1:0", "192.0.2.10:443"); err == nil {
		edge.Close()
		t.Fatal("edge accepted a public control target")
	}
}

func TestEndpointEdgeCloseDrainsEstablishedConnections(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := target.Accept()
		if err == nil {
			accepted <- connection
		}
	}()
	edge, err := OpenEndpointEdge("127.0.0.1:0", target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer edge.Close()
	incoming, err := net.DialTimeout("tcp", edge.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer incoming.Close()
	var outgoing net.Conn
	select {
	case outgoing = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("edge did not connect to the explicit target")
	}
	defer outgoing.Close()
	closed := make(chan error, 1)
	go func() { closed <- edge.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("edge shutdown left a forwarder running")
	}
	assertEndpointConnectionClosed(t, incoming)
	assertEndpointConnectionClosed(t, outgoing)
	edge.mu.Lock()
	remaining := len(edge.conns)
	edge.mu.Unlock()
	if remaining != 0 {
		t.Fatal("edge shutdown retained owned connection handles")
	}
	if err := edge.Close(); err != nil {
		t.Fatal("repeated shutdown changed the result:", err)
	}
}
