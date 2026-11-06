package deviceclient

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestReleaseReadIdleDeadlineRenewsAfterProgress(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	connection := &releaseIdleConnection{Conn: client, timeout: 50 * time.Millisecond}
	go func() { _, _ = server.Write([]byte("a")) }()
	var body [1]byte
	if _, err := connection.Read(body[:]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond) // The next read needs a fresh idle window.
	go func() { _, _ = server.Write([]byte("b")) }()
	if _, err := connection.Read(body[:]); err != nil || body[0] != 'b' {
		t.Fatal("progress inherited the previous read deadline", err)
	}
	if _, err := connection.Read(body[:]); err == nil {
		t.Fatal("stalled body read had no idle deadline")
	}
}

type releaseReadSignalConnection struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (connection *releaseReadSignalConnection) Read(body []byte) (int, error) {
	connection.once.Do(func() { close(connection.started) })
	return connection.Conn.Read(body)
}

func TestReleaseBodyDeadlineReplacesPendingHeaderRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	read := &releaseReadSignalConnection{Conn: client, started: make(chan struct{})}
	connection := &releaseIdleConnection{Conn: read, timeout: 50 * time.Millisecond, readTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() {
		var body [1]byte
		_, err := connection.Read(body[:])
		done <- err
	}()
	<-read.started // net/http can have this body read pending when headers return.
	if err := connection.setReadTimeout(50 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatal("pending body read did not use its idle deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending body read retained the header preparation deadline")
	}
}
