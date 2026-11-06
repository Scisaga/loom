package clientadapter

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
)

type egressTLSCompletionConn struct {
	net.Conn
	reads                                    atomic.Int32
	entered, physicalClosed, release, exited chan struct{}
	enterOnce, closeOnce, exitOnce           sync.Once
}

func (c *egressTLSCompletionConn) Read(body []byte) (int, error) {
	count := c.reads.Add(1)
	if count > 1 {
		c.enterOnce.Do(func() { close(c.entered) })
	}
	n, err := c.Conn.Read(body)
	if count > 1 {
		<-c.release
		c.exitOnce.Do(func() { close(c.exited) })
	}
	return n, err
}

func (c *egressTLSCompletionConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.physicalClosed) })
	return err
}

func TestEgressCancellationJoinsTransportTLS(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	c := &egressTLSCompletionConn{Conn: local, entered: make(chan struct{}), physicalClosed: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(c.release) }) }
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, err := NativeDiagnosticContext(ctx, "demo-local-secret", func(context.Context, string, string) (net.Conn, error) { return c, nil })
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		reader := bufio.NewReader(remote)
		_, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		_, _ = io.WriteString(remote, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = io.Copy(io.Discard, reader)
	}()
	finished := make(chan struct{})
	go func() {
		_ = ProbeEgressBusiness(ctx, control.EgressProbe{Target: "https://demo.example/", SpecDigest: "sha256:" + strings.Repeat("a", 64), PublicInternet: true})
		close(finished)
	}()
	select {
	case <-c.entered:
	case <-time.After(time.Second):
		t.Fatal("TLS did not begin reading")
	}
	cancel()
	select {
	case <-c.physicalClosed:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close TLS socket")
	}
	select {
	case <-finished:
		select {
		case <-c.exited:
		default:
			t.Fatal("measurement returned before its TLS read exited")
		}
	case <-time.After(50 * time.Millisecond):
	}
	release()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("cancelled TLS measurement did not finish after its read exited")
	}
	select {
	case <-c.exited:
	default:
		t.Fatal("TLS read did not exit")
	}

}
