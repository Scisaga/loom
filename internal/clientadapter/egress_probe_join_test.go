package clientadapter

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"loom/internal/control"
)

// A gate after the physical read unblocks makes completion observable without
// allowing a transport-owned goroutine to disappear before the assertion.
type egressReadCompletionConn struct {
	net.Conn
	entered, physicalClosed, release, exited chan struct{}
	enterOnce, closeOnce, exitOnce           sync.Once
}

func (c *egressReadCompletionConn) Read(body []byte) (int, error) {
	c.enterOnce.Do(func() { close(c.entered) })
	n, err := c.Conn.Read(body)
	<-c.release
	c.exitOnce.Do(func() { close(c.exited) })
	return n, err
}

func (c *egressReadCompletionConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.physicalClosed) })
	return err
}

func TestEgressCancellationJoinsTransportOwnedConnect(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	c := &egressReadCompletionConn{Conn: local, entered: make(chan struct{}), physicalClosed: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(c.release) }) }
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, err := NativeDiagnosticContext(ctx, "demo-local-secret", func(context.Context, string, string) (net.Conn, error) { return c, nil })
	if err != nil {
		t.Fatal(err)
	}
	go func() { body := make([]byte, 4096); _, _ = remote.Read(body) }()
	finished := make(chan struct{})
	go func() {
		_ = ProbeEgressBusiness(ctx, control.EgressProbe{Target: "https://demo.example/", SpecDigest: "sha256:" + strings.Repeat("a", 64), PublicInternet: true})
		close(finished)
	}()
	select {
	case <-c.entered:
	case <-time.After(time.Second):
		t.Fatal("CONNECT did not begin reading")
	}
	cancel()
	select {
	case <-c.physicalClosed:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close physical socket")
	}
	select {
	case <-finished:
		select {
		case <-c.exited:
		default:
			t.Fatal("measurement returned before its CONNECT read exited")
		}
	case <-time.After(50 * time.Millisecond):
		// Cancellation must join the gated read before returning.
	}
	release()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("cancelled measurement did not finish after its read exited")
	}
}

func TestHTTPSCancellationClosesLateSuccessfulDialBeforeReturning(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	connection := &egressReadCompletionConn{Conn: local, physicalClosed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	go func() {
		_ = probeHTTPS(ctx, "https://demo.example/", &tls.Config{MinVersion: tls.VersionTLS12}, func(context.Context, string, string) (net.Conn, error) {
			close(entered)
			<-release
			return connection, nil
		}, time.Now(), nil)
		close(finished)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	cancel()
	select {
	case <-finished:
		t.Fatal("measurement returned while its dial was in flight")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("late successful dial was not joined")
	}
	select {
	case <-connection.physicalClosed:
	default:
		t.Fatal("late socket was not closed before return")
	}
}
