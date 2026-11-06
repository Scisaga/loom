package clientadapter

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
)

// The gate is below measurementConnection. While it is held, the socket Read
// has been unblocked by Close but quota.refund has definitely not run yet.
type egressHTTPHeaderReadConn struct {
	net.Conn
	armed         *atomic.Bool
	gate, release chan struct{}
	once          sync.Once
	claimed       int
	reading       atomic.Int32
	readStarted   chan struct{}
}

func (c *egressHTTPHeaderReadConn) Read(body []byte) (int, error) {
	c.reading.Add(1)
	defer c.reading.Add(-1)
	select {
	case c.readStarted <- struct{}{}:
	default:
	}
	n, err := c.Conn.Read(body)
	if err != nil && c.armed.Load() {
		c.once.Do(func() { c.claimed = len(body); close(c.gate) })
		<-c.release
	}
	return n, err
}

func TestEgressCancellationJoinsHTTPHeaderReadAndQuotaRefund(t *testing.T) {
	var armed atomic.Bool
	gotGET := make(chan struct{})
	endpoint := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		armed.Store(true)
		close(gotGET)
		<-r.Context().Done() // TLS and GET completed; no response headers.
	}))
	// No post-handshake ticket may satisfy a physical read after GET; the
	// in-flight read below must be waiting for the silent response headers.
	endpoint.TLS = &tls.Config{SessionTicketsDisabled: true}
	endpoint.StartTLS()
	defer endpoint.Close()
	var relays sync.WaitGroup
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote, err := net.Dial("tcp", endpoint.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		local, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			remote.Close()
			t.Error(err)
			return
		}
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffered.Flush()
		relays.Add(1)
		go func() {
			defer relays.Done()
			done := make(chan struct{})
			go func() { _, _ = io.Copy(remote, buffered); remote.Close(); close(done) }()
			_, _ = io.Copy(local, remote)
			local.Close()
			<-done
		}()
	}))
	defer api.Close()
	gate, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialed := make(chan *egressHTTPHeaderReadConn, 1)
	ctx, err := NativeDiagnosticContext(ctx, "demo-local-secret", func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := (&net.Dialer{}).DialContext(ctx, network, api.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		physical := &egressHTTPHeaderReadConn{Conn: connection, armed: &armed, gate: gate, release: release, readStarted: make(chan struct{}, 1)}
		dialed <- physical
		return physical, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	budget, err := NewMeasurementBudget(MeasurementLimits{Window: time.Minute, Requests: 2, Concurrent: 1, Bytes: 64 << 10, Timeout: 8 * time.Second}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(endpoint.Listener.Addr().String())
	probe := control.EgressProbe{Target: "https://example.com:" + port + "/demo", SpecDigest: "sha256:" + strings.Repeat("a", 64), PublicInternet: true}
	trusted := endpoint.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	trusted.MinVersion = tls.VersionTLS12
	quotaReady := make(chan *measurementSockets, 1)
	finished := make(chan struct{})
	go func() {
		_, _ = runMeasurementOn(ctx, budget, "demo-egress-header", 32<<10, func(pending context.Context) (ProbeResult, error) {
			quotaReady <- pending.Value(measurementSocketKey{}).(*measurementSockets)
			return probeEgressBusiness(pending, probe, trusted), nil
		})
		close(finished)
	}()
	select {
	case <-gotGET:
	case <-time.After(time.Second):
		t.Fatal("trusted TLS server did not receive GET")
	}
	physical, quota := <-dialed, <-quotaReady
	readDeadline := time.NewTimer(time.Second)
	defer readDeadline.Stop()
	// Receiving GET does not schedule the client's response reader. Establish
	// actual measurementConnection.Read ownership before testing its join.
	for physical.reading.Load() == 0 {
		select {
		case <-physical.readStarted:
		case <-readDeadline.C:
			t.Fatal("physical HTTP header read did not enter before cancellation")
		}
	}
	cancel()
	select {
	case <-gate:
	case <-time.After(time.Second):
		t.Fatal("Close did not release the actual HTTP header read")
	}
	quota.mu.Lock()
	before := quota.rx
	quota.mu.Unlock()
	claimed := physical.claimed
	early := false
	select {
	case <-finished:
		early = true
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("measurement did not finish after HTTP read gate released")
	}
	deadline := time.Now().Add(time.Second)
	refunded := false
	for time.Now().Before(deadline) {
		quota.mu.Lock()
		refunded = quota.rx >= before+int64(claimed)
		quota.mu.Unlock()
		if refunded {
			break
		}
		time.Sleep(time.Millisecond)
	}
	relays.Wait()
	if !refunded {
		t.Fatal("actual measurementConnection.Read did not refund its claimed RX after release")
	}
	if early {
		t.Fatal("measurement returned while its HTTP header measurementConnection.Read and quota refund were still in flight")
	}
}
