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

func TestEgressHTTPSRetainsRequestTLSAndResponseMeaning(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var requests atomic.Int32
			endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.RequestURI() != "/demo-path?q=raw%2Fvalue" || !strings.HasPrefix(r.Host, "example.com:") {
					t.Error("exit-local I/O changed the original HTTPS request")
				}
				w.Header().Set("Location", "https://redirect.example/never-follow")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, strings.Repeat("x", 8192))
			}))
			defer endpoint.Close()
			_, port, _ := net.SplitHostPort(endpoint.Listener.Addr().String())
			target := "https://example.com:" + port + "/demo-path?q=raw%2Fvalue"
			probe := control.EgressProbe{Target: target, SpecDigest: "sha256:" + strings.Repeat("a", 64), PublicInternet: true}
			var connects atomic.Int32
			var relays sync.WaitGroup
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				connects.Add(1)
				if r.Method != http.MethodConnect || r.URL.Path != "/loom/egress" || r.Header.Get("Authorization") != "Bearer demo-local-secret" || r.Header.Get("X-Loom-Target") != "tcp://example.com:"+port {
					t.Error("measurement escaped its authenticated local I/O or lost the original target")
					http.Error(w, "denied", http.StatusForbidden)
					return
				}
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
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			diagnostic, err := NativeDiagnosticContext(ctx, "demo-local-secret", func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != "127.0.0.1:61800" {
					t.Error("Go attempted physical target resolution or dialing")
				}
				return (&net.Dialer{}).DialContext(ctx, network, api.Listener.Addr().String())
			})
			if err != nil {
				t.Fatal(err)
			}
			trusted := endpoint.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			trusted.MinVersion = tls.VersionTLS12
			result := probeEgressBusiness(diagnostic, probe, trusted)
			if !result.Available || result.Action != "https_request" || result.Target != target || requests.Load() != 1 || connects.Load() != 1 {
				t.Fatal("exit request, first-4KiB or no-redirect meaning changed", result)
			}
			relays.Wait()
			result = probeEgressBusiness(diagnostic, probe, &tls.Config{MinVersion: tls.VersionTLS12})
			if result.Available {
				t.Fatal("untrusted business TLS was accepted")
			}
			relays.Wait()
		})
	}
}

func TestEgressConnectCancellationAndBufferedHandoff(t *testing.T) {
	t.Run("pending cancellation", func(t *testing.T) {
		entered, canceled := make(chan struct{}), make(chan struct{})
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(entered)
			<-r.Context().Done()
			close(canceled)
		}))
		defer api.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		d := nativeDiagnostic{secret: "demo-local-secret", dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, api.Listener.Addr().String())
		}}
		finished := make(chan error, 1)
		go func() { _, err := dialNativeEgress(ctx, d, "tcp", "demo.example:443"); finished <- err }()
		<-entered
		cancel()
		select {
		case err := <-finished:
			if err == nil {
				t.Fatal("canceled connect succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("pending connect did not close its own socket")
		}
		select {
		case <-canceled:
		case <-time.After(time.Second):
			t.Fatal("native connect request did not receive cancellation")
		}
	})
	t.Run("buffered handoff", func(t *testing.T) {
		done := make(chan struct{})
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			local, buffered, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				close(done)
				return
			}
			_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\ndemo-buffer")
			_ = buffered.Flush()
			local.Close()
			close(done)
		}))
		defer api.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		d := nativeDiagnostic{secret: "demo-local-secret", dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, api.Listener.Addr().String())
		}}
		conn, err := dialNativeEgress(ctx, d, "tcp", "demo.example:443")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		cancel() // A completed DialContext no longer owns the returned stream.
		body, err := io.ReadAll(conn)
		if err != nil || string(body) != "demo-buffer" {
			t.Fatal("CONNECT consumed buffered application bytes", err)
		}
		<-done
	})
}
