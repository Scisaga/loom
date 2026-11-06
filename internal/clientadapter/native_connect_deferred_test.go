package clientadapter

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestNativeConnectDefersOnlyExplicitLocalPendingOrConflict(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusConflict, http.StatusBadGateway, http.StatusOK} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				request, err := http.ReadRequest(bufio.NewReader(server))
				if err == nil && (request.Method != http.MethodConnect || request.Header.Get("X-Loom-Target") != "tcp://demo.example:443") {
					err = errors.New("native request changed its exact target")
				}
				if err == nil {
					_, err = fmt.Fprintf(server, "HTTP/1.1 %d Test\r\nContent-Length: 0\r\n\r\n", status)
				}
				done <- err
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			diagnostic := nativeDiagnostic{secret: "demo-secret", dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
			connection, err := dialNativeConnect(ctx, diagnostic, "/loom/probe", "", "", "tcp", "demo.example:443")
			if status == http.StatusOK {
				if err != nil || connection == nil {
					t.Fatal("valid native tunnel failed", err)
				}
				connection.Close()
			} else if err == nil || errors.Is(err, ErrMeasurementDeferred) != (status == http.StatusServiceUnavailable || status == http.StatusConflict) {
				t.Fatal("local pending was recorded as a network failure or transport failure was hidden", status, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHTTPSPreservesNativeLocalPendingAndRealTransportFailure(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusConflict, http.StatusBadGateway} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				_, err := http.ReadRequest(bufio.NewReader(server))
				if err == nil {
					_, err = fmt.Fprintf(server, "HTTP/1.1 %d Test\r\nContent-Length: 0\r\n\r\n", status)
				}
				done <- err
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			diagnostic := nativeDiagnostic{secret: "demo-secret", dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
			result := probeHTTPS(ctx, "https://demo.example/health", &tls.Config{MinVersion: tls.VersionTLS12},
				func(ctx context.Context, network, target string) (net.Conn, error) {
					return dialNativeConnect(ctx, diagnostic, "/loom/probe", "", "", network, target)
				}, time.Now(), nil)
			if result.Available || result.Deferred != (status != http.StatusBadGateway) {
				t.Fatal("HTTPS turned local pending into a network failure or hid a transport failure", status, result.Deferred)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCancelledHTTPSIsDeferredWithoutStartingAnotherDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := probeHTTPS(ctx, "https://demo.example/health", &tls.Config{MinVersion: tls.VersionTLS12},
		func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("cancelled request started a dial")
			return nil, context.Canceled
		}, time.Now(), nil)
	if result.Available || !result.Deferred {
		t.Fatal("cancelled HTTPS was recorded as a network failure")
	}
}
