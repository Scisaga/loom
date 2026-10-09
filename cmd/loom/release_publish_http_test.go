package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReleaseDownloadProgressStallAndCancellation(t *testing.T) {
	for _, mode := range []string{"progress", "stall", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			idle := 200 * time.Millisecond
			finishHandler := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				if mode != "progress" {
					<-r.Context().Done()
					// Do not race the client's cancellation with a successfully
					// completed empty chunked response from this fixture.
					<-finishHandler
					return
				}
				for range 12 {
					select {
					case <-r.Context().Done():
						return
					case <-time.After(40 * time.Millisecond):
					}
					if _, err := io.WriteString(w, "demo"); err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
			}))
			defer server.Close()
			defer close(finishHandler)
			client := releasePublicHTTPClient(idle)
			defer client.CloseIdleConnections()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if mode == "cancel" {
				cancel()
			}
			started := time.Now()
			body, err := io.ReadAll(response.Body)
			switch mode {
			case "progress":
				if err != nil || string(body) != strings.Repeat("demo", 12) || time.Since(started) <= idle {
					t.Fatalf("progressing body was cut off: %d bytes, %v", len(body), err)
				}
			case "stall":
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() || ctx.Err() != nil {
					t.Fatalf("stalled body did not hit the inactivity deadline: %v", err)
				}
			case "cancel":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("body read ignored request cancellation: %v", err)
				}
			}
		})
	}
}
