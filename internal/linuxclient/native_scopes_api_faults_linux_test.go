package linuxclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"loom/internal/clientadapter"
)

// Only the temporary selector client for this Scope uses the gate. Resource
// GET is a shared API; this injects an API boundary failure into one owned
// operation, not a sender factory failure or RouteManager confirmation.
type nativeScopeAPIGate struct {
	selector  *clientadapter.HTTPSelector
	entered   chan struct{}
	release   chan struct{}
	forwarded chan int
	finished  chan struct{}
	mu        sync.Mutex
	events    []nativeScopeAPIGateEvent
	writeErr  error
}

type nativeScopeAPIGateEvent struct {
	Stage      string `json:"stage"`
	Scope      string `json:"scope"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Status     int    `json:"status,omitempty"`
	ElapsedNS  int64  `json:"elapsed_ns"`
	APIOnly    bool   `json:"api_boundary_injection"`
	RealNative bool   `json:"real_native_response"`
}

// mode is one of fail-resource-get, hold-resource-get, hold-selector-put.
// Every other request and every released PUT goes to the real native API.
func newNativeScopeAPIGate(t *testing.T, ctx context.Context, config, evidence, scope, mode string) *nativeScopeAPIGate {
	t.Helper()
	g := &nativeScopeAPIGate{entered: make(chan struct{}, 1), release: make(chan struct{}), forwarded: make(chan int, 1), finished: make(chan struct{})}
	started := time.Now()
	var err error
	record := func(stage, method, path string, status int, real bool) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.events = append(g.events, nativeScopeAPIGateEvent{Stage: stage, Scope: scope, Method: method, Path: path, Status: status, ElapsedNS: time.Since(started).Nanoseconds(), APIOnly: true, RealNative: real})
		if err := atomicJSON(filepath.Join(evidence, mode+"-"+url.PathEscape(scope)+"-gate.json"), g.events); err != nil && g.writeErr == nil {
			g.writeErr = err
		}
	}
	backend := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, clientadapter.SelectorReadbackLimit+1))
		if err != nil || len(body) > clientadapter.SelectorReadbackLimit {
			http.Error(w, "invalid test request", http.StatusBadRequest)
			return
		}
		matched := (mode == "fail-resource-get" || mode == "hold-resource-get") && r.Method == http.MethodGet && r.URL.Path == "/loom/resources" || mode == "hold-selector-put" && r.Method == http.MethodPut && r.URL.Path == "/proxies/"+scope
		if matched {
			record("complete-request-held", r.Method, r.URL.Path, 0, false)
			once.Do(func() { g.entered <- struct{}{} })
			if mode == "fail-resource-get" {
				record("injected-resource-get-failure", r.Method, r.URL.Path, http.StatusServiceUnavailable, false)
				http.Error(w, "test resource GET unavailable", http.StatusServiceUnavailable)
				close(g.finished)
				return
			}
			if mode == "hold-resource-get" {
				select {
				case <-r.Context().Done():
					record("owned-request-cancelled", r.Method, r.URL.Path, 0, false)
				case <-ctx.Done():
					record("test-owner-stopped", r.Method, r.URL.Path, 0, false)
				}
				close(g.finished)
				return
			}
			// The caller's cancellation deliberately does not cancel this
			// already accepted request. Its release occurs only after the new
			// real CAS and readback; the native backend must generate the 409.
			select {
			case <-g.release:
				record("late-request-released-to-native", r.Method, r.URL.Path, 0, false)
			case <-ctx.Done():
				close(g.finished)
				return
			}
		}
		pending := r.Context()
		if matched && mode == "hold-selector-put" {
			pending = ctx
		}
		forward := r.Clone(pending)
		forward.URL = &url.URL{Scheme: "http", Host: "127.0.0.1:61800", Path: r.URL.Path, RawQuery: r.URL.RawQuery}
		forward.RequestURI = ""
		forward.Body = io.NopCloser(bytes.NewReader(body))
		response, err := backend.RoundTrip(forward)
		if err != nil {
			record("native-forward-error", r.Method, r.URL.Path, 0, false)
			if matched {
				g.forwarded <- 0
				close(g.finished)
			}
			http.Error(w, "test native forwarding failed", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		record("native-response", r.Method, r.URL.Path, response.StatusCode, true)
		if matched {
			g.forwarded <- response.StatusCode
			defer close(g.finished)
		}
		for key, values := range response.Header {
			w.Header()[key] = values
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	t.Cleanup(func() {
		server.Close()
		backend.CloseIdleConnections()
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.writeErr != nil {
			t.Error("API gate evidence was not persisted", g.writeErr)
		}
	})
	g.selector, err = clientadapter.NewHTTPSelector(config)
	if err != nil {
		t.Fatal(err)
	}
	address := server.Listener.Addr().String()
	g.selector.SetDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	return g
}

func waitNativeScopeGate(t *testing.T, ctx context.Context, event <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-event:
	case <-ctx.Done():
		t.Fatal(fmt.Sprint("API gate did not reach ", label))
	}
}
