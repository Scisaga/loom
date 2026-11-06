package clientadapter

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/protocol"
)

type countedNativeConn struct {
	net.Conn
	rx, tx *atomic.Int64
}

func (c countedNativeConn) Read(body []byte) (int, error) {
	n, err := c.Conn.Read(body)
	c.rx.Add(int64(n))
	return n, err
}
func (c countedNativeConn) Write(body []byte) (int, error) {
	n, err := c.Conn.Write(body)
	c.tx.Add(int64(n))
	return n, err
}

// This measures the real authenticated loopback read path without starting a
// dataplane, changing host networking or manufacturing probe activity.
func BenchmarkBoundNativeReadback(b *testing.B) {
	at, routes, _ := engineEvidence()
	id := routes[0].ID
	selection := clientmodel.Selection{Scope: "access", PolicyID: "demo-policy", CandidateID: id, Revision: "demo-revision", Targets: map[string]string{}, Choices: map[string]protocol.RouteChoice{id: {EntryNodeID: "demo-exit", FirstResourceID: "demo-fast", FinalExit: "demo-exit"}}}
	snapshot, _ := json.Marshal(map[string]any{"now": selection.CandidateID, "policy_id": selection.PolicyID, "revision": selection.Revision, "targets": selection.Targets, "choices": selection.Choices})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer demo-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/proxies/access":
			_, _ = w.Write(snapshot)
		case "/loom/tcp-observations":
			_, _ = w.Write([]byte(`{"observations":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	selector, err := NewHTTPSelector(`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-secret"}}}`)
	if err != nil {
		b.Fatal(err)
	}
	defer selector.client.CloseIdleConnections()
	var rx, tx atomic.Int64
	selector.SetDialer(func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return countedNativeConn{conn, &rx, &tx}, nil
	})
	memory := clientmodel.SelectionMemory{PolicyID: "demo-policy", NetworkGeneration: "demo-network", NativeBinding: &clientmodel.NativeBinding{Revision: selection.Revision, NetworkGeneration: "demo-network", ExecutionSpec: "demo-spec"}}
	state := State{Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-network", NativeExecutionSpec: "demo-spec", SelectionMemory: map[string]clientmodel.SelectionMemory{"access": memory}}
	var before, after syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &before)
	b.ResetTimer()
	for range b.N {
		_, changed, err := RefreshNativeObservations(context.Background(), selector, routes, state, func() time.Time { return at })
		if err != nil || changed {
			b.Fatal("unchanged local read recomputed routing", err)
		}
	}
	b.StopTimer()
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &after)
	cpu := func(v syscall.Rusage) time.Duration {
		return time.Duration(v.Utime.Sec+v.Stime.Sec)*time.Second + time.Duration(v.Utime.Usec+v.Stime.Usec)*time.Microsecond
	}
	b.ReportMetric(float64(rx.Load()+tx.Load())/float64(b.N), "loopback-B/op")
	b.ReportMetric(float64(cpu(after)-cpu(before))/float64(b.N), "cpu-ns/op")
}

func TestNativeQuickReadAcceptsEventCompletedDuringLoopbackIO(t *testing.T) {
	_, routes, _ := engineEvidence()
	id := routes[0].ID
	selection := clientmodel.Selection{Scope: "access", PolicyID: "demo-policy", CandidateID: id, Revision: "demo-revision", Targets: map[string]string{}, Choices: map[string]protocol.RouteChoice{id: {EntryNodeID: "demo-exit", FirstResourceID: "demo-fast", FinalExit: "demo-exit"}}}
	snapshot, _ := json.Marshal(map[string]any{"now": selection.CandidateID, "policy_id": selection.PolicyID, "revision": selection.Revision, "targets": selection.Targets, "choices": selection.Choices})
	var completed atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer demo-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/proxies/access" {
			_, _ = w.Write(snapshot)
			return
		}
		if r.URL.Path != "/loom/tcp-observations" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// The business attempt really completes while the read is in flight.
		time.Sleep(5 * time.Millisecond)
		at := time.Now().UTC().Truncate(time.Millisecond)
		completed.Store(at.UnixMilli())
		body := nativeBody(t, selection.Revision, selection.PolicyID, id, "available", at.Add(-time.Millisecond), at)
		_, _ = w.Write(body)
	}))
	defer server.Close()
	selector, err := NewHTTPSelector(`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-secret"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	defer selector.client.CloseIdleConnections()
	selector.SetDialer(func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	})
	memory := clientmodel.SelectionMemory{PolicyID: selection.PolicyID, NetworkGeneration: "demo-network", NativeBinding: &clientmodel.NativeBinding{Revision: selection.Revision, NetworkGeneration: "demo-network", ExecutionSpec: "demo-spec"}, Decisions: map[string]clientmodel.SelectionDecision{"": {Current: id}}}
	state := State{Preference: clientmodel.Preference{Schema: 3, PolicyID: selection.PolicyID}, NetworkGeneration: "demo-network", NativeExecutionSpec: "demo-spec", SelectionMemory: map[string]clientmodel.SelectionMemory{"access": memory}}
	started := time.Now().UnixMilli()
	refreshed, changed, err := RefreshNativeObservations(context.Background(), selector, routes, state, time.Now)
	if err != nil || len(refreshed.NativeObservations) != 1 || completed.Load() <= started || changed {
		t.Fatal("same-call completed result was discarded as future or fixed exit reran routing", err)
	}
}
