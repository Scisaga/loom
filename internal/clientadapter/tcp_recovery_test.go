package clientadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"
)

func TestTCPRecoveryPinsOnlyItsRequestAndKeepsClientPolicy(t *testing.T) {
	at, routes, _ := engineEvidence()
	route := routes[0]
	current := clientmodel.Selection{Scope: "access", PolicyID: route.PolicyID, CandidateID: routes[1].ID, Revision: "demo-revision", Targets: map[string]string{}, Choices: map[string]protocol.RouteChoice{routes[1].ID: {EntryNodeID: routes[1].EntryNodeID, FirstResourceID: routes[1].FirstResourceID, FinalExit: routes[1].FinalExit}}}
	for _, scenario := range []string{"exact", "different response", "superseded"} {
		t.Run(scenario, func(t *testing.T) {
			var posts, reads atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.Header.Get("Authorization") != "Bearer demo-local-secret" {
					http.Error(w, "missing existing authentication", http.StatusForbidden)
					return
				}
				switch {
				case request.Method == http.MethodPost && request.URL.Path == "/loom/access/access/tcp-connect":
					posts.Add(1)
					var value struct {
						Revision string               `json:"expected_revision"`
						PolicyID string               `json:"policy_id"`
						Choice   protocol.RouteChoice `json:"choice"`
						Target   string               `json:"target"`
					}
					if json.NewDecoder(request.Body).Decode(&value) != nil || value.Revision != current.Revision || value.PolicyID != current.PolicyID || value.Target != "tcp://web.example:443" || value.Choice != (protocol.RouteChoice{EntryNodeID: route.EntryNodeID, FirstResourceID: route.FirstResourceID, FinalExit: route.FinalExit}) {
						t.Error("calibration lost its original complete request")
					}
					time.Sleep(60 * time.Millisecond)
					result := NativeTCPObservation{Revision: current.Revision, PolicyID: current.PolicyID, CandidateID: route.ID, Target: "web.example:443", Result: "available", StartedAt: at.UnixMilli(), ObservedAt: at.Add(time.Millisecond).UnixMilli()}
					if scenario == "different response" {
						result.Target = "other.example:443"
					}
					_ = json.NewEncoder(w).Encode(result)
				case request.Method == http.MethodGet && request.URL.Path == "/proxies/access":
					reads.Add(1)
					revision := current.Revision
					if scenario == "superseded" {
						revision = "demo-newer-revision"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"now": current.CandidateID, "targets": current.Targets, "policy_id": current.PolicyID, "choices": current.Choices, "revision": revision})
				default:
					t.Error("exploration attempted a selector mutation")
					http.Error(w, "unexpected operation", http.StatusBadRequest)
				}
			}))
			defer server.Close()
			selector, err := NewHTTPSelector(`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-local-secret"}}}`)
			if err != nil {
				t.Fatal(err)
			}
			selector.client.Timeout = 25 * time.Millisecond
			transport := selector.client.Transport.(*http.Transport)
			defer transport.CloseIdleConnections()
			transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = selector.calibrateTCP(ctx, current, route, "tcp://web.example:443")
			if scenario == "exact" && err != nil || scenario != "exact" && err == nil {
				t.Fatal("unexpected request binding result", err)
			}
			if scenario == "superseded" && !errors.Is(err, ErrSelectionSuperseded) {
				t.Fatal("late completion was not discarded", err)
			}
			if posts.Load() != 1 || scenario != "different response" && reads.Load() != 1 || selector.client.Timeout != 25*time.Millisecond || selector.client.Transport != transport {
				t.Fatal("calibration changed the shared client or selector", posts.Load(), reads.Load())
			}
			if _, err = selector.calibrateTCP(context.Background(), current, route, "tcp://web.example:443"); err == nil || posts.Load() != 1 {
				t.Fatal("unbounded exploration reached native I/O")
			}
		})
	}
}

func TestOrdinaryHealthExpiresOnceWhileOriginalActivityRemains(t *testing.T) {
	at, routes, _ := engineEvidence()
	for i := range routes {
		routes[i].FixedExit = false
	}
	id := routes[0].ID
	until := at.Add(30 * time.Second)
	sample := clientmodel.Observation{CandidateID: id, Scope: "access", Target: "demo.example:443", Action: "tcp_connect", Result: "unavailable", NetworkGeneration: "demo-network", ObservedAt: at.Format(time.RFC3339Nano), ValidUntil: until.Format(time.RFC3339Nano)}
	s := &fakeSelector{current: map[string]string{"access": id}, snapshots: map[string]clientmodel.Selection{"access": {PolicyID: "demo-policy", Choices: map[string]protocol.RouteChoice{id: {EntryNodeID: routes[0].EntryNodeID, FirstResourceID: routes[0].FirstResourceID, FinalExit: routes[0].FinalExit}}}}}
	state := State{Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-network", NativeExecutionSpec: "demo-spec", NativeObservations: []clientmodel.Observation{sample}, SelectionMemory: map[string]clientmodel.SelectionMemory{"access": {PolicyID: "demo-policy", NetworkGeneration: "demo-network", NativeHealthUntil: until.UnixMilli(), NativeBinding: &clientmodel.NativeBinding{Revision: "0", NetworkGeneration: "demo-network", ExecutionSpec: "demo-spec"}}}}
	state, changed, err := RefreshNativeObservations(context.Background(), s, routes, state, func() time.Time { return until })
	if err != nil || !changed || len(state.NativeObservations) != 1 || state.NativeObservations[0] != sample || state.SelectionMemory["access"].NativeHealthUntil != 0 {
		t.Fatal("health expiration deleted activity or renewed its original value", err)
	}
	_, changed, err = RefreshNativeObservations(context.Background(), s, routes, state, func() time.Time { return until.Add(time.Second) })
	if err != nil || changed {
		t.Fatal("an already consumed deadline kept recomputing the graph", err)
	}
}

func TestNodeWorkerKeepsTCPRecoveryLocalAndHonorsRetryPeriod(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	clock := at
	budget, _ := NewMeasurementBudget(MeasurementLimits{Window: time.Minute, Requests: 8, Concurrent: 1, Bytes: 1 << 20, Timeout: time.Second}, func() time.Time { return clock })
	ctx := WithMeasurementBudget(context.Background(), budget)
	timing := DefaultMeasurementTiming
	var attempts, delivered, shared int
	task := nodeMeasurement{key: "demo-tcp", active: true, localRun: func(context.Context) (clientmodel.Observation, error) {
		attempts++
		return clientmodel.Observation{CandidateID: "demo-candidate", Scope: "access", Target: "demo.example:443", Action: "tcp_calibration", Result: "available", NetworkGeneration: "demo-network", ObservedAt: clock.Format(time.RFC3339Nano), ValidUntil: clock.Add(time.Minute).Format(time.RFC3339Nano)}, nil
	}, localProgress: func(values []clientmodel.Observation) error { delivered += len(values); return nil }}
	for _, offset := range []time.Duration{0, time.Second, timing.ActivePeriod} {
		clock = at.Add(offset)
		values, err := observeNodeJobs(ctx, []nodeMeasurement{task}, nil, "demo-network", func() time.Time { return clock }, timing, func([]control.Observation) error { shared++; return nil })
		if err != nil || len(values) != 0 {
			t.Fatal("local TCP completion entered shared measurement output", err)
		}
	}
	if attempts != 2 || delivered != 2 || shared != 0 {
		t.Fatal("TCP worker bypassed its repeat period or signed reducer", attempts, delivered, shared)
	}
	task.key = "demo-deferred"
	task.localRun = func(context.Context) (clientmodel.Observation, error) {
		return clientmodel.Observation{}, ErrMeasurementDeferred
	}
	_, err := observeNodeJobs(ctx, []nodeMeasurement{task}, nil, "demo-network", func() time.Time { return clock }, timing, nil)
	if err != nil {
		t.Fatal(err)
	}
	if budget.discovered[task.key].After(clock) {
		t.Fatal("budget deferral pretended an actual attempt was completed")
	}
}

func TestCancelledTCPWorkerProducesNoLocalFailureAndJoins(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	entered, stopped := make(chan struct{}), make(chan struct{})
	task := nodeMeasurement{key: "demo-cancel", active: true, localRun: func(ctx context.Context) (clientmodel.Observation, error) {
		close(entered)
		<-ctx.Done()
		close(stopped)
		return clientmodel.Observation{}, ctx.Err()
	}, localProgress: func([]clientmodel.Observation) error { t.Error("cancellation produced a health sample"); return nil }}
	go func() { <-entered; cancel() }()
	_, err := observeNodeJobs(ctx, []nodeMeasurement{task}, nil, "demo-network", func() time.Time { return at }, DefaultMeasurementTiming, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("TCP worker returned before its actual operation ended")
	}
}

func TestTCPRecoveryDefersOnlyNativeLocalPending(t *testing.T) {
	_, routes, _ := engineEvidence()
	route := routes[0]
	current := clientmodel.Selection{Scope: "access", PolicyID: route.PolicyID, Revision: "demo-revision"}
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusConflict, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodPost || r.URL.Path != "/loom/access/access/tcp-connect" {
					t.Error("cold task fetched a resource catalog or changed a selector")
				}
				http.Error(w, http.StatusText(status), status)
			}))
			defer server.Close()
			selector, err := NewHTTPSelector(`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-secret"}}}`)
			if err != nil {
				t.Fatal(err)
			}
			if err = selector.SetResourceSource(resourcePoolSource); err != nil {
				t.Fatal(err)
			}
			selector.SetDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = selector.calibrateTCP(ctx, current, route, "tcp://demo.example:443")
			if requests != 1 || err == nil || errors.Is(err, ErrMeasurementDeferred) != (status == http.StatusServiceUnavailable) || errors.Is(err, ErrSelectionSuperseded) != (status == http.StatusConflict) {
				t.Fatal("native status lost its local-pending/conflict/transport distinction", status, requests, err)
			}
		})
	}
}
