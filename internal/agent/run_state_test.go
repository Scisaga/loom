package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/model"
	"loom/internal/version"
)

func TestTickKeepsLastCompleteHealthWhileProbeIsInFlight(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "agent-state.json")
	measurementPath := filepath.Join(dir, "measurements.jsonl")
	declaration := Decl{
		ID: "intl-api", Selector: "svc:intl-api", Objective: model.Latency,
		Targets:      []string{"http://probe-target.invalid/"},
		TuningPeriod: "10m", Window: "10m", MinSamples: 1, StaleAfter: "5m",
		Candidates: []Cand{{Tag: "cand:intl-api:direct", ProbeUser: "direct"}},
	}
	scope := decisionScope("demo-d", &declaration)
	p50 := 42
	initial := State{
		Node: "demo-d", TS: now.Add(-time.Minute).Format(time.RFC3339),
		ComponentVersion: version.AgentProtocolVersion,
		Selections: []Selection{{
			Declaration: declaration.ID, Selector: declaration.Selector,
			Candidate:     declaration.Candidates[0].Tag,
			DecisionScope: scope,
			UpdatedAt:     now.Add(-time.Minute).Format(time.RFC3339),
			Health: &CandidateHealth{
				Candidates: 1, RecentSuccess: 1, SelectedState: healthSuccess,
				SelectedSamples: 1, SelectedP50MS: &p50, BestP50MS: &p50,
			},
		}},
	}
	body, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	selections, err := newStateStore(statePath, "demo-d", []Decl{declaration}, now)
	if err != nil {
		t.Fatal(err)
	}

	probeEntered := make(chan struct{})
	probeRelease := make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	releaseProbe := func() { releaseOnce.Do(func() { close(probeRelease) }) }
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		enteredOnce.Do(func() { close(probeEntered) })
		<-probeRelease
		_, _ = w.Write([]byte("ok"))
	}))
	defer probe.Close()
	defer releaseProbe()
	selector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("selector method = %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"Selector","now":"cand:intl-api:direct"}`))
	}))
	defer selector.Close()

	opts := Options{Now: func() time.Time { return now }, ProbeTimeout: 2 * time.Second}
	cfg := &Config{
		Node: "demo-d", Probe: probe.Listener.Addr().String(), ProbeSecret: "secret",
	}
	measurements := &store{path: measurementPath, retention: time.Hour, now: opts.Now}
	errCh := make(chan error, 1)
	go func() {
		errCh <- tick(context.Background(), cfg, &declaration,
			newClash(selector.Listener.Addr().String(), "secret"),
			measurements, selections, newObserved(), 10*time.Minute,
			map[string]string{}, &sync.Mutex{}, &opts, func(string, ...any) {})
	}()

	select {
	case <-probeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("probe did not start")
	}
	during, err := ReadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(during.Selections) != 1 || during.Selections[0].Health == nil {
		t.Fatalf("in-flight probe replaced complete health: %+v", during)
	}
	releaseProbe()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	final, err := ReadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Selections) != 1 || final.Selections[0].Health == nil {
		t.Fatalf("completed probe did not publish health: %+v", final)
	}
}

func TestCancelledTickCannotWriteSelectorMeasurementsOrState(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "agent-state.json")
	measurementPath := filepath.Join(dir, "measurements.jsonl")
	declaration := Decl{
		ID: "svc", Selector: "svc:svc", Objective: model.Latency,
		Targets:      []string{"http://probe-target.invalid/"},
		TuningPeriod: "10m", Window: "1h", MinSamples: 1, StaleAfter: "30m",
		Candidates: []Cand{{Tag: "a", ProbeUser: "a"}, {Tag: "b", ProbeUser: "b"}},
	}
	selections, err := newStateStore(statePath, "access-a", []Decl{declaration}, now)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	probeEntered := make(chan struct{})
	var enteredOnce sync.Once
	probe := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		enteredOnce.Do(func() { close(probeEntered) })
		<-r.Context().Done()
	}))
	defer probe.Close()

	var selectorPuts atomic.Int32
	selector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			selectorPuts.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"Selector","now":"a"}`))
	}))
	defer selector.Close()

	ctx, cancel := context.WithCancel(context.Background())
	options := Options{Now: func() time.Time { return now }, ProbeTimeout: 30 * time.Second}
	config := &Config{Node: "access-a", Probe: probe.Listener.Addr().String(), ProbeSecret: "secret"}
	measurements := &store{path: measurementPath, retention: time.Hour, now: options.Now}
	errCh := make(chan error, 1)
	go func() {
		errCh <- tick(ctx, config, &declaration,
			newClash(selector.Listener.Addr().String(), "secret"), measurements, selections,
			newObserved(), 10*time.Minute, map[string]string{}, &sync.Mutex{}, &options,
			func(string, ...any) {})
	}()

	select {
	case <-probeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("probe did not start")
	}
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled tick error=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled tick did not return promptly")
	}
	if got := selectorPuts.Load(); got != 0 {
		t.Fatalf("cancelled tick wrote selector %d times", got)
	}
	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("cancelled tick rewrote state:\nbefore=%s\nafter=%s", before, after)
	}
	if _, err := os.Stat(measurementPath); !os.IsNotExist(err) {
		t.Fatalf("cancelled partial round wrote measurements: %v", err)
	}
}

func TestCancelledContextPreventsClashRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := newClash(server.Listener.Addr().String(), "secret").Select(ctx, "svc:d", "candidate"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Select with cancelled context error=%v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("cancelled selector request reached server %d times", got)
	}
}
