package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
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
	p50 := 42
	initial := State{
		Node: "demo-d", TS: now.Add(-time.Minute).Format(time.RFC3339),
		ComponentVersion: version.AgentProtocolVersion,
		Selections: []Selection{{
			Declaration: declaration.ID, Selector: declaration.Selector,
			Candidate: declaration.Candidates[0].Tag,
			UpdatedAt: now.Add(-time.Minute).Format(time.RFC3339),
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
		errCh <- tick(cfg, &declaration,
			newClash(selector.Listener.Addr().String(), "secret"),
			measurements, selections, newObserved(), 10*time.Minute,
			map[string]int{}, &sync.Mutex{}, &opts, func(string, ...any) {})
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
