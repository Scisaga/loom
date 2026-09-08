package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"loom/internal/attest"
	"loom/internal/model"
	"loom/internal/observation"
)

func TestClientEntryProbesConcurrentOnceAndServerUpdatesDoNotProbe(t *testing.T) {
	var mu sync.Mutex
	current := map[string]string{"demo-service-a": "demo-a", "demo-service-b": "demo-a"}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		key := strings.TrimPrefix(r.URL.Path, "/proxies/")
		if r.Method == http.MethodPut {
			var body struct{ Name string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			current[key] = body.Name
			w.WriteHeader(204)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"type": "Selector", "now": current[key]})
	}))
	defer api.Close()
	// 若新实现误调用旧业务入口，立即记录；HTTP 目标本身也是禁止访问的接收器。
	var requests int
	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mu.Lock(); requests++; mu.Unlock(); w.WriteHeader(500) }))
	defer forbidden.Close()
	cfg := &Config{Node: "demo-client", API: strings.TrimPrefix(api.URL, "http://"), Probe: strings.TrimPrefix(forbidden.URL, "http://"), ObservationStale: "10m"}
	for _, name := range []string{"demo-service-a", "demo-service-b"} {
		cfg.Declarations = append(cfg.Declarations, Decl{ID: name, Selector: name, Objective: model.Latency, Targets: []string{"https://service.example/"}, MinSamples: 999, TuningPeriod: "1ms", Window: "1h", StaleAfter: "1h", Candidates: []Cand{
			{Tag: "demo-a", Chain: []string{"demo-entry", "demo-exit"}}, {Tag: "demo-b", Chain: []string{"demo-exit"}},
		}})
	}
	cache, err := NewObservationCache(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan string, 2)
	release := make(chan struct{})
	probes := map[string]int{}
	var entryDisplays [][]ClientPathMeasurement
	opts := ClientOptions{StatePath: filepath.Join(t.TempDir(), "state.json"), Observations: cache, Entries: []ClientEntry{
		{Node: "demo-entry", Address: "192.0.2.1"}, {Node: "demo-exit", Address: "192.0.2.2"}, {Node: "demo-entry", Address: "192.0.2.1"},
	}, OnEntries: func(m []ClientPathMeasurement) {
		mu.Lock()
		defer mu.Unlock()
		entryDisplays = append(entryDisplays, m)
	}, Probe: func(ctx context.Context, e ClientEntry) (time.Duration, error) {
		mu.Lock()
		probes[e.Node]++
		mu.Unlock()
		started <- e.Node
		select {
		case <-release:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		if e.Node == "demo-entry" {
			return time.Millisecond, nil
		}
		return 20 * time.Millisecond, nil
	}}
	done := make(chan error, 1)
	go func() { done <- RunClient(ctx, cfg, opts) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("entry probes serialized or missing")
		}
	}
	close(release)
	waitClientState(t, opts.StatePath, func(s *State) bool { return len(s.Selections) == 2 })
	// 无服务器结果也完成第一轮；不等待 999 个样本。
	id := newObservationIdentity(t, "demo-exit")
	now := time.Now().UTC().Truncate(time.Second)
	for round := 0; round < 2; round++ {
		o := signedCacheObservation(t, id, now.Add(time.Duration(round)*time.Second), false)
		if err := cache.Ingest(ctx, rawCacheObservation(t, o), id.ca, now.Add(time.Duration(round)*time.Second)); err != nil {
			t.Fatal(err)
		}
		waitClientState(t, opts.StatePath, func(s *State) bool {
			return len(s.Selections) == 2 && s.Selections[0].Candidate == "demo-b" && s.Selections[1].Candidate == "demo-b"
		})
	}
	s := waitClientState(t, opts.StatePath, func(s *State) bool { return strings.Contains(s.Selections[0].Reason, "分段观测估算") })
	for _, v := range s.Selections {
		if v.Health.SelectedSamples != 0 || v.Health.SelectedP50MS != nil || v.Health.SelectedP95MS != nil || v.Health.SelectedState != "unknown" {
			t.Fatal("fabricated complete-path measurements")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if probes["demo-entry"] != 1 || probes["demo-exit"] != 1 || requests != 0 {
		t.Fatalf("probes=%v business requests=%d", probes, requests)
	}
	if len(entryDisplays) != 1 || len(entryDisplays[0]) != 2 || *entryDisplays[0][0].DelayMS != 1 || entryDisplays[0][0].ObservedAt == "" {
		t.Fatalf("UI callback duplicated probes or lost original entry result: %+v", entryDisplays)
	}
}

func waitClientState(t *testing.T, path string, accept func(*State) bool) *State {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s, err := ReadState(path)
		if err == nil && s != nil && len(s.Selections) > 0 && accept(s) {
			return s
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("client selection missing")
	return nil
}

func TestClientCostPreservesUnknownFailureAndDirection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	c := newTestObservationCache(t)
	entry := observation.Observation{Node: "demo-entry", TS: now.Format(time.RFC3339), LinkMetrics: &attest.LinkMetricAttest{LinkMetricClaim: attest.LinkMetricClaim{Metrics: []attest.LinkMetric{{PeerNode: "demo-exit", Transport: "hysteria2", Scope: "single_hop", Carrier: "public", ObservedAt: now.Format(time.RFC3339), RTTMS: 20, Samples: 1}}}}}
	exit := observation.Observation{Node: "demo-exit", TS: now.Format(time.RFC3339), Targets: []observation.Reach{{Target: "https://service.example", FirstByteMs: 30, Samples: 2}}}
	c.by[entry.Node] = entry
	c.by[exit.Node] = exit
	chain := []string{entry.Node, exit.Node}
	targets := []string{"https://service.example/"}
	x := c.clientCost(chain, targets, now)
	if !x.known || x.failed || x.ms != 50 {
		t.Fatalf("cost=%+v", x)
	}
	if c.clientCost(chain, []string{"https://service.example/other"}, now).known || c.clientCost(chain, targets, now.Add(11*time.Minute)).known || c.clientCost([]string{exit.Node, entry.Node}, targets, now).known {
		t.Fatal("missing, expired or reverse evidence accepted")
	}
	exit.Targets[0].Failures = 2
	exit.Targets[0].Error = "demo failure"
	c.by[exit.Node] = exit
	x = c.clientCost(chain, targets, now)
	if !x.failed {
		t.Fatal("known server failure lost")
	}
	entry.LinkMetrics = nil
	entry.Edges = []observation.Edge{{To: exit.Node, RTTMs: 1, Samples: 1}}
	c.by[entry.Node] = entry
	if c.clientCost(chain, targets, now).known {
		t.Fatal("WG neighbor RTT substituted for public Hy2 hop")
	}
}

func TestClientPingFailureIsUnknownAndUnauthorizedEntryIsNotProbed(t *testing.T) {
	r := map[string]entryResult{"demo-entry": {Err: errors.New("ICMP filtered")}}
	if _, ok := entryFor(Cand{Chain: []string{"demo-entry"}}, r); ok {
		t.Fatal("ICMP failure treated as valid zero RTT")
	}
	cfg := &Config{Node: "demo-client", Declarations: []Decl{{ID: "demo-service", Candidates: []Cand{{Tag: "demo-a", Chain: []string{"demo-entry"}}}}}}
	called := false
	err := RunClient(context.Background(), cfg, ClientOptions{StatePath: filepath.Join(t.TempDir(), "state.json"), Entries: []ClientEntry{{Node: "demo-unauthorized", Address: "192.0.2.9"}}, Probe: func(context.Context, ClientEntry) (time.Duration, error) { called = true; return 0, nil }})
	if err == nil || called {
		t.Fatal("unauthorized entry probed")
	}
}

func TestClientReusesNeighborMeasurementsAndAvailableServiceTargets(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	c := newTestObservationCache(t)
	c.by["demo-entry"] = observation.Observation{Node: "demo-entry", TS: now.Format(time.RFC3339), Edges: []observation.Edge{{To: "demo-exit", RTTMs: 20, Samples: 5}}}
	c.by["demo-exit"] = observation.Observation{Node: "demo-exit", TS: now.Format(time.RFC3339), Targets: []observation.Reach{{Target: "https://service.example", FirstByteMs: 30, Samples: 5}}}
	targets := c.clientTargets([]string{"https://missing.example/", "https://service.example/"}, now)
	if len(targets) != 1 || targets[0] != "https://service.example/" {
		t.Fatalf("available target discarded: %v", targets)
	}
	cost := c.clientCost([]string{"demo-entry", "demo-exit"}, targets, now, []string{"neighbor"})
	if !cost.known || cost.failed || cost.ms != 50 {
		t.Fatalf("actual neighbor measurements ignored: %+v", cost)
	}
	if c.clientCost([]string{"demo-entry", "demo-exit"}, targets, now, []string{"public-hysteria2"}).known {
		t.Fatal("neighbor measurements used for a public carrier")
	}
}
