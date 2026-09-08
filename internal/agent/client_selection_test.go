package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"loom/internal/model"
	"loom/internal/observation"
)

type clientRouteCase struct {
	tag      string
	hops     int
	ms       int
	failures int
	unknown  bool
}

// §5.5.1：通过实际 selector 读写验证减少中继，反向排列候选也不能改变结果。
func TestClientRemovesDominatedRelays(t *testing.T) {
	for _, tt := range []struct {
		name    string
		current string
		paths   []clientRouteCase
		want    string
	}{
		{"shorter_faster_below_threshold", "demo-relay", []clientRouteCase{{tag: "demo-relay", hops: 2, ms: 100}, {tag: "demo-short", hops: 1, ms: 95}}, "demo-short"},
		{"shorter_equal_delay", "demo-relay", []clientRouteCase{{tag: "demo-relay", hops: 2, ms: 100}, {tag: "demo-short", hops: 1, ms: 100}}, "demo-short"},
		{"blocked_fastest_does_not_hide_shorter", "demo-relay", []clientRouteCase{{tag: "demo-relay", hops: 2, ms: 100}, {tag: "demo-short", hops: 1, ms: 95}, {tag: "demo-fast", hops: 2, ms: 94}}, "demo-short"},
		{"small_gain_does_not_add_relay", "demo-short", []clientRouteCase{{tag: "demo-short", hops: 1, ms: 100}, {tag: "demo-relay", hops: 2, ms: 95}}, "demo-short"},
		{"useful_relay_is_allowed", "demo-short", []clientRouteCase{{tag: "demo-short", hops: 1, ms: 100}, {tag: "demo-relay", hops: 2, ms: 75}}, "demo-relay"},
		{"slower_short_path_does_not_win", "demo-relay", []clientRouteCase{{tag: "demo-relay", hops: 2, ms: 100}, {tag: "demo-short", hops: 1, ms: 105}}, "demo-relay"},
		{"worse_failures_do_not_win", "demo-relay", []clientRouteCase{{tag: "demo-relay", hops: 2, ms: 100}, {tag: "demo-short", hops: 1, ms: 50, failures: 1}}, "demo-relay"},
		{"lower_failures_can_add_relay", "demo-short", []clientRouteCase{{tag: "demo-short", hops: 1, ms: 100, failures: 1}, {tag: "demo-relay", hops: 2, ms: 110}}, "demo-relay"},
		{"unknown_short_path_does_not_win", "demo-relay", []clientRouteCase{{tag: "demo-relay", hops: 2, ms: 100}, {tag: "demo-short", hops: 1, ms: 50, unknown: true}}, "demo-relay"},
		{"same_hops_keep_configured_threshold", "demo-first", []clientRouteCase{{tag: "demo-first", hops: 1, ms: 100}, {tag: "demo-second", hops: 1, ms: 95}}, "demo-first"},
	} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%t", tt.name, reverse), func(t *testing.T) {
				now := time.Now().UTC().Truncate(time.Second)
				d := Decl{ID: "demo-service", Selector: "demo-selector", Objective: model.Latency, SwitchThreshold: 0.2,
					Targets:    []string{"https://service.example/", "https://missing.example/"},
					Candidates: []Cand{{Tag: "demo-direct"}}}
				cache := newTestObservationCache(t)
				entries := map[string]entryResult{}
				carriers := map[string][]string{}
				for _, p := range tt.paths {
					chain := []string{p.tag + "-exit"}
					if p.hops == 2 {
						chain = append([]string{p.tag + "-entry"}, chain...)
						cache.by[chain[0]] = observation.Observation{Node: chain[0], TS: now.Format(time.RFC3339),
							Edges: []observation.Edge{{To: chain[1], RTTMs: 1, Samples: 5}}}
						carriers[p.tag] = []string{"neighbor"}
					}
					entries[chain[0]] = entryResult{RTT: time.Millisecond, At: now}
					if !p.unknown {
						exit := chain[len(chain)-1]
						cache.by[exit] = observation.Observation{Node: exit, TS: now.Format(time.RFC3339),
							Targets: []observation.Reach{{Target: d.Targets[0], FirstByteMs: p.ms - p.hops, Samples: 5, Failures: p.failures}}}
					}
					d.Candidates = append(d.Candidates, Cand{Tag: p.tag, Chain: chain})
				}
				if reverse {
					slices.Reverse(d.Candidates)
				}
				runClientSelectionRounds(t, d, tt.current, tt.want, cache, entries, carriers, now)
			})
		}
	}
}

// §16.1.2：出口目标未知时，更近的入口不能凭空抵消未测的中继段。
func TestClientMissingObservationsDoNotAddRelay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	d := Decl{ID: "demo-service", Selector: "demo-selector", Objective: model.Latency, SwitchThreshold: 0.2,
		Targets: []string{"https://service.example/"}, Candidates: []Cand{
			{Tag: "demo-relay", Chain: []string{"demo-entry", "demo-exit"}},
			{Tag: "demo-short", Chain: []string{"demo-exit"}},
		}}
	runClientSelectionRounds(t, d, "demo-short", "demo-short", newTestObservationCache(t), map[string]entryResult{
		"demo-entry": {RTT: time.Millisecond, At: now}, "demo-exit": {RTT: 25 * time.Millisecond, At: now},
	}, nil, now)
}

func runClientSelectionRounds(t *testing.T, d Decl, initial, want string, cache *ObservationCache, entries map[string]entryResult, carriers map[string][]string, now time.Time) {
	t.Helper()
	var mu sync.Mutex
	actual, writes := initial, 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/proxies/"+d.Selector {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]string{"type": "Selector", "now": actual})
		case http.MethodPut:
			var body struct{ Name string }
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			actual, writes = body.Name, writes+1
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected method: %s", r.Method)
			w.WriteHeader(405)
		}
	}))
	defer api.Close()
	cfg := &Config{Node: "demo-client", API: strings.TrimPrefix(api.URL, "http://"), Declarations: []Decl{d}}
	path := filepath.Join(t.TempDir(), "state.json")
	states, err := newStateStore(context.Background(), path, cfg.Node, cfg.Declarations, now)
	if err != nil {
		t.Fatal(err)
	}
	k := newClash(cfg.API, "")
	defer k.c.CloseIdleConnections()
	for round := range 2 {
		if err := selectClientRoute(context.Background(), cfg, d, k, states, entries, cache, carriers, now.Add(time.Duration(round)*time.Second)); err != nil {
			t.Fatal(err)
		}
		state, err := ReadState(path)
		if err != nil || len(state.Selections) != 1 || state.Selections[0].Candidate != want {
			t.Fatalf("round %d: state=%+v error=%v; want %s", round, state, err, want)
		}
		if round == 0 && initial != want {
			var oldHops, newHops int
			for _, c := range d.Candidates {
				if c.Tag == initial {
					oldHops = len(c.Chain)
				}
				if c.Tag == want {
					newHops = len(c.Chain)
				}
			}
			if newHops < oldHops && !strings.Contains(state.Selections[0].Reason, "减少中继") {
				t.Fatalf("missing simplification reason: %s", state.Selections[0].Reason)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	wantWrites := 0
	if initial != want {
		wantWrites = 1
	}
	if actual != want || writes != wantWrites {
		t.Fatalf("actual=%s writes=%d; want %s with %d writes", actual, writes, want, wantWrites)
	}
}
