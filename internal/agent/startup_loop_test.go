package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"loom/internal/measure"
	"loom/internal/model"
)

type startupNetwork struct {
	mu      sync.Mutex
	current string
	counts  map[string]int
	puts    int
	gets    int
	switchC chan struct{}
	firstC  chan struct{}
}

func startupNetworkFixture(t *testing.T, useful bool) (*startupNetwork, *Config, Options) {
	t.Helper()
	n := &startupNetwork{current: "current", counts: map[string]int{}, switchC: make(chan struct{}, 1), firstC: make(chan struct{}, 1)}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		defer n.mu.Unlock()
		if r.Method == http.MethodPut {
			var value struct{ Name string }
			_ = json.NewDecoder(r.Body).Decode(&value)
			n.current = value.Name
			n.puts++
			select {
			case n.switchC <- struct{}{}:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		n.gets++
		if n.gets == 2 {
			select {
			case n.firstC <- struct{}{}:
			default:
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"type": "Selector", "now": n.current})
	}))
	t.Cleanup(api.Close)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Proxy-Authorization"), "Basic "))
		user, _, _ := strings.Cut(string(auth), ":")
		n.mu.Lock()
		n.counts[user]++
		n.mu.Unlock()
		delay := map[string]time.Duration{"current": 30, "a-fast": 3, "b-side": 15, "c-side": 20, "z-unseen": 1}[user] * time.Millisecond
		if !useful && user == "current" {
			delay = time.Millisecond
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(delay):
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(proxy.Close)
	d := Decl{ID: "service", Selector: "selector", Objective: model.Latency, Targets: []string{"http://target.invalid/"}, TuningPeriod: "1h", Window: "1h", StaleAfter: "1h", MinSamples: 4, ProbeBudget: 4, SwitchThreshold: .2}
	for _, tag := range []string{"current", "a-fast", "b-side", "c-side", "z-unseen"} {
		d.Candidates = append(d.Candidates, Cand{Tag: tag, ProbeUser: tag, Chain: []string{tag}})
	}
	cfg := &Config{Node: "access", API: strings.TrimPrefix(api.URL, "http://"), Probe: strings.TrimPrefix(proxy.URL, "http://"), Declarations: []Decl{d}}
	dir := t.TempDir()
	opts := Options{MeasurementPath: filepath.Join(dir, "measurements.jsonl"), StatePath: filepath.Join(dir, "state.json"), Log: io.Discard, ProbeTimeout: time.Second, ShareEquivalentProbes: true, StartupProbeInterval: 5 * time.Millisecond}
	return n, cfg, opts
}

func TestStartupLoopUsesRealSamplesAndOnlyOneChallenger(t *testing.T) {
	n, cfg, opts := startupNetworkFixture(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, opts) }()
	select {
	case <-n.switchC:
	case <-time.After(3 * time.Second):
		t.Fatal("bounded startup never qualified its promising challenger")
	}
	// Allow more than another comparison interval; completion must not restart
	// a startup sweep or advance the normal one-hour maintenance deadline.
	time.Sleep(40 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.current != "a-fast" || n.puts != 1 || n.counts["current"] != 4 || n.counts["a-fast"] != 4 || n.counts["b-side"] != 1 || n.counts["c-side"] != 1 || n.counts["z-unseen"] != 0 {
		t.Fatalf("startup exceeded its comparison or fabricated repeated samples: current=%s puts=%d requests=%v", n.current, n.puts, n.counts)
	}
	ms, err := measure.Load(opts.MeasurementPath)
	if err != nil || len(ms) != 10 {
		t.Fatalf("physical requests and raw journal disagree: records=%d err=%v", len(ms), err)
	}
}

func TestStartupLoopDoesNotSupplementAnAlreadyBestCurrentPath(t *testing.T) {
	n, cfg, opts := startupNetworkFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, opts) }()
	select {
	case <-n.firstC:
	case <-time.After(3 * time.Second):
		t.Fatal("first bounded round did not finish")
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	total := 0
	for _, count := range n.counts {
		total += count
	}
	if total != 4 || n.puts != 0 {
		t.Fatalf("unhelpful comparison consumed additional budget: requests=%v puts=%d", n.counts, n.puts)
	}
}

func TestStartupLoopMultiTargetStopsAtExactSampleDeficit(t *testing.T) {
	n, cfg, opts := startupNetworkFixture(t, true)
	cfg.Declarations[0].Targets = []string{"http://target.invalid/a", "http://target.invalid/b", "http://target.invalid/c"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, opts) }()
	select {
	case <-n.switchC:
	case <-time.After(3 * time.Second):
		t.Fatal("multi-target startup never completed its one-sample deficit")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	// The first round has three samples per candidate. Only one more is
	// missing for current/challenger, not another batch of three each.
	if n.counts["current"] != 4 || n.counts["a-fast"] != 4 || n.counts["b-side"] != 3 || n.counts["c-side"] != 3 || n.counts["z-unseen"] != 0 {
		t.Fatalf("supplementary targets exceeded actual sample deficits: %v", n.counts)
	}
	ms, err := measure.Load(opts.MeasurementPath)
	if err != nil || len(ms) != 14 {
		t.Fatalf("multi-target raw samples=%d err=%v", len(ms), err)
	}
}

func TestStartupLoopCancellationDuringWaitStopsAllFurtherProbes(t *testing.T) {
	n, cfg, opts := startupNetworkFixture(t, true)
	opts.StartupProbeInterval = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, opts) }()
	select {
	case <-n.firstC:
	case <-time.After(3 * time.Second):
		t.Fatal("first bounded round did not finish")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup interval blocked generation cancellation")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	total := 0
	for _, count := range n.counts {
		total += count
	}
	if total != 4 || n.puts != 0 {
		t.Fatalf("cancellation still sent supplementary requests/selector writes: %v %d", n.counts, n.puts)
	}
}
