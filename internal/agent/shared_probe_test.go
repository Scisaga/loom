package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/measure"
	"loom/internal/model"
)

// §5.5：一个目标的挂起请求只合并相同链路/目标，不能阻塞别的声明，
// 等待者取消也不能迫使仍有需要的原探测停下来。
func TestSharedProbesIndependentTargetsAndCancelableWaiters(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	var blockedRequests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			blockedRequests.Add(1)
			enteredOnce.Do(func() { close(entered) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer proxy.Close()
	defer releaseOnce.Do(func() { close(release) })
	d := Decl{ID: "demo-service", TuningPeriod: "10m", Window: "1h", StaleAfter: "20m", Targets: []string{"http://service.example/slow", "http://service.example/fast"}, Candidates: []Cand{{Tag: "demo-path", Chain: []string{"demo-entry", "demo-exit"}}}}
	cfg := &Config{Probe: proxy.Listener.Addr().String(), Declarations: []Decl{d}}
	p := newSharedProbes(cfg)
	opts := &Options{Now: time.Now, ProbeTimeout: 5 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := make(chan error, 1)
	go func() {
		_, err, _ := p.probe(ctx, cfg, &d, d.Candidates[0], d.Targets[0], "demo-owner", opts)
		owner <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("original probe did not start")
	}
	fast := make(chan error, 1)
	go func() {
		_, err, _ := p.probe(ctx, cfg, &d, d.Candidates[0], d.Targets[1], "demo-other-target", opts)
		fast <- err
	}()
	select {
	case err := <-fast:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("unrelated target blocked behind slow request")
	}
	waitCtx, stopWait := context.WithCancel(ctx)
	waiter := make(chan error, 1)
	go func() {
		_, err, _ := p.probe(waitCtx, cfg, &d, d.Candidates[0], d.Targets[0], "demo-waiter", opts)
		waiter <- err
	}()
	stopWait()
	select {
	case err := <-waiter:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled waiter remained stuck behind owner")
	}
	consumer := make(chan error, 1)
	go func() {
		_, err, _ := p.probe(ctx, cfg, &d, d.Candidates[0], d.Targets[0], "demo-shared-consumer", opts)
		consumer <- err
	}()
	releaseOnce.Do(func() { close(release) })
	if err := <-owner; err != nil {
		t.Fatalf("waiter canceled original probe: %v", err)
	}
	if err := <-consumer; err != nil {
		t.Fatalf("same-key consumer did not receive original result: %v", err)
	}
	if _, err, _ := p.probe(ctx, cfg, &d, d.Candidates[0], d.Targets[0], "demo-next-scope", opts); err != nil || blockedRequests.Load() != 1 {
		t.Fatalf("concurrent/cache consumers created duplicate physical requests: requests=%d err=%v", blockedRequests.Load(), err)
	}
}

func TestSharedProbesReusePhysicalSampleWithoutInflatingScope(t *testing.T) {
	var requests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer proxy.Close()
	a := Decl{ID: "best", TuningPeriod: "10m", Window: "1h", StaleAfter: "20m", Targets: []string{"http://target.invalid"}, Candidates: []Cand{{Tag: "opaque-a", ProbeUser: "a", Chain: []string{"entry", "exit"}}}}
	b := a
	b.ID, b.Targets, b.Candidates = "service", []string{"http://target.invalid/"}, []Cand{{Tag: "opaque-b", ProbeUser: "b", Chain: []string{"entry", "exit"}}}
	cfg := &Config{Probe: strings.TrimPrefix(proxy.URL, "http://"), Declarations: []Decl{a, b}}
	cache := newSharedProbes(cfg)
	now := time.Now().UTC()
	opts := &Options{ProbeTimeout: time.Second, Now: func() time.Time { return now }}
	_, err, first := cache.probe(context.Background(), cfg, &a, a.Candidates[0], a.Targets[0], "scope-a", opts)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	_, err, reused := cache.probe(context.Background(), cfg, &b, b.Candidates[0], b.Targets[0], "scope-b", opts)
	if err != nil || requests.Load() != 1 || !reused.Equal(first) {
		t.Fatalf("equivalent scope did not reuse original observation: requests=%d at=%s err=%v", requests.Load(), reused, err)
	}
	// A subsequent round in either scope needs a new physical observation.
	_, err, next := cache.probe(context.Background(), cfg, &b, b.Candidates[0], b.Targets[0], "scope-b", opts)
	if err != nil || requests.Load() != 2 || !next.Equal(now) {
		t.Fatalf("same scope counted its old sample again: requests=%d at=%s err=%v", requests.Load(), next, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err, _ := cache.probe(ctx, cfg, &a, a.Candidates[0], a.Targets[0], "scope-a", opts); err == nil || requests.Load() != 2 {
		t.Fatal("canceled consumer reused or created an observation")
	}
}

func TestSharedProbesDoNotMergeDifferentTargetsOrAmbiguousChains(t *testing.T) {
	var requests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unreachable", http.StatusServiceUnavailable)
	}))
	defer proxy.Close()
	decl := Decl{ID: "a", TuningPeriod: "10m", Window: "1h", StaleAfter: "20m", Targets: []string{"http://target.invalid/a", "http://target.invalid/a/"}, Candidates: []Cand{{Tag: "a"}, {Tag: "b"}}}
	cfg := &Config{Probe: strings.TrimPrefix(proxy.URL, "http://"), Declarations: []Decl{decl}}
	cache := newSharedProbes(cfg)
	opts := &Options{ProbeTimeout: time.Second, Now: time.Now}
	for index, target := range decl.Targets {
		if _, err, _ := cache.probe(context.Background(), cfg, &decl, decl.Candidates[0], target, string(rune('a'+index)), opts); err == nil {
			t.Fatal("physical HTTP failure became success")
		}
	}
	_, _, _ = cache.probe(context.Background(), cfg, &decl, decl.Candidates[1], decl.Targets[0], "other-scope", opts)
	if requests.Load() != 3 {
		t.Fatalf("different URLs or ambiguous chains merged: %d", requests.Load())
	}
}

func TestRunProbeSharingIsOptInAndKeepsIndependentScopedEvidence(t *testing.T) {
	for _, share := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "client"}[share], func(t *testing.T) {
			var requests atomic.Int32
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				_, _ = w.Write([]byte("ok"))
			}))
			defer proxy.Close()
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("unexpected selector mutation: %s", r.Method)
				}
				_, _ = w.Write([]byte(`{"type":"Selector","now":"` + strings.TrimPrefix(r.URL.Path, "/proxies/") + `"}`))
			}))
			defer api.Close()
			a := Decl{ID: "best", Selector: "opaque-a", Objective: model.Latency, TuningPeriod: "10m", Window: "1h", StaleAfter: "20m", MinSamples: 4, Targets: []string{"http://target.invalid"}, Candidates: []Cand{{Tag: "opaque-a", ProbeUser: "a", Chain: []string{"entry", "exit"}}}}
			b := a
			b.ID, b.Selector, b.Targets, b.Candidates = "service", "opaque-b", []string{"http://target.invalid/"}, []Cand{{Tag: "opaque-b", ProbeUser: "b", Chain: []string{"entry", "exit"}}}
			cfg := &Config{Node: "access", API: strings.TrimPrefix(api.URL, "http://"), Probe: strings.TrimPrefix(proxy.URL, "http://"), Declarations: []Decl{a, b}}
			dir := t.TempDir()
			opts := Options{Once: true, ShareEquivalentProbes: share, MeasurementPath: filepath.Join(dir, "measurements.jsonl"), StatePath: filepath.Join(dir, "state.json"), Log: io.Discard}
			if err := Run(context.Background(), cfg, opts); err != nil {
				t.Fatal(err)
			}
			want := int32(2)
			if share {
				want = 1
			}
			ms, err := measure.Load(opts.MeasurementPath)
			if err != nil || requests.Load() != want || len(ms) != 2 || ms[0].DecisionScope == ms[1].DecisionScope || ms[0].CandidateID == ms[1].CandidateID {
				t.Fatalf("sharing changed scoped evidence: requests=%d ms=%+v err=%v", requests.Load(), ms, err)
			}
		})
	}
}
