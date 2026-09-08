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

	"loom/internal/attest"
	"loom/internal/measure"
	"loom/internal/model"
	"loom/internal/observation"
)

// §16.1.2：通过真实 Run 回路验证客户端报告缓存只剪掉有可信失败证据的出口，
// 不代替本机的成功探测，也不能让坏签名或过期数据减少候选覆盖。
func TestRunConsumesOnlyTrustedFreshClientObservations(t *testing.T) {
	for _, evidence := range []string{"trusted-expired", "trusted-recovered", "tampered", "expired"} {
		t.Run(evidence, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			var mu sync.Mutex
			requests := map[string]int{}
			current := "demo-pruned"
			probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				credentials, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Proxy-Authorization"), "Basic "))
				if err != nil {
					t.Error(err)
				}
				user, _, _ := strings.Cut(string(credentials), ":")
				mu.Lock()
				requests[user]++
				mu.Unlock()
				_, _ = w.Write([]byte("synthetic response"))
			}))
			defer probe.Close()
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Method == http.MethodPut {
					var request struct {
						Name string `json:"name"`
					}
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
					}
					current = request.Name
					w.WriteHeader(http.StatusNoContent)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"type": "Selector", "now": current})
			}))
			defer api.Close()
			cfg := &Config{
				Node: "demo-client", API: api.Listener.Addr().String(), Probe: probe.Listener.Addr().String(),
				ObservationStale: "10m", Declarations: []Decl{{
					ID: "demo-service", Selector: "demo-selector", Objective: model.Latency,
					Targets: []string{"http://service.example/"}, TuningPeriod: "10m", Window: "1h", StaleAfter: "20m", MinSamples: 4,
					Candidates: []Cand{{Tag: "demo-direct", ProbeUser: "demo-direct"}, {Tag: "demo-pruned", ProbeUser: "demo-pruned", Chain: []string{"demo-entry", "demo-exit"}}},
				}},
			}
			cache, err := NewObservationCache(cfg)
			if err != nil {
				t.Fatal(err)
			}
			identity := newObservationIdentity(t, "demo-exit")
			at := now.Add(-time.Minute)
			if evidence == "expired" {
				at = now.Add(-11 * time.Minute)
			}
			o := signedCacheObservation(t, identity, at, true)
			o.Targets[0].Target = "http://service.example"
			o.Attest, err = attest.Sign(attest.Claim{CanonicalVersion: 5, Node: o.Node, TS: o.TS, MeasurementsSHA256: observation.MeasurementDigest(&o)}, identity.key, identity.cert)
			if err != nil {
				t.Fatal(err)
			}
			if evidence == "tampered" {
				o.Targets[0].Error = "changed after signing"
			}
			err = cache.Ingest(context.Background(), rawCacheObservation(t, o), identity.ca, now)
			trusted := strings.HasPrefix(evidence, "trusted-")
			if (err == nil) != trusted {
				t.Fatalf("evidence %s acceptance: %v", evidence, err)
			}
			dir := t.TempDir()
			opts := Options{Once: true, Observations: cache, MeasurementPath: filepath.Join(dir, "measurements.jsonl"), StatePath: filepath.Join(dir, "state.json"), Now: func() time.Time { return now }, Log: io.Discard}
			// 旧成功不能盖过当前服务器失败；旧 derived 兼容保留在日志里，
			// 但不能再进入完整路径统计或被本轮重复追加。
			scope := decisionScope(cfg.Node, &cfg.Declarations[0])
			prior := measure.Measurement{TS: now.Add(-2 * time.Minute).Format(time.RFC3339), Node: cfg.Node, CandidateID: "demo-pruned", Declaration: cfg.Declarations[0].ID, DecisionScope: scope, Target: cfg.Declarations[0].Targets[0], FirstByteMs: 10, Point: measure.L4Tunnel, Kind: measure.Active}
			legacy := prior
			legacy.Kind, legacy.Error = measure.Derived, "legacy derived failure"
			if err := measure.Append(opts.MeasurementPath, []measure.Measurement{prior, legacy}); err != nil {
				t.Fatal(err)
			}
			if err := Run(context.Background(), cfg, opts); err != nil {
				t.Fatal(err)
			}
			ms, err := measure.Load(opts.MeasurementPath)
			if err != nil {
				t.Fatal(err)
			}
			derived := 0
			for _, m := range ms {
				if m.Kind == measure.Derived {
					derived++
					if m.CandidateID != "demo-pruned" || m.Error == "" {
						t.Fatalf("invalid derived evidence: %+v", m)
					}
				}
			}
			mu.Lock()
			mu.Unlock() // Run 已返回；与最后一次测试端点写入同步。
			if requests["demo-direct"] != 1 {
				t.Fatalf("local successful path was not physically verified: %v", requests)
			}
			if trusted {
				if requests["demo-pruned"] != 0 || derived != 1 || current != "demo-direct" {
					t.Fatalf("trusted failure did not prune and leave failed current: requests=%v derived=%d selected=%s", requests, derived, current)
				}
			} else if requests["demo-pruned"] != 1 || derived != 1 || current != "demo-pruned" {
				t.Fatalf("untrusted evidence changed probing or min_samples: requests=%v derived=%d selected=%s", requests, derived, current)
			}
			state, err := ReadState(opts.StatePath)
			if err != nil || len(state.Selections) != 1 {
				t.Fatalf("state: %+v err=%v", state, err)
			}
			health := state.Selections[0].Health
			if health == nil || health.SelectedFailures != 0 || trusted && health.SelectedSamples != 1 || !trusted && health.SelectedSamples != 2 {
				t.Fatalf("server/legacy constraints inflated full-path samples: %+v", health)
			}
			if trusted {
				now = now.Add(15 * time.Second)
				if err := Run(context.Background(), cfg, opts); err != nil {
					t.Fatal(err)
				}
				repeated, err := measure.Load(opts.MeasurementPath)
				if err != nil || len(repeated) != len(ms)+1 {
					t.Fatalf("same source observation appended fake path samples: samples=%d err=%v", len(repeated), err)
				}
				// 恢复报告或原来源观测过期，后续真实探测均重新覆盖该候选。
				if evidence == "trusted-recovered" {
					now = now.Add(time.Minute)
					o.TS = now.Format(time.RFC3339)
					o.Targets[0].Failures, o.Targets[0].Error = 0, ""
					o.Attest, err = attest.Sign(attest.Claim{CanonicalVersion: 5, Node: o.Node, TS: o.TS, MeasurementsSHA256: observation.MeasurementDigest(&o)}, identity.key, identity.cert)
					if err != nil {
						t.Fatal(err)
					}
					if err := cache.Ingest(context.Background(), rawCacheObservation(t, o), identity.ca, now); err != nil {
						t.Fatal(err)
					}
				} else {
					now = now.Add(11 * time.Minute)
				}
				if err := Run(context.Background(), cfg, opts); err != nil {
					t.Fatal(err)
				}
				state, err = ReadState(opts.StatePath)
				if err != nil || state.Selections[0].Health.RecentSuccess != 2 || state.Selections[0].Health.RecentDegraded != 0 {
					t.Fatalf("old source or legacy derived kept path unavailable: %+v err=%v", state, err)
				}
				mu.Lock()
				mu.Unlock()
				if requests["demo-pruned"] != 1 {
					t.Fatalf("old observation still pruned path: %v", requests)
				}
			}
		})
	}
}
