package agent

import (
	"testing"
	"time"

	"loom/internal/attest"
	"loom/internal/observation"
)

func TestClientPathMeasurementsUseActualCarrierAndTarget(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ts := now.Format(time.RFC3339)
	cache := &ObservationCache{maxAge: time.Minute, by: map[string]observation.Observation{
		"demo-entry": {Node: "demo-entry", TS: ts,
			Edges:       []observation.Edge{{To: "demo-exit", RTTMs: 170, Samples: 2}},
			LinkMetrics: &attest.LinkMetricAttest{LinkMetricClaim: attest.LinkMetricClaim{Metrics: []attest.LinkMetric{{PeerNode: "demo-exit", Transport: "hysteria2", Carrier: "public", Scope: "single_hop", ObservedAt: ts, RTTMS: 38, P50MS: 38, P95MS: 41, Samples: 2, TransferBytes: 80000, TransferDurationMS: 100}}}}},
		"demo-exit": {Node: "demo-exit", TS: ts, Targets: []observation.Reach{{Target: "https://demo.example", FirstByteMs: 57, Samples: 2}}},
	}}
	chain, targets := []string{"demo-entry", "demo-exit"}, []string{"https://demo.example/", "https://missing.example/"}
	public := cache.ClientPathMeasurements(chain, targets, []string{"public-hysteria2"}, now)
	if len(public) != 3 || public[0].Hop != 1 || *public[0].DelayMS != 38 || *public[0].VariationMS != 3 || *public[0].RateBPS != 6400000 || public[0].ObservedAt != ts {
		t.Fatalf("public metrics lost or replaced by WG: %+v", public)
	}
	if public[1].Hop != 2 || public[1].Kind != "target" || *public[1].DelayMS != 57 || public[2].DelayMS != nil || public[2].ObservedAt != "" {
		t.Fatalf("targets were merged or fabricated: %+v", public)
	}
	wg := cache.ClientPathMeasurements(chain, targets, []string{"neighbor"}, now)[0]
	if *wg.DelayMS != 170 || wg.VariationMS != nil || wg.RateBPS != nil {
		t.Fatalf("WG borrowed public metrics or invented a history window: %+v", wg)
	}
	unknown := cache.ClientPathMeasurements(chain, targets, []string{"unknown"}, now)[0]
	if unknown.DelayMS != nil {
		t.Fatal("unknown carrier acquired a delay")
	}
	// 显示结果不能原地修改缓存；过期数据不保留看似当前的数值。
	*public[0].DelayMS = 999
	if *cache.ClientPathMeasurements(chain, targets, []string{"public-hysteria2"}, now)[0].DelayMS != 38 {
		t.Fatal("UI mutated cache")
	}
	for _, m := range cache.ClientPathMeasurements(chain, targets, []string{"public-hysteria2"}, now.Add(2*time.Minute)) {
		if m.DelayMS != nil || m.VariationMS != nil || m.RateBPS != nil {
			t.Fatal("stale metrics displayed")
		}
	}
	cache.by["demo-entry"].LinkMetrics.Metrics[0].ObservedAt = now.Add(-2 * time.Minute).Format(time.RFC3339)
	if cache.ClientPathMeasurements(chain, targets, []string{"public-hysteria2"}, now)[0].DelayMS != nil {
		t.Fatal("fresh outer timestamp refreshed an old link metric")
	}
}

func TestClientPathMeasurementsKeepFailuresAndZeroDelayDistinct(t *testing.T) {
	now := time.Now().UTC()
	cache := &ObservationCache{maxAge: time.Minute, by: map[string]observation.Observation{
		"demo-entry": {TS: now.Format(time.RFC3339), Edges: []observation.Edge{{To: "demo-exit", Samples: 1}}},
		"demo-exit":  {TS: now.Format(time.RFC3339), Targets: []observation.Reach{{Target: "https://demo.example/", Samples: 2, Failures: 2, Error: "demo timeout"}}},
	}}
	m := cache.ClientPathMeasurements([]string{"demo-entry", "demo-exit"}, []string{"https://demo.example/"}, []string{"neighbor"}, now)
	if m[0].DelayMS == nil || *m[0].DelayMS != 0 || m[1].DelayMS != nil || m[1].Failures != 2 || m[1].Error != "demo timeout" {
		t.Fatalf("zero, unknown and failure were confused: %+v", m)
	}
}
