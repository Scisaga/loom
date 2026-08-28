package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrafficJSONExposesOnlyAttachedCentralHistory(t *testing.T) {
	history := &TrafficHistoryView{
		WindowStart: "2026-08-27T12:00:00Z", WindowEnd: "2026-08-28T12:00:00Z",
		BucketWidth: "1h", Source: "signed test",
		Buckets: []TrafficBucketView{{
			Start: "2026-08-27T12:00:00Z", End: "2026-08-27T13:00:00Z", Samples: 1,
			Nodes: []TrafficNodeTotalsView{{Node: "a", RXBytes: 10, TXBytes: 20, Bytes: 30, Samples: 1}},
		}},
	}
	h := Handler(Deps{Snapshot: func() View { return View{TrafficHistory: history} }})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/traffic.json", nil))
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("traffic response = %d %q", rr.Code, rr.Header().Get("Content-Type"))
	}
	var got TrafficExportView
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 1 || got.HistoryStatus != "available" || got.History == nil ||
		got.History.BucketWidth != "1h" || len(got.History.Buckets) != 1 ||
		got.History.Buckets[0].Nodes[0].Bytes != "30" {
		t.Fatalf("traffic JSON = %+v", got)
	}
	if string(rr.Body.Bytes()) == "" || !json.Valid(rr.Body.Bytes()) {
		t.Fatalf("invalid traffic JSON: %q", rr.Body.String())
	}
}

func TestTrafficJSONExportsCurrentCountersWithoutHistoryOnOrdinaryNode(t *testing.T) {
	h := Handler(Deps{Snapshot: func() View {
		return View{Self: "n1", ObservedAt: "2026-08-28T12:00:00Z", Nodes: []NodeView{{
			ID: "n1", Self: true, TrafficObservedAt: "2026-08-28T11:59:58Z",
			Tunnels: []TunnelView{{Interface: "wg-n2", PeerNode: "n2", LinkID: "n1/n2",
				RxBytes: 10, TxBytes: 20, CounterEpoch: "boot/7",
				CounterObservedAt: "2026-08-28T11:59:58Z", CounterSource: "direct /status",
				CounterPresent: true, TrafficTrusted: true}},
		}}}
	}})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/traffic.json", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("ordinary-node traffic endpoint status = %d, want 200", rr.Code)
	}
	var got TrafficExportView
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Node != "n1" || got.History != nil || len(got.Current) != 1 ||
		got.HistoryStatus != "not_supported" || got.Current[0].RXBytes != "10" || !got.Current[0].Trusted {
		t.Fatalf("ordinary-node traffic JSON = %+v", got)
	}
}

func TestTrafficJSONKeepsSampledZeroCounterAndFallsBackToNodeObservation(t *testing.T) {
	h := Handler(Deps{Snapshot: func() View {
		return View{Self: "n1", ObservedAt: "2026-08-28T12:00:00Z", Nodes: []NodeView{{
			ID: "n1", Self: true, ObservedAt: "2026-08-28T11:59:57Z",
			Tunnels: []TunnelView{{Interface: "wg-n2", RxBytes: 0, TxBytes: 0, CounterPresent: true}},
		}}}
	}})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/traffic.json", nil))
	var got TrafficExportView
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Current) != 1 || got.Current[0].RXBytes != "0" || got.Current[0].TXBytes != "0" ||
		got.CurrentObservedAt != "2026-08-28T11:59:57Z" {
		t.Fatalf("sampled zero-counter export = %+v", got)
	}
}

func TestTrafficJSONUsesDedicatedCachedSnapshotAndExactDecimalCounters(t *testing.T) {
	fullCalls, trafficCalls := 0, 0
	h := Handler(Deps{
		Snapshot: func() View { fullCalls++; return View{} },
		TrafficSnapshot: func() View {
			trafficCalls++
			return View{Self: "n1", IntentSource: "current SSOT", TrafficHistoryStatus: "unavailable",
				TrafficHistoryError: "retained store unavailable", Nodes: []NodeView{{
					ID: "n1", Self: true, Tunnels: []TunnelView{{
						Interface: "wg-n2", CounterPresent: true, RxBytes: 1<<62 + 7, TxBytes: 9,
					}},
				}}}
		},
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/traffic.json", nil))
	if fullCalls != 0 || trafficCalls != 1 {
		t.Fatalf("traffic endpoint snapshot calls: full=%d traffic=%d", fullCalls, trafficCalls)
	}
	var got TrafficExportView
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Scope != "control" || got.HistoryStatus != "unavailable" ||
		got.HistoryError == "" || got.Current[0].RXBytes != "4611686018427387911" {
		t.Fatalf("versioned exact traffic export = %+v", got)
	}
}
