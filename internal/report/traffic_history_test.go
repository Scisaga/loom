package report

import (
	"path/filepath"
	"testing"
	"time"

	"loom/internal/attest"
	trafficstore "loom/internal/traffic"
	"loom/internal/webui"
)

func TestTrafficFrameFromViewAcceptsOnlyVerifiedCounters(t *testing.T) {
	at := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	v := webui.View{Nodes: []webui.NodeView{
		{ID: "verified", TrafficVerified: true, VerifiedTraffic: []webui.VerifiedTrafficCounterView{{
			Interface: "wg-peer", PeerNode: "peer", CounterEpoch: "boot/7",
			ObservedAt: at.Format(time.RFC3339), RXBytes: 10, TXBytes: 20,
		}}},
		{ID: "direct-but-unsigned", TrafficTrusted: true, Tunnels: []webui.TunnelView{{
			Interface: "wg-peer", PeerNode: "peer", CounterEpoch: "boot/8",
			CounterObservedAt: at.Format(time.RFC3339), RxBytes: 30, TxBytes: 40,
			TrafficTrusted: true,
		}}},
		{ID: "mixed", TrafficVerified: true, Tunnels: []webui.TunnelView{{
			Interface: "wg-peer", PeerNode: "peer", CounterEpoch: "boot/9",
			CounterObservedAt: at.Format(time.RFC3339), RxBytes: 50, TxBytes: 60,
		}}},
	}}
	frame := trafficFrameFromView(v, at)
	if len(frame.Counters) != 1 || frame.Counters[0].Node != "verified" {
		t.Fatalf("retained counters = %+v", frame.Counters)
	}
}

func TestLocalSignedTrafficDoesNotOverwriteNewerDirectCounters(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	ca, key, crt := reportTestIdentity(t, "self")
	claim := attest.TrafficClaim{
		Version: attest.TrafficClaimVersion, Node: "self", TS: now.Add(-time.Minute).Format(time.RFC3339),
		Counters: []attest.TrafficCounter{{
			Interface: "wg-peer", PeerNode: "peer", LinkID: "peer/self",
			PeerPublicKey: "old-peer-key", CounterEpoch: "old-epoch", RXBytes: 10, TXBytes: 20,
		}},
	}
	signed, err := attest.SignTraffic(claim, key, crt)
	if err != nil {
		t.Fatal(err)
	}
	status := &Status{
		Node: "self", TS: now.Format(time.RFC3339),
		Observation: &Observation{Node: "self", TS: claim.TS, Traffic: signed},
		Tunnels:     []Tunnel{{Interface: "wg-peer", PeerPresent: true, UnitState: "active", HandshakeAgeSec: 5, RxByt: 1000, TxByt: 2000}},
	}
	view := buildViewWithCA(&Config{Node: "self", ExpectedNodes: []string{"self"}}, status, now,
		func(string) ([]byte, error) { return ca, nil })
	if len(view.Nodes) != 1 || len(view.Nodes[0].Tunnels) != 1 {
		t.Fatalf("unexpected local view: %+v", view.Nodes)
	}
	node, tunnel := view.Nodes[0], view.Nodes[0].Tunnels[0]
	if tunnel.RxBytes != 1000 || tunnel.TxBytes != 2000 || tunnel.CounterObservedAt != status.TS ||
		tunnel.CounterSource != "direct /status" || tunnel.TrafficVerified {
		t.Fatalf("signed gossip sample overwrote direct current counter: %+v", tunnel)
	}
	if !node.TrafficVerified || len(node.VerifiedTraffic) != 1 ||
		node.VerifiedTraffic[0].RXBytes != 10 || node.VerifiedTraffic[0].ObservedAt != claim.TS {
		t.Fatalf("signed history evidence was not retained separately: %+v", node)
	}
}

func TestTrafficHistoryFromStoreMapsNodeAndTXOnlyLinkBuckets(t *testing.T) {
	start := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	store, err := trafficstore.NewStore(filepath.Join(t.TempDir(), "traffic.jsonl"),
		trafficRetention, 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	appendTrafficTestFrame(t, store, start, 100, 200, 200, 100)
	appendTrafficTestFrame(t, store, start.Add(time.Minute), 160, 240, 240, 160)

	history, err := trafficHistoryFromStore(store, start.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if history == nil || len(history.Buckets) != 24 {
		t.Fatalf("history = %+v", history)
	}
	bucket := history.Buckets[0]
	if len(bucket.Nodes) != 2 || bucket.Nodes[0].Node != "a" || bucket.Nodes[0].Bytes != 100 {
		t.Fatalf("node totals = %+v", bucket.Nodes)
	}
	if len(bucket.Links) != 1 || bucket.Links[0].From != "a" || bucket.Links[0].To != "b" ||
		bucket.Links[0].TXBytes != 100 || bucket.Links[0].ReportingEndpoints != 2 {
		t.Fatalf("link totals = %+v", bucket.Links)
	}
}

func appendTrafficTestFrame(t *testing.T, store *trafficstore.Store, at time.Time,
	aRX, aTX, bRX, bTX int64) {
	t.Helper()
	err := store.Append(trafficstore.Frame{
		CollectedAt: at.Format(time.RFC3339),
		Counters: []trafficstore.Counter{
			{Node: "a", Peer: "b", Interface: "wg-b", Epoch: "boot-a/1", TS: at.Format(time.RFC3339), RXBytes: aRX, TXBytes: aTX},
			{Node: "b", Peer: "a", Interface: "wg-a", Epoch: "boot-b/2", TS: at.Format(time.RFC3339), RXBytes: bRX, TXBytes: bTX},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}
