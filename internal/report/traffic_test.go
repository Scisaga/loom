package report

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"loom/internal/attest"
)

func TestTrafficClaimFromWGDumpUsesTopologyIdentityAndResetEpoch(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	cfg := &Config{
		Node: "gz02", Interfaces: []string{"wg-sg02"},
		Neighbors: []Neighbor{{Node: "sg02", Addr: "10.99.0.1:61802"}},
	}
	dump := strings.Join([]string{
		"wg-sg02\tprivate\tpublic\t61687\toff",
		"wg-sg02\tpeer-key-sg\t(none)\t1.2.3.4:61687\t10.99.0.1/32\t123\t1000\t2000\t25",
		"wg-unmanaged\tother-key\t(none)\t5.6.7.8:1\t10.0.0.1/32\t123\t999\t999\t25",
	}, "\n")
	claim, err := trafficClaimFromDump(cfg, now, []byte(dump), "boot-1",
		func(iface string) (string, error) {
			if iface != "wg-sg02" {
				t.Fatalf("unexpected interface index lookup %q", iface)
			}
			return "42", nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if claim.Node != "gz02" || claim.TS != now.Format(time.RFC3339) || len(claim.Counters) != 1 {
		t.Fatalf("claim identity/counters wrong:%+v", claim)
	}
	c := claim.Counters[0]
	peerKeySum := sha256.Sum256([]byte("peer-key-sg"))
	wantEpoch := fmt.Sprintf("boot-1/42/%x", peerKeySum[:16])
	if c.PeerNode != "sg02" || c.LinkID != "gz02/sg02" || c.PeerPublicKey != "peer-key-sg" ||
		c.CounterEpoch != wantEpoch || c.RXBytes != 1000 || c.TXBytes != 2000 {
		t.Fatalf("counter did not preserve logical/diagnostic/reset identity:%+v", c)
	}
}

func TestTrafficClaimRejectsMultiplePeersOnManagedInterface(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cfg := &Config{Node: "gz02", Interfaces: []string{"wg-sg02"}}
	row := func(key string) string {
		return "wg-sg02\t" + key + "\t(none)\t1.2.3.4:1\t10.0.0.1/32\t1\t2\t3\t25"
	}
	_, err := trafficClaimFromDump(cfg, now, []byte(row("key-a")+"\n"+row("key-b")), "boot",
		func(string) (string, error) { return "42", nil })
	if err == nil || !strings.Contains(err.Error(), "多个 WireGuard peers") {
		t.Fatalf("one-interface-one-peer invariant was not enforced:%v", err)
	}
}

func TestTrafficAttachmentSurvivesGossipAndMapsOnlyAfterVerification(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca, key, crt := reportTestIdentity(t, "gz02")
	claim := attest.TrafficClaim{
		Version: attest.TrafficClaimVersion, Node: "gz02", TS: now.Format(time.RFC3339),
		Counters: []attest.TrafficCounter{{
			Interface: "wg-sg02", PeerNode: "sg02", LinkID: "gz02/sg02",
			PeerPublicKey: "peer-key", CounterEpoch: "boot/42", RXBytes: 100, TXBytes: 200,
		}},
	}
	signed, err := attest.SignTraffic(claim, key, crt)
	if err != nil {
		t.Fatal(err)
	}
	original := Observation{Node: "gz02", TS: claim.TS, Traffic: signed}
	wire, err := json.Marshal(&original)
	if err != nil {
		t.Fatal(err)
	}
	var relayed Observation
	if err := json.Unmarshal(wire, &relayed); err != nil {
		t.Fatal(err)
	}

	tbl := newTable()
	tbl.verifyTraffic = func(o *Observation, at time.Time, maxAge time.Duration) error {
		_, err := verifyTrafficAttachment(o, ca, at, maxAge)
		return err
	}
	if err := tbl.put(&relayed, now, time.Minute); err != nil {
		t.Fatalf("valid traffic attachment did not enter gossip table:%v", err)
	}
	learned := tbl.snapshot("jm24", now, time.Minute)
	if len(learned) != 1 || learned[0].Traffic == nil {
		t.Fatalf("gossip dropped optional traffic attachment:%+v", learned)
	}
	view := buildViewWithCA(&Config{Node: "jm24", ExpectedNodes: []string{"jm24", "gz02"}},
		&Status{Node: "jm24", TS: claim.TS, Learned: learned}, now,
		func(string) ([]byte, error) { return ca, nil })
	var remoteFound bool
	for _, node := range view.Nodes {
		if node.ID != "gz02" {
			continue
		}
		remoteFound = true
		if !node.TrafficTrusted || !node.TrafficVerified || node.TrafficObservedAt != claim.TS ||
			len(node.Tunnels) != 1 {
			t.Fatalf("verified remote counters not mapped:%+v", node)
		}
		tunnel := node.Tunnels[0]
		if !tunnel.CounterPresent || !tunnel.TrafficTrusted || !tunnel.TrafficVerified || tunnel.PeerNode != "sg02" ||
			tunnel.LinkID != "gz02/sg02" || tunnel.CounterEpoch != "boot/42" ||
			tunnel.CounterObservedAt != claim.TS || tunnel.RxBytes != 100 || tunnel.TxBytes != 200 {
			t.Fatalf("trusted TunnelView lost counter identity:%+v", tunnel)
		}
	}
	if !remoteFound {
		t.Fatal("learned node missing from view")
	}

	// A relay can alter the optional JSON field without invalidating v5, but a
	// new reader must reject that traffic domain and map no counter.
	tampered := relayed
	tampered.Traffic = &attest.TrafficAttest{
		TrafficClaim: relayed.Traffic.TrafficClaim,
		Cert:         relayed.Traffic.Cert, Sig: relayed.Traffic.Sig,
	}
	tampered.Traffic.Counters = append([]attest.TrafficCounter(nil), relayed.Traffic.Counters...)
	tampered.Traffic.Counters[0].RXBytes++
	badView := buildViewWithCA(&Config{Node: "jm24"},
		&Status{Node: "jm24", TS: claim.TS, Learned: []Observation{tampered}}, now,
		func(string) ([]byte, error) { return ca, nil })
	for _, node := range badView.Nodes {
		if node.ID == "gz02" && (node.TrafficTrusted || len(node.Tunnels) != 0 || node.Health != "problem") {
			t.Fatalf("tampered traffic was trusted or failed silently:%+v", node)
		}
	}
	if err := tbl.put(&tampered, now.Add(time.Second), time.Minute); err == nil ||
		!strings.Contains(err.Error(), "流量") {
		t.Fatalf("new gossip reader accepted tampered traffic:%v", err)
	}
}

func TestDirectTunnelOnlyMarksCounterPresentWhenInterfaceExists(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	st := &Status{Node: "a", TS: now.Format(time.RFC3339), Tunnels: []Tunnel{
		{Interface: "wg-b", Down: true, HandshakeAgeSec: -1},
		{Interface: "wg-c", PeerPresent: true, UnitState: "active", HandshakeAgeSec: 10},
	}}
	node := nodeView("a", true, true, st, nil, nil, "", now)
	if len(node.Tunnels) != 2 || node.Tunnels[0].CounterPresent || !node.Tunnels[1].CounterPresent {
		t.Fatalf("direct counter presence did not follow interface evidence: %+v", node.Tunnels)
	}
	if !node.TrafficTrusted || node.TrafficObservedAt != st.TS {
		t.Fatalf("present direct counter did not mark node traffic evidence: %+v", node)
	}

	allDown := &Status{Node: "a", TS: now.Format(time.RFC3339), Tunnels: []Tunnel{{
		Interface: "wg-b", Down: true, HandshakeAgeSec: -1,
	}}}
	downNode := nodeView("a", true, true, allDown, nil, nil, "", now)
	if downNode.TrafficTrusted || downNode.TrafficObservedAt != "" {
		t.Fatalf("down-only tunnel set was presented as current counter evidence: %+v", downNode)
	}
}

func TestTrafficDoesNotChangeV5MeasurementClaim(t *testing.T) {
	o := &Observation{
		Node: "gz02", TS: "2026-08-28T12:00:00Z", Applied: "snapshot",
		Edges: []Edge{{To: "sg02", RTTMs: 10, Samples: 5}},
	}
	legacyBefore, currentBefore := claimsForObservation(o, 5)
	digestBefore := measurementDigest(o)
	o.Traffic = &attest.TrafficAttest{TrafficClaim: attest.TrafficClaim{
		Version: 1, Node: o.Node, TS: o.TS,
		Counters: []attest.TrafficCounter{{
			Interface: "wg-sg02", PeerNode: "sg02", LinkID: "gz02/sg02",
			PeerPublicKey: "key", CounterEpoch: "boot/1", RXBytes: 1, TXBytes: 2,
		}},
	}}
	legacyAfter, currentAfter := claimsForObservation(o, 5)
	if digestAfter := measurementDigest(o); digestAfter != digestBefore ||
		!reflect.DeepEqual(legacyBefore, legacyAfter) || !reflect.DeepEqual(currentBefore, currentAfter) {
		t.Fatalf("adding traffic mutated deployed measurement/v5 claim:\ndigest %s -> %s\nclaim %#v -> %#v",
			digestBefore, digestAfter, currentBefore, currentAfter)
	}
}

func TestTrafficAttachmentBindsOuterNodeAndTimestamp(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca, key, crt := reportTestIdentity(t, "gz02")
	claim := attest.TrafficClaim{
		Version: 1, Node: "gz02", TS: now.Format(time.RFC3339),
		Counters: []attest.TrafficCounter{{
			Interface: "wg-sg02", PeerNode: "sg02", LinkID: "gz02/sg02",
			PeerPublicKey: "key", CounterEpoch: "boot/1",
		}},
	}
	signed, err := attest.SignTraffic(claim, key, crt)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []*Observation{
		{Node: "hz01", TS: claim.TS, Traffic: signed},
		{Node: claim.Node, TS: now.Add(time.Second).Format(time.RFC3339), Traffic: signed},
	} {
		if _, err := verifyTrafficAttachment(o, ca, now, time.Minute); err == nil ||
			!strings.Contains(err.Error(), "外层") {
			t.Fatalf("valid signed traffic was rebound to another observation:%v", err)
		}
	}
}
