package attest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testTrafficClaim(node, peer, ts string) TrafficClaim {
	return TrafficClaim{
		Version: TrafficClaimVersion, Node: node, TS: ts,
		Counters: []TrafficCounter{{
			Interface: "wg-" + peer, PeerNode: peer,
			LinkID:        CanonicalTrafficLinkID(node, peer),
			PeerPublicKey: "peer-public-key", CounterEpoch: "boot-a/42",
			RXBytes: 1234, TXBytes: 5678,
		}},
	}
}

func TestTrafficSignVerifyAndJSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newCA(t)
	key, crt := ca.issue(t, "gz02")
	signed, err := SignTraffic(testTrafficClaim("gz02", "sg02", now.Format(time.RFC3339)), key, crt)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var relayed TrafficAttest
	if err := json.Unmarshal(wire, &relayed); err != nil {
		t.Fatal(err)
	}
	got, err := VerifyTrafficFresh(&relayed, ca.certPEM, now, time.Minute)
	if err != nil {
		t.Fatalf("JSON 转述后的流量陈述无法验签:%v", err)
	}
	if got.Node != "gz02" || len(got.Counters) != 1 || got.Counters[0].LinkID != "gz02/sg02" ||
		got.Counters[0].RXBytes != 1234 || got.Counters[0].CounterEpoch != "boot-a/42" {
		t.Fatalf("验出的 counter 不完整:%+v", got)
	}
}

func TestTrafficSignatureRejectsTamperingAndSpeakingForPeer(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newCA(t)
	key, crt := ca.issue(t, "gz02")
	signed, err := SignTraffic(testTrafficClaim("gz02", "sg02", now.Format(time.RFC3339)), key, crt)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*TrafficCounter){
		"rx":       func(c *TrafficCounter) { c.RXBytes++ },
		"peer":     func(c *TrafficCounter) { c.PeerNode = "ber01"; c.Interface = "wg-ber01"; c.LinkID = "ber01/gz02" },
		"link":     func(c *TrafficCounter) { c.LinkID = "gz02/hz01" },
		"epoch":    func(c *TrafficCounter) { c.CounterEpoch = "boot-b/99" },
		"peer key": func(c *TrafficCounter) { c.PeerPublicKey = "rotated-by-relay" },
	} {
		bad := *signed
		bad.Counters = append([]TrafficCounter(nil), signed.Counters...)
		mutate(&bad.Counters[0])
		if _, err := VerifyTraffic(&bad, ca.certPEM); err == nil {
			t.Errorf("relay 改写 %s 后仍验签成功", name)
		}
	}

	peerKey, peerCert := ca.issue(t, "ber01")
	impersonated, err := SignTraffic(testTrafficClaim("gz02", "sg02", now.Format(time.RFC3339)), peerKey, peerCert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTraffic(impersonated, ca.certPEM); err == nil || !strings.Contains(err.Error(), "替") {
		t.Fatalf("ber01 的证书替 gz02 签流量未被拒绝:%v", err)
	}
}

func TestTrafficFreshnessAndResetBoundaryAreExplicit(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newCA(t)
	key, crt := ca.issue(t, "gz02")
	old := testTrafficClaim("gz02", "sg02", now.Add(-11*time.Minute).Format(time.RFC3339))
	signed, err := SignTraffic(old, key, crt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTrafficFresh(signed, ca.certPEM, now, 10*time.Minute); err == nil ||
		!strings.Contains(err.Error(), "过期") {
		t.Fatalf("旧 counter snapshot 被无限重放:%v", err)
	}

	first := testTrafficClaim("gz02", "sg02", now.Format(time.RFC3339))
	second := first
	second.Counters = append([]TrafficCounter(nil), first.Counters...)
	second.Counters[0].CounterEpoch = "boot-a/99"
	if first.Counters[0].CounterEpoch == second.Counters[0].CounterEpoch {
		t.Fatal("接口重建没有产生独立 counter reset boundary")
	}
}

func TestTrafficCanonicalSortsCountersWithoutChangingLogicalLink(t *testing.T) {
	ts := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	a := testTrafficClaim("gz02", "sg02", ts)
	bCounter := TrafficCounter{
		Interface: "wg-hz01", PeerNode: "hz01", LinkID: "gz02/hz01",
		PeerPublicKey: "second-key", CounterEpoch: "boot-a/43", RXBytes: 9, TXBytes: 10,
	}
	a.Counters = append(a.Counters, bCounter)
	b := a
	b.Counters = []TrafficCounter{bCounter, a.Counters[0]}
	if string(a.canonical()) != string(b.canonical()) {
		t.Fatal("同一组 counters 的输入顺序改变了 traffic canonical")
	}
	if CanonicalTrafficLinkID("sg02", "gz02") != CanonicalTrafficLinkID("gz02", "sg02") {
		t.Fatal("link ID 不是方向无关的")
	}
}

func TestTrafficClaimRejectsTwoPeersOnOneManagedInterface(t *testing.T) {
	ts := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	c := testTrafficClaim("gz02", "sg02", ts)
	second := c.Counters[0]
	second.PeerPublicKey = "second-key"
	c.Counters = append(c.Counters, second)
	ca := newCA(t)
	key, crt := ca.issue(t, "gz02")
	if _, err := SignTraffic(c, key, crt); err == nil || !strings.Contains(err.Error(), "重复 managed interface") {
		t.Fatalf("one-interface-one-peer claim invariant was not enforced:%v", err)
	}
}
