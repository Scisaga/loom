package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testLinkMetricClaim(node, peer, ts string) LinkMetricClaim {
	return LinkMetricClaim{
		Version: LinkMetricClaimVersion,
		Node:    node,
		TS:      ts,
		Metrics: []LinkMetric{{
			PeerNode: peer, Transport: LinkMetricTransportHysteria2,
			Scope: LinkMetricScopeSingleHop, Carrier: LinkMetricCarrierPublic,
			ObservedAt: ts, RTTMS: 207, P50MS: 203, P95MS: 211,
			Samples: 8, Failures: 1, TransferBytes: 262144, TransferDurationMS: 117,
			Error: "one timeout",
		}},
	}
}

func TestLinkMetricSignVerifyAndJSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newCA(t)
	key, crt := ca.issue(t, "jm24")
	signed, err := SignLinkMetric(
		testLinkMetricClaim("jm24", "gz02", now.Format(time.RFC3339)), key, crt)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var relayed LinkMetricAttest
	if err := json.Unmarshal(wire, &relayed); err != nil {
		t.Fatal(err)
	}
	got, err := VerifyLinkMetricFresh(&relayed, ca.certPEM, now, time.Minute)
	if err != nil {
		t.Fatalf("JSON 转述后的链路度量无法验签:%v", err)
	}
	if got.Node != "jm24" || len(got.Metrics) != 1 ||
		got.Metrics[0].PeerNode != "gz02" || got.Metrics[0].RTTMS != 207 ||
		got.Metrics[0].TransferBytes != 262144 {
		t.Fatalf("验出的链路度量不完整:%+v", got)
	}
}

func TestLinkMetricRejectsTamperingAndImpersonation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newCA(t)
	key, crt := ca.issue(t, "jm24")
	signed, err := SignLinkMetric(
		testLinkMetricClaim("jm24", "gz02", now.Format(time.RFC3339)), key, crt)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*LinkMetricAttest){
		"node":       func(s *LinkMetricAttest) { s.Node = "hz01" },
		"claim time": func(s *LinkMetricAttest) { s.TS = now.Add(time.Second).Format(time.RFC3339) },
		"peer":       func(s *LinkMetricAttest) { s.Metrics[0].PeerNode = "hz01" },
		"rtt":        func(s *LinkMetricAttest) { s.Metrics[0].RTTMS++ },
		"window":     func(s *LinkMetricAttest) { s.Metrics[0].P95MS++ },
		"transfer":   func(s *LinkMetricAttest) { s.Metrics[0].TransferBytes++ },
		"error":      func(s *LinkMetricAttest) { s.Metrics[0].Error = "two timeouts" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *signed
			bad.Metrics = append([]LinkMetric(nil), signed.Metrics...)
			mutate(&bad)
			if _, err := VerifyLinkMetric(&bad, ca.certPEM); err == nil {
				t.Fatal("tampered link metric verified")
			}
		})
	}

	peerKey, peerCert := ca.issue(t, "ber01")
	impersonated, err := SignLinkMetric(
		testLinkMetricClaim("jm24", "gz02", now.Format(time.RFC3339)), peerKey, peerCert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLinkMetric(impersonated, ca.certPEM); err == nil ||
		!strings.Contains(err.Error(), "替") {
		t.Fatalf("ber01 的证书替 jm24 签链路度量未被拒绝:%v", err)
	}
}

func TestLinkMetricRejectsReplayAndStaleOrFutureSamples(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newCA(t)
	key, crt := ca.issue(t, "jm24")

	old := testLinkMetricClaim("jm24", "gz02", now.Add(-11*time.Minute).Format(time.RFC3339))
	signed, err := SignLinkMetric(old, key, crt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLinkMetricFresh(signed, ca.certPEM, now, 10*time.Minute); err == nil ||
		!strings.Contains(err.Error(), "过期") {
		t.Fatalf("旧 link metric claim 被无限重放:%v", err)
	}

	staleSample := testLinkMetricClaim("jm24", "gz02", now.Format(time.RFC3339))
	staleSample.Metrics[0].ObservedAt = now.Add(-11 * time.Minute).Format(time.RFC3339)
	signed, err = SignLinkMetric(staleSample, key, crt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLinkMetricFresh(signed, ca.certPEM, now, 10*time.Minute); err == nil ||
		!strings.Contains(err.Error(), "过期") {
		t.Fatalf("新 claim 中的旧 metric 被接受:%v", err)
	}

	future := testLinkMetricClaim("jm24", "gz02", now.Add(3*time.Minute).Format(time.RFC3339))
	signed, err = SignLinkMetric(future, key, crt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLinkMetricFresh(signed, ca.certPEM, now, 10*time.Minute); err == nil ||
		!strings.Contains(err.Error(), "未来") {
		t.Fatalf("未来 link metric claim 被接受:%v", err)
	}
	if _, err := VerifyLinkMetricFresh(signed, ca.certPEM, now, 0); err == nil {
		t.Fatal("非正的新鲜度窗口被接受")
	}
}

func TestLinkMetricRejectsDuplicatePeersAndInvalidBounds(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	ca := newCA(t)
	key, crt := ca.issue(t, "jm24")
	base := testLinkMetricClaim("jm24", "gz02", now)

	duplicate := base
	duplicate.Metrics = append([]LinkMetric(nil), base.Metrics...)
	duplicate.Metrics = append(duplicate.Metrics, duplicate.Metrics[0])
	if _, err := SignLinkMetric(duplicate, key, crt); err == nil ||
		!strings.Contains(err.Error(), "重复") {
		t.Fatalf("重复 peer 未被拒绝:%v", err)
	}

	for name, mutate := range map[string]func(*LinkMetric){
		"self peer":            func(m *LinkMetric) { m.PeerNode = "jm24" },
		"transport":            func(m *LinkMetric) { m.Transport = "wireguard" },
		"scope":                func(m *LinkMetric) { m.Scope = "full_path" },
		"carrier":              func(m *LinkMetric) { m.Carrier = "wireguard" },
		"observed time":        func(m *LinkMetric) { m.ObservedAt = "not-a-time" },
		"negative rtt":         func(m *LinkMetric) { m.RTTMS = -1 },
		"excessive p95":        func(m *LinkMetric) { m.P95MS = LinkMetricMaxRTTMS + 1 },
		"reversed percentiles": func(m *LinkMetric) { m.P50MS, m.P95MS = 12, 11 },
		"zero samples":         func(m *LinkMetric) { m.Samples = 0 },
		"too many failures":    func(m *LinkMetric) { m.Failures = m.Samples + 1 },
		"negative bytes":       func(m *LinkMetric) { m.TransferBytes = -1 },
		"unpaired transfer":    func(m *LinkMetric) { m.TransferDurationMS = 0 },
		"oversized duration":   func(m *LinkMetric) { m.TransferDurationMS = LinkMetricMaxTransferDurationMS + 1 },
		"control error":        func(m *LinkMetric) { m.Error = "bad\nerror" },
		"oversized error":      func(m *LinkMetric) { m.Error = strings.Repeat("x", LinkMetricMaxErrorSize+1) },
	} {
		t.Run(name, func(t *testing.T) {
			claim := base
			claim.Metrics = append([]LinkMetric(nil), base.Metrics...)
			mutate(&claim.Metrics[0])
			if _, err := SignLinkMetric(claim, key, crt); err == nil {
				t.Fatal("invalid link metric was signed")
			}
		})
	}

	allFailed := base
	allFailed.Metrics = append([]LinkMetric(nil), base.Metrics...)
	m := &allFailed.Metrics[0]
	m.Failures, m.RTTMS, m.P50MS, m.P95MS = m.Samples, 0, 0, 0
	m.TransferBytes, m.TransferDurationMS, m.Error = 0, 0, ""
	if _, err := SignLinkMetric(allFailed, key, crt); err == nil ||
		!strings.Contains(err.Error(), "没有 error") {
		t.Fatalf("无错误原因的全失败度量被接受:%v", err)
	}

	tooMany := base
	tooMany.Metrics = make([]LinkMetric, LinkMetricMaxMetrics+1)
	for i := range tooMany.Metrics {
		tooMany.Metrics[i] = base.Metrics[0]
		tooMany.Metrics[i].PeerNode = fmt.Sprintf("p%d", i)
	}
	if _, err := SignLinkMetric(tooMany, key, crt); err == nil ||
		!strings.Contains(err.Error(), "过多") {
		t.Fatalf("过多 metrics 被接受:%v", err)
	}
}

func TestLinkMetricCanonicalSortAndV5Independence(t *testing.T) {
	ts := "2026-08-28T12:00:00Z"
	a := testLinkMetricClaim("jm24", "hz01", ts)
	second := a.Metrics[0]
	second.PeerNode = "gz02"
	a.Metrics = append(a.Metrics, second)
	b := a
	b.Metrics = []LinkMetric{a.Metrics[1], a.Metrics[0]}
	if string(a.canonical()) != string(b.canonical()) {
		t.Fatal("同一组有向 metrics 的输入顺序改变了 canonical")
	}

	v5 := Claim{
		CanonicalVersion: 5, Node: "gz02", TS: ts, Commit: "abc", Binary: "def", Applied: "snap",
		Components:         []ComponentClaim{{Name: "wireguard", Expected: "2", Actual: "2"}},
		MeasurementsSHA256: strings.Repeat("a", 64),
	}
	before := string(v5.canonical())
	_ = a.canonical()
	if after := string(v5.canonical()); after != before {
		t.Fatal("构造 link metric 改变了 loom-attest canonical bytes")
	}
	sum := sha256.Sum256(v5.canonical())
	if got, want := hex.EncodeToString(sum[:]), "4e3634054e55a1ca2174a055f3fee3761bdb81134065b6fed510a49f06285a4b"; got != want {
		t.Fatalf("loom-attest-v5 canonical drifted: %s != %s", got, want)
	}
}
