package report

import (
	"strings"
	"testing"
	"time"

	"loom/internal/attest"
)

func TestLinkMetricHistoryUsesFifteenMinutePercentilesAndMedianRawRatePair(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	h := newHistory()
	for _, sample := range []linkProbeSample{
		// This would dominate every aggregate if the 15-minute boundary leaked.
		{at: now.Add(-16 * time.Minute), rttMS: 999, bytes: 999_000, durationMS: 1},
		{at: now.Add(-14 * time.Minute), rttMS: 100, bytes: 1_000, durationMS: 100}, // 10 B/ms
		{at: now.Add(-10 * time.Minute), rttMS: 300, bytes: 9_000, durationMS: 300}, // 30 B/ms
		{at: now.Add(-5 * time.Minute), err: "timeout"},
		{at: now.Add(-time.Minute), rttMS: 200, bytes: 2_000, durationMS: 100}, // median: 20 B/ms
	} {
		h.addLinkProbe("demo-b", sample)
	}

	got, ok := h.linkMetric("demo-b", attest.LinkMetricTransportHysteria2,
		attest.LinkMetricCarrierPublic, now)
	if !ok {
		t.Fatal("15 分钟内有探测样本却没有生成链路度量")
	}
	if got.P50MS != 200 || got.P95MS != 300 || got.RTTMS != 200 {
		t.Fatalf("15 分钟 P50/P95 统计错误: %+v", got)
	}
	if got.Samples != 4 || got.Failures != 1 {
		t.Fatalf("过期样本混入或失败样本丢失: %+v", got)
	}
	// The signed contract carries a real numerator/denominator pair.  It must
	// not synthesize rounded bytes or duration from the median rate.
	if got.TransferBytes != 2_000 || got.TransferDurationMS != 100 {
		t.Fatalf("中位速率没有保留对应原始 bytes/duration 对: %+v", got)
	}
}

func TestLinkMetricAttachmentBindsOuterNodeAndTimestamp(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ts := now.Format(time.RFC3339)
	caPEM, keyPEM, certPEM := reportTestIdentity(t, "demo-d")
	signed, err := attest.SignLinkMetric(attest.LinkMetricClaim{
		Version: attest.LinkMetricClaimVersion, Node: "demo-d", TS: ts,
		Metrics: []attest.LinkMetric{{
			PeerNode: "demo-b", Transport: attest.LinkMetricTransportHysteria2,
			Scope: attest.LinkMetricScopeSingleHop, Carrier: attest.LinkMetricCarrierPublic,
			ObservedAt: ts, RTTMS: 20, P50MS: 20, P95MS: 24,
			Samples: 3, TransferBytes: 64 << 10, TransferDurationMS: 30,
		}},
	}, keyPEM, certPEM)
	if err != nil {
		t.Fatal(err)
	}
	base := Observation{Node: "demo-d", TS: ts, LinkMetrics: signed}
	if _, err := verifyLinkMetricAttachment(&base, caPEM, now, time.Minute); err != nil {
		t.Fatalf("相同外层 node/ts 的有效附件绑定失败: %v", err)
	}

	for name, mutate := range map[string]func(*Observation){
		"node": func(o *Observation) { o.Node = "demo-c" },
		"timestamp": func(o *Observation) {
			o.TS = now.Add(time.Second).Format(time.RFC3339)
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := base
			mutate(&o)
			if _, err := verifyLinkMetricAttachment(&o, caPEM, now, time.Minute); err == nil ||
				!strings.Contains(err.Error(), "不一致") {
				t.Fatalf("有效签名附件被移到不同外层 %s 后仍通过绑定: %v", name, err)
			}
		})
	}
}
