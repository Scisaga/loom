package report

import (
	"strings"
	"testing"
	"time"

	"loom/internal/webui"
)

func TestBuildViewKeepsSilentExpectedTopologyUnknown(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	cfg := &Config{
		Node: "a", ExpectedNodes: []string{"a", "b", "c"},
		ExpectedTunnels: []ExpectedTunnel{{From: "b", To: "c"}},
	}
	v := buildView(cfg, &Status{Node: "a", TS: now.Format(time.RFC3339), Applied: "snap"}, now)
	if len(v.Nodes) != 3 {
		t.Fatalf("完全静默节点从拓扑消失了:%+v", v.Nodes)
	}
	byID := map[string]string{}
	for _, n := range v.Nodes {
		byID[n.ID] = n.Health
		if n.IngressKnown {
			t.Fatalf("reduced node report invented current-SSOT ingress metadata for %s", n.ID)
		}
	}
	if byID["a"] != "healthy" || byID["b"] != "unknown" || byID["c"] != "unknown" {
		t.Fatalf("节点三态不真实:%v", byID)
	}
	if len(v.Links) != 1 || v.Links[0].Kind != "tunnel" || v.Links[0].State != "unknown" {
		t.Fatalf("无观测 SSOT 隧道没有保持 unknown:%+v", v.Links)
	}
}

func TestBuildViewDerivesDynamicEdgeOnlyFromFreshActualRoute(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	cfg := &Config{Node: "a", ExpectedNodes: []string{"a", "b", "c"},
		ExpectedTunnels: []ExpectedTunnel{{From: "b", To: "c"}},
		ExpectedRoutes: []ExpectedRoute{
			{Access: "a", Declaration: "fresh", Chain: []string{"b"}},
			{Access: "a", Declaration: "fresh", Chain: []string{"b", "c"}},
		}}
	st := &Status{Node: "a", TS: now.Format(time.RFC3339), Agent: &AgentState{
		Node: "a", TS: now.Format(time.RFC3339), Selections: []AgentSelection{
			{Declaration: "fresh", Selector: "svc:fresh", Candidate: "opaque", Chain: []string{"b"}, UpdatedAt: now.Format(time.RFC3339)},
			{Declaration: "stale", Selector: "svc:stale", Candidate: "opaque2", Chain: []string{"c"}, UpdatedAt: now.Add(-time.Hour).Format(time.RFC3339)},
		},
	}}
	v := buildView(cfg, st, now)
	var candidate int
	for _, l := range v.Links {
		if l.Kind == "candidate" {
			candidate++
			if l.From != "a" || l.To != "b" || l.State != "unverified" || l.Source == "" {
				t.Fatalf("候选跳信息不完整或被冒充在线:%+v", l)
			}
		}
	}
	if candidate != 1 {
		t.Fatalf("候选非 WG hop 聚合不对:%+v", v.Links)
	}
	selected, unverified := 0, 0
	for _, p := range v.Candidates {
		switch p.State {
		case "selected":
			selected++
			if len(p.Chain) != 2 || p.Chain[0] != "a" || p.Chain[1] != "b" {
				t.Fatalf("当前选择没有叠到对应候选:%+v", p)
			}
		case "unverified":
			unverified++
		}
	}
	if selected != 1 || unverified != 1 {
		t.Fatalf("候选路径状态没有区分声明与实读:%+v", v.Candidates)
	}
}

func TestUnsignedRelayedNodeIsUnknownNotHealthy(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	v := buildView(&Config{Node: "a"}, &Status{Node: "a", TS: now.Format(time.RFC3339),
		Learned: []Observation{{Node: "b", TS: now.Format(time.RFC3339), Applied: "snap"}}}, now)
	for _, n := range v.Nodes {
		if n.ID == "b" {
			if n.Health != "unknown" {
				t.Fatalf("未签名转述被冒充健康:%+v", n)
			}
			if n.Applied != "" {
				t.Fatalf("未签名 Applied 进入了全网快照判定:%+v", n)
			}
		}
	}
}

func TestLegacySignedAppliedIsTrustedButMeasurementsAreNot(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	o := &Observation{Node: "b", TS: now.Format(time.RFC3339), Applied: "outer",
		Targets: []Reach{{Target: "https://forged.test", Error: "forged"}}}
	n := nodeView("b", false, false, nil, o, &AttestedState{Applied: "signed"}, "", now)
	if n.Applied != "signed" {
		t.Fatalf("legacy signed Applied did not come from trusted claim: %+v", n)
	}
	if len(n.Targets) != 0 {
		t.Fatalf("legacy signature authorized mutable measurements: %+v", n.Targets)
	}
}

func TestTrustedRelayedMeasurementsWithoutSelfCheckRemainUnknown(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	view := func(uplink bool) webui.NodeView {
		o := &Observation{Node: "b", TS: now.Format(time.RFC3339), Targets: []Reach{{
			Target: "https://probe.test", Samples: 5, Failures: 5, Error: "timeout", Uplink: uplink,
		}}}
		return nodeView("b", false, false, nil, o,
			&AttestedState{MeasurementsVerified: true}, "", now)
	}
	if n := view(true); n.Health != "unknown" || len(n.Problems) != 0 {
		t.Fatalf("partial signed measurements were mistaken for a complete health verdict: %+v", n)
	}
	if n := view(false); n.Health != "unknown" || len(n.Problems) != 0 {
		t.Fatalf("ordinary pruning Target was promoted to node fault: %+v", n)
	}
}

func TestUnexpectedObservationCannotCreateWGCarrierEdge(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	cfg := &Config{
		Node: "a", ExpectedNodes: []string{"a", "b", "c"},
		ExpectedTunnels: []ExpectedTunnel{{From: "b", To: "c"}},
	}
	st := &Status{
		Node: "a", TS: now.Format(time.RFC3339),
		Learned: []Observation{{
			Node: "b", TS: now.Format(time.RFC3339),
			Edges: []Edge{{To: "a", RTTMs: 7}},
		}},
	}
	v := buildView(cfg, st, now)
	if len(v.Links) != 1 {
		t.Fatalf("陌生观测边创建了承载拓扑:%+v", v.Links)
	}
	got := v.Links[0]
	if got.From != "b" || got.To != "c" || got.Kind != "tunnel" || got.State != "unknown" {
		t.Fatalf("SSOT 承载底图被陌生观测改写:%+v", got)
	}
}

func TestSignedDirectMetricOnlyUpgradesExactExpectedDirection(t *testing.T) {
	cfg := &Config{
		ExpectedDirectLinks: []ExpectedDirectLink{{
			From: "a", To: "b", Transport: "hysteria2", Carrier: "public",
		}},
	}
	metric := func(peer string) webui.VerifiedLinkMetricView {
		return webui.VerifiedLinkMetricView{
			PeerNode: peer, Transport: "hysteria2", Carrier: "public",
			ObservedAt: "2026-08-29T12:00:00Z", RTTMS: 21, P50MS: 21, P95MS: 25,
			Samples: 3, TransferBytes: 64 << 10, DurationMS: 20,
		}
	}

	// These values have already crossed the signature verification boundary,
	// but a valid signature still must not grant topology authority.
	links := topologyLinks(cfg, []webui.NodeView{
		{ID: "b", VerifiedLinkMetrics: []webui.VerifiedLinkMetricView{metric("a")}}, // reverse direction
		{ID: "a", VerifiedLinkMetrics: []webui.VerifiedLinkMetricView{metric("c")}}, // undeclared peer
	})
	if len(links) != 1 || links[0].From != "a" || links[0].To != "b" ||
		links[0].Kind != "direct-hy2" || links[0].State != "unknown" {
		t.Fatalf("反向或陌生的已验签度量改写/创建了拓扑边: %+v", links)
	}

	links = topologyLinks(cfg, []webui.NodeView{{
		ID: "a", VerifiedLinkMetrics: []webui.VerifiedLinkMetricView{metric("b")},
	}})
	if len(links) != 1 || links[0].State != "active" ||
		links[0].ObservedFrom != "a" || links[0].ObservedTo != "b" || links[0].MS != 21 {
		t.Fatalf("精确匹配 ExpectedDirectLinks 的方向没有升级底图: %+v", links)
	}
}

func TestDomesticTopologyLayerKeepsCandidatePathsWithoutDirectWG(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	cfg := &Config{
		Node: "jm24", ExpectedNodes: []string{"jm24", "gz02", "hz01"},
		ExpectedRoutes: []ExpectedRoute{
			{Access: "jm24", Declaration: "best", Chain: []string{"gz02"}},
			{Access: "jm24", Declaration: "best", Chain: []string{"hz01"}},
			{Access: "jm24", Declaration: "best", Chain: []string{"gz02", "hz01"}},
			{Access: "jm24", Declaration: "best", Chain: []string{"hz01", "gz02"}},
		},
	}
	v := buildView(cfg, &Status{Node: "jm24", TS: now.Format(time.RFC3339)}, now)
	want := map[string]bool{"gz02\x00hz01": true, "gz02\x00jm24": true, "hz01\x00jm24": true}
	for _, l := range v.Links {
		if l.Kind != "candidate" || l.State != "unverified" {
			continue
		}
		delete(want, l.From+"\x00"+l.To)
	}
	if len(want) != 0 {
		t.Fatalf("同一拓扑层缺候选路径边 %v；没有常驻 WG 不能等价成没有路径，got=%+v", want, v.Links)
	}
}

func TestRelayedEdgesNeedMeasurementAttestationAndSamples(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	cfg := &Config{Node: "a", ExpectedNodes: []string{"a", "b"},
		ExpectedTunnels: []ExpectedTunnel{{From: "a", To: "b"}}}
	unsigned := &Status{Node: "a", TS: now.Format(time.RFC3339), Learned: []Observation{{
		Node: "b", TS: now.Format(time.RFC3339), Edges: []Edge{{To: "a", RTTMs: 1, Samples: 5}},
	}}}
	v := buildView(cfg, unsigned, now)
	if len(v.Links) != 1 || v.Links[0].State != "unknown" {
		t.Fatalf("未签名 relay 把 WG 边假绿:%+v", v.Links)
	}

	// Even locally trusted data needs a real sample. Empty Error alone is not
	// evidence of health.
	zero := &Status{Node: "a", TS: now.Format(time.RFC3339), Observation: &Observation{
		Node: "a", TS: now.Format(time.RFC3339), Edges: []Edge{{To: "b", RTTMs: 1}},
	}}
	v = buildView(cfg, zero, now)
	if v.Links[0].State != "unknown" {
		t.Fatalf("零样本观测把 WG 边假绿:%+v", v.Links)
	}
}

func TestCarrierEdgeDistinguishesPartialFromCompleteFailure(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	cfg := &Config{Node: "a", ExpectedNodes: []string{"a", "b"},
		ExpectedTunnels: []ExpectedTunnel{{From: "a", To: "b"}}}
	viewFor := func(failures int) string {
		st := &Status{Node: "a", TS: now.Format(time.RFC3339), Observation: &Observation{
			Node: "a", TS: now.Format(time.RFC3339),
			Edges: []Edge{{To: "b", RTTMs: 10, Samples: 5, Failures: failures, Error: "timeout"}},
		}}
		return buildView(cfg, st, now).Links[0].State
	}
	if got := viewFor(0); got != "active" {
		t.Fatalf("0/5 失败状态=%s, want active", got)
	}
	if got := viewFor(4); got != "degraded" {
		t.Fatalf("4/5 失败仍被画成 %s, want degraded", got)
	}
	if got := viewFor(5); got != "failed" {
		t.Fatalf("5/5 失败状态=%s, want failed", got)
	}
}

func TestCarrierEvidenceKeepsSourceRTTAndTimeFromOneSample(t *testing.T) {
	old := "2026-08-26T11:55:00Z"
	fresh := "2026-08-26T12:00:00Z"
	cfg := &Config{ExpectedTunnels: []ExpectedTunnel{{From: "a", To: "b"}}}
	links := topologyLinks(cfg, []webui.NodeView{
		{ID: "a", Edges: []webui.EdgeView{{To: "b", MS: 100, Samples: 5, ObservedAt: old}}},
		{ID: "b", Edges: []webui.EdgeView{{To: "a", MS: 20, Samples: 5, ObservedAt: fresh}}},
	})
	if len(links) != 1 {
		t.Fatalf("unexpected links: %+v", links)
	}
	l := links[0]
	if l.MS != 20 || l.ObservedAt != fresh || !strings.HasPrefix(l.Source, "b→a ") {
		t.Fatalf("carrier combined fields from different endpoint samples: %+v", l)
	}

	// Worst state remains pessimistic, but its metadata must remain the failed
	// observation's metadata rather than borrowing a fresher healthy timestamp.
	links = topologyLinks(cfg, []webui.NodeView{
		{ID: "a", Edges: []webui.EdgeView{{To: "b", Samples: 5, Failures: 5, Err: "down", ObservedAt: old}}},
		{ID: "b", Edges: []webui.EdgeView{{To: "a", MS: 20, Samples: 5, ObservedAt: fresh}}},
	})
	l = links[0]
	if l.State != "failed" || l.ObservedAt != old || !strings.HasPrefix(l.Source, "a→b ") {
		t.Fatalf("worst carrier state borrowed another sample's time/source: %+v", l)
	}
}

func TestMeasurementTimestampIsIndependentFromFreshStatusTimestamp(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	measuredAt := now.Add(-7 * time.Minute).Format(time.RFC3339)
	statusAt := now.Format(time.RFC3339)
	cfg := &Config{Node: "a", ExpectedNodes: []string{"a", "b"},
		ExpectedTunnels: []ExpectedTunnel{{From: "a", To: "b"}}}
	st := &Status{Node: "a", TS: statusAt, Observation: &Observation{
		Node: "a", TS: measuredAt,
		Edges:   []Edge{{To: "b", RTTMs: 12, Samples: 5}},
		Targets: []Reach{{Target: "https://example.test/", FirstByteMs: 20, Samples: 5}},
	}}
	v := buildView(cfg, st, now)
	if len(v.Links) != 1 || v.Links[0].ObservedAt != measuredAt {
		t.Fatalf("边时间被新鲜 Status.TS 假刷新: links=%+v", v.Links)
	}
	var selfFound bool
	for _, n := range v.Nodes {
		if n.ID != "a" {
			continue
		}
		selfFound = true
		if n.ObservedAt != statusAt {
			t.Fatalf("节点状态时间=%q, want fresh status %q", n.ObservedAt, statusAt)
		}
		if len(n.Edges) != 1 || n.Edges[0].ObservedAt != measuredAt {
			t.Fatalf("边没有保留 Observation.TS: %+v", n.Edges)
		}
		if len(n.Targets) != 1 || n.Targets[0].ObservedAt != measuredAt {
			t.Fatalf("目标没有保留 Observation.TS: %+v", n.Targets)
		}
	}
	if !selfFound {
		t.Fatal("view 缺本机节点")
	}
}
