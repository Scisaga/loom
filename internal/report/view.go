package report

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"loom/internal/attest"
	"loom/internal/version"
	"loom/internal/webui"
)

// buildView 把 /status 的同一份 Status 变成界面视图。这里不重新探测网络，
// 也不从事件历史猜当前路径；版本、rollout、Agent 选择都来自 Status 或已验签
// 的 Observation。
func buildView(cfg *Config, self *Status, now time.Time) webui.View {
	return buildViewWithCA(cfg, self, now, os.ReadFile)
}

// buildViewWithCA keeps CA loading injectable for end-to-end trust tests. The
// production wrapper always supplies os.ReadFile.
func buildViewWithCA(cfg *Config, self *Status, now time.Time,
	readCA func(string) ([]byte, error)) webui.View {
	now = now.UTC()
	v := webui.View{
		Self: cfg.Node, Applied: self.Applied, ObservedAt: now.Format(time.RFC3339),
		IntentSource: "serving node applied inventory",
	}
	attestationAge, err := cfg.ObsStale()
	if err != nil {
		attestationAge = AttestationMaxAge
		v.Warnings = append(v.Warnings, "observation_stale 无法解析，验签新鲜度回退到 "+AttestationMaxAge.String()+":"+err.Error())
	}
	var ca []byte
	var caErr error
	caLoaded := false
	loadCA := func() {
		if !caLoaded {
			ca, caErr = readCA(caPath)
			caLoaded = true
		}
	}
	verifyTraffic := func(o *Observation) (*attest.TrafficClaim, string) {
		if o == nil || o.Traffic == nil {
			return nil, ""
		}
		loadCA()
		if caErr != nil {
			return nil, "读签名 CA:" + caErr.Error()
		}
		claim, err := verifyTrafficAttachment(o, ca, now, attestationAge)
		if err != nil {
			return nil, err.Error()
		}
		return claim, ""
	}
	verifyLinkMetrics := func(o *Observation) (*attest.LinkMetricClaim, string) {
		if o == nil || o.LinkMetrics == nil {
			return nil, ""
		}
		loadCA()
		if caErr != nil {
			return nil, "读签名 CA:" + caErr.Error()
		}
		claim, err := verifyLinkMetricAttachment(o, ca, now, attestationAge)
		if err != nil {
			return nil, err.Error()
		}
		return claim, ""
	}
	verifySelfCheck := func(o *Observation) (*attest.SelfCheckClaim, string) {
		if o == nil || o.SelfCheck == nil {
			return nil, ""
		}
		loadCA()
		if caErr != nil {
			return nil, "读签名 CA:" + caErr.Error()
		}
		claim, err := verifySelfCheckAttachment(o, ca, now, attestationAge)
		if err != nil {
			return nil, err.Error()
		}
		return claim, ""
	}
	declared := make(map[string]bool, len(cfg.ExpectedNodes))
	for _, id := range cfg.ExpectedNodes {
		if id != "" {
			declared[id] = true
		}
	}
	byNode := map[string]webui.NodeView{}
	local := nodeView(cfg.Node, true, true, self, self.Observation, nil, "", now)
	local.Declared = declared[cfg.Node]
	localTraffic, localTrafficErr := verifyTraffic(self.Observation)
	applyTrafficClaim(&local, localTraffic, localTrafficErr, now, false)
	localLinkMetrics, localLinkMetricsErr := verifyLinkMetrics(self.Observation)
	applyLinkMetricClaim(&local, localLinkMetrics, localLinkMetricsErr)
	byNode[cfg.Node] = local

	for i := range self.Learned {
		o := &self.Learned[i]
		var trusted *AttestedState
		identityErr := ""
		if observationNeedsVerification(o, cfg.AttestationMinVersion) {
			loadCA()
			if caErr != nil {
				identityErr = "读签名 CA:" + caErr.Error()
			} else if got, err := VerifyObservationAtLeast(o, ca, now, attestationAge,
				cfg.AttestationMinVersion); err != nil {
				identityErr = err.Error()
			} else {
				trusted = got
			}
		}
		if o.Node == "" || o.Node == cfg.Node {
			continue
		}
		node := nodeView(o.Node, false, false, nil, o, trusted, identityErr, now)
		node.Declared = declared[o.Node]
		selfCheck, selfCheckErr := verifySelfCheck(o)
		applySelfCheckClaim(&node, selfCheck, selfCheckErr)
		traffic, trafficErr := verifyTraffic(o)
		applyTrafficClaim(&node, traffic, trafficErr, now, true)
		linkMetrics, linkMetricsErr := verifyLinkMetrics(o)
		applyLinkMetricClaim(&node, linkMetrics, linkMetricsErr)
		byNode[o.Node] = node
	}
	for _, id := range cfg.ExpectedNodes {
		if id == "" {
			continue
		}
		if _, ok := byNode[id]; !ok {
			byNode[id] = webui.NodeView{
				ID: id, Declared: true, Health: "unknown", Source: "SSOT 期望 · 未收到观测",
			}
		}
	}
	for _, n := range byNode {
		v.Nodes = append(v.Nodes, n)
	}
	sort.Slice(v.Nodes, func(i, j int) bool { return v.Nodes[i].ID < v.Nodes[j].ID })

	for i := range v.Nodes {
		if v.Nodes[i].Agent != nil {
			v.Routes = append(v.Routes, v.Nodes[i].Agent.Selections...)
		}
	}
	sort.Slice(v.Routes, func(i, j int) bool {
		if v.Routes[i].Node != v.Routes[j].Node {
			return v.Routes[i].Node < v.Routes[j].Node
		}
		return v.Routes[i].Declaration < v.Routes[j].Declaration
	})
	v.Candidates = candidatePaths(cfg, v.Routes)
	v.Links = topologyLinks(cfg, v.Nodes)

	if self.Publisher != nil {
		p := self.Publisher
		v.Publisher = &webui.PublisherView{
			PID: p.PID, IntervalSeconds: p.IntervalSeconds,
			Commit: p.Version.Commit, Binary: p.Version.Binary,
			StartedAt: p.StartedAt, UpdatedAt: p.UpdatedAt,
			LastSuccess: p.LastSuccess, LastSnapshot: p.LastSnapshot, LastSSOT: p.LastSSOT,
			LastError: p.LastError, LastErrorAt: p.LastErrorAt,
			Healthy: !p.Unhealthy(now),
		}
	}
	if len(self.Learned) == 0 && len(cfg.Neighbors) > 0 {
		v.Warnings = append(v.Warnings,
			"只听到本机的观测。转述链可能断了，或者邻居的上报者没跑")
	}
	return v
}

func candidatePaths(cfg *Config, routes []webui.RouteView) []webui.CandidatePathView {
	selected := map[string]webui.RouteView{}
	keyFor := func(node, declaration string, chain []string) string {
		return node + "\x00" + declaration + "\x00" + strings.Join(chain, "\x00")
	}
	for _, r := range routes {
		if r.Stale {
			continue
		}
		// RouteView.Chain 含接入节点这个隐式起点；ExpectedRoute.Chain 不含。
		chain := r.Chain
		if len(chain) > 0 && chain[0] == r.Node {
			chain = chain[1:]
		}
		selected[keyFor(r.Node, r.Declaration, chain)] = r
	}
	seen := map[string]bool{}
	var out []webui.CandidatePathView
	for _, e := range cfg.ExpectedRoutes {
		chain := append([]string{e.Access}, e.Chain...)
		key := keyFor(e.Access, e.Declaration, e.Chain)
		p := webui.CandidatePathView{
			Node: e.Access, Declaration: e.Declaration, Chain: chain,
			State: "unverified", Source: "SSOT RouteCandidate.ServerChain · 未实时核验",
		}
		if r, ok := selected[key]; ok {
			p.State, p.ObservedAt = "selected", r.ObservedAt
			p.Source = r.Source + " · 当前选中"
			p.ScopeKind, p.ScopeID, p.PolicyID = r.ScopeKind, r.ScopeID, r.PolicyID
		}
		seen[key] = true
		out = append(out, p)
	}
	// 配置/运行态短暂漂移时，实际 selector 值仍必须显示，不能因新配置尚未
	// 带上候选表而从中控消失。
	for key, r := range selected {
		if seen[key] {
			continue
		}
		out = append(out, webui.CandidatePathView{
			Node: r.Node, Declaration: r.Declaration, Chain: append([]string(nil), r.Chain...),
			ScopeKind: r.ScopeKind, ScopeID: r.ScopeID, PolicyID: r.PolicyID,
			State: "selected", ObservedAt: r.ObservedAt,
			Source: r.Source + " · 当前选中（不在本机 expected_routes）",
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a := out[i].Node + "\x00" + out[i].Declaration + "\x00" + strings.Join(out[i].Chain, "\x00")
		b := out[j].Node + "\x00" + out[j].Declaration + "\x00" + strings.Join(out[j].Chain, "\x00")
		return a < b
	})
	return out
}

func nodeView(id string, self, reached bool, st *Status, o *Observation,
	trusted *AttestedState, identityErr string, now time.Time) webui.NodeView {

	n := webui.NodeView{ID: id, Health: "unknown", Self: self, Reached: reached, IdentityError: identityErr}
	if reached {
		n.Source = "直连 /status"
	} else if trusted != nil {
		n.Source = "签名转述"
	} else {
		n.Source = "未签名转述"
	}
	if identityErr != "" {
		n.Health = "problem"
		n.Source = "无效签名转述"
		n.Problems = append(n.Problems, "签名陈述无效:"+identityErr)
		// 身份绑定失败后不能再把边挂到这个 Node 上。
		o = nil
	}
	if o != nil {
		n.AgeSec = int(o.Age(now).Seconds())
		n.ObservedAt = o.TS
		// Applied is node-owned state.  A relayed legacy observation may remain
		// visible as unknown, but its mutable outer field must not participate in
		// the all-network snapshot verdict.  Every signed claim version binds
		// Applied; measurement v3 is required only for Edges/Targets.
		if reached {
			n.Applied = o.Applied
		} else if trusted != nil {
			n.Applied = trusted.Applied
		}
		// Self is collected locally. Relayed measurements are usable only when a
		// v3 node-owned claim binds them; a valid legacy identity signature does
		// not authorize mutable outer Edges/Targets.
		if reached || (trusted != nil && trusted.MeasurementsVerified) {
			for _, e := range o.Edges {
				n.Edges = append(n.Edges, webui.EdgeView{
					To: e.To, MS: e.RTTMs, Samples: e.Samples,
					Failures: e.Failures, Err: e.Error, ObservedAt: o.TS,
				})
			}
			for _, r := range o.Targets {
				n.Targets = append(n.Targets, webui.TargetView{
					Target: r.Target, MS: r.FirstByteMs, Err: r.Error,
					ObservedAt: o.TS, Uplink: r.Uplink})
			}
		}
	}
	if trusted != nil {
		n.Version = versionView(trusted.Version)
		n.Rollout = rolloutView(trusted.Rollout, now)
		n.Agent = agentView(trusted.Agent, "签名转述", now)
		n.Components = componentViews(trusted.Components)
	}
	if st == nil {
		// A remote Observation, even with signed individual fields, is not a
		// complete Status verdict. Health remains unknown until the independent
		// self-check attachment is verified and applied by buildView.
		return n
	}
	if st.OKAt(now) {
		n.Health = "healthy"
	} else {
		n.Health = "problem"
	}

	if st.TS != "" {
		n.ObservedAt = st.TS
	}
	if st.Applied != "" {
		n.Applied = st.Applied
	}
	n.Version = versionView(st.Version)
	n.Rollout = rolloutView(st.Rollout, now)
	n.Agent = agentView(st.Agent, "直连 /status", now)
	n.Components = componentViews(st.Components)
	n.Rotating = append(n.Rotating, st.Rotating...)
	for i := range st.Tunnels {
		t := &st.Tunnels[i]
		peerNode := trafficPeerNode(t.Interface)
		tv := webui.TunnelView{
			Interface: t.Interface, CarrierPresent: true, State: t.UnitState,
			AgeSec: int(t.HandshakeAgeSec), RxBytes: t.RxByt, TxBytes: t.TxByt,
			PeerNode: peerNode, CounterObservedAt: st.TS,
			CounterSource: "direct /status", CounterPresent: t.PeerPresent,
			TrafficTrusted: t.PeerPresent,
			OK:             !t.Down && !t.Stale && t.HandshakeAgeSec >= 0,
		}
		if peerNode != "" {
			tv.LinkID = attest.CanonicalTrafficLinkID(id, peerNode)
		}
		switch {
		case t.Down:
			tv.State = "down"
		case t.HandshakeAgeSec < 0:
			tv.State = "未握手"
		}
		if tv.State != "" && tv.State != "active" && tv.State != "down" && tv.State != "未握手" {
			tv.OK = false
		}
		n.Tunnels = append(n.Tunnels, tv)
	}
	for i := range n.Tunnels {
		if n.Tunnels[i].CounterPresent {
			n.TrafficTrusted = true
			n.TrafficObservedAt = st.TS
			break
		}
	}
	if d := st.Drift; d != nil {
		for _, f := range d.Modified {
			n.Problems = append(n.Problems, "配置被改过:"+f)
		}
		for _, f := range d.Missing {
			n.Problems = append(n.Problems, "配置缺失:"+f)
		}
		for _, f := range d.Unreadable {
			n.Problems = append(n.Problems, "配置读不到:"+f)
		}
	}
	for _, component := range st.Components {
		if !component.OK() {
			n.Problems = append(n.Problems, componentProblem(component))
		}
	}
	n.Problems = append(n.Problems, agentHealthProblems(st.Agent)...)
	n.Problems = append(n.Problems, st.Errors...)
	return n
}

// applySelfCheckClaim is the only remote-health mapping boundary. Missing
// attachments intentionally leave health unknown. Explicit signed healthy is
// accepted only with an empty problem list (also enforced by attest); explicit
// unhealthy always produces problem with the node-owned explanations.
func applySelfCheckClaim(n *webui.NodeView, claim *attest.SelfCheckClaim,
	verificationError string) {
	if n == nil {
		return
	}
	if verificationError != "" {
		n.Health = "problem"
		n.Problems = append(n.Problems, "自检签名陈述无效:"+verificationError)
		return
	}
	if claim == nil {
		return
	}
	if claim.Healthy && len(claim.Problems) == 0 {
		if n.Health != "problem" {
			n.Health = "healthy"
		}
		if n.Source == "未签名转述" {
			n.Source = "签名健康转述"
		}
		return
	}
	n.Health = "problem"
	n.Problems = append(n.Problems, claim.Problems...)
	if n.Source == "未签名转述" {
		n.Source = "签名健康转述"
	}
}

// applyTrafficClaim is the only remote-counter mapping boundary. Callers pass
// a claim only after verifying the independent traffic signature and binding
// its Node/TS to the outer Observation. Invalid or unsigned data never reaches
// TunnelView, so later storage/UI code can trust TrafficTrusted rather than
// reinterpreting raw gossip JSON.
func applyTrafficClaim(n *webui.NodeView, claim *attest.TrafficClaim,
	verificationError string, now time.Time, mapAsCurrent bool) {
	if n == nil {
		return
	}
	if verificationError != "" {
		n.Health = "problem"
		n.Problems = append(n.Problems, "流量签名陈述无效:"+verificationError)
		return
	}
	if claim == nil {
		return
	}
	n.TrafficVerified = true
	if mapAsCurrent {
		n.TrafficTrusted = true
		n.TrafficObservedAt = claim.TS
	}
	age := 0
	if observed, err := time.Parse(time.RFC3339, claim.TS); err == nil {
		age = int(now.UTC().Sub(observed.UTC()).Seconds())
		if age < 0 {
			age = 0
		}
	}
	for _, counter := range claim.Counters {
		n.VerifiedTraffic = append(n.VerifiedTraffic, webui.VerifiedTrafficCounterView{
			Interface: counter.Interface, PeerNode: counter.PeerNode,
			LinkID: counter.LinkID, PeerPublicKey: counter.PeerPublicKey,
			CounterEpoch: counter.CounterEpoch, ObservedAt: claim.TS,
			RXBytes: counter.RXBytes, TXBytes: counter.TXBytes,
		})
		if !mapAsCurrent {
			continue
		}
		idx := -1
		for i := range n.Tunnels {
			if n.Tunnels[i].Interface == counter.Interface &&
				(n.Tunnels[i].PeerNode == "" || n.Tunnels[i].PeerNode == counter.PeerNode) {
				idx = i
				break
			}
		}
		if idx < 0 {
			n.Tunnels = append(n.Tunnels, webui.TunnelView{
				Interface: counter.Interface, PeerNode: counter.PeerNode,
				LinkID: counter.LinkID, State: "counter-only", AgeSec: age,
			})
			idx = len(n.Tunnels) - 1
		}
		tunnel := &n.Tunnels[idx]
		tunnel.PeerNode = counter.PeerNode
		tunnel.LinkID = counter.LinkID
		tunnel.PeerPublicKey = counter.PeerPublicKey
		tunnel.CounterEpoch = counter.CounterEpoch
		tunnel.CounterObservedAt = claim.TS
		tunnel.CounterPresent = true
		if n.Self {
			tunnel.CounterSource = "signed self observation"
		} else {
			tunnel.CounterSource = "independently signed relay"
		}
		tunnel.RxBytes = counter.RXBytes
		tunnel.TxBytes = counter.TXBytes
		tunnel.TrafficTrusted = true
		tunnel.TrafficVerified = true
	}
}

// applyLinkMetricClaim is the only mapping boundary for public Hysteria2
// single-hop probes.  The claim has already been independently verified and
// bound to the outer observation; topologyLinks still cross-checks each
// direction against ExpectedDirectLinks before drawing it.
func applyLinkMetricClaim(n *webui.NodeView, claim *attest.LinkMetricClaim,
	verificationError string) {
	if n == nil {
		return
	}
	if verificationError != "" {
		n.Health = "problem"
		n.Problems = append(n.Problems, "Hy2 链路度量签名陈述无效:"+verificationError)
		return
	}
	if claim == nil {
		return
	}
	for _, metric := range claim.Metrics {
		n.VerifiedLinkMetrics = append(n.VerifiedLinkMetrics, webui.VerifiedLinkMetricView{
			PeerNode: metric.PeerNode, ObservedAt: metric.ObservedAt,
			Transport: metric.Transport, Carrier: metric.Carrier,
			RTTMS: int(metric.RTTMS), P50MS: int(metric.P50MS), P95MS: int(metric.P95MS),
			Samples: int(metric.Samples), Failures: int(metric.Failures),
			TransferBytes: metric.TransferBytes, DurationMS: metric.TransferDurationMS,
		})
	}
}

func componentViews(xs []ComponentStatus) []webui.ComponentView {
	out := make([]webui.ComponentView, 0, len(xs))
	for _, c := range xs {
		out = append(out, webui.ComponentView{
			Name: c.Name, Expected: c.Expected, Actual: c.Actual, Error: c.Error, OK: c.OK(),
		})
	}
	return out
}

func trustedComponents(xs []webui.ComponentView) []ComponentStatus {
	out := make([]ComponentStatus, 0, len(xs))
	for _, c := range xs {
		out = append(out, ComponentStatus{
			Name: c.Name, Expected: c.Expected, Actual: c.Actual, Error: c.Error,
		})
	}
	return out
}

func componentProblem(c ComponentStatus) string {
	if c.Error != "" {
		return fmt.Sprintf("组件 %s 无法核对:%s（期望 %s）", c.Name, c.Error, c.Expected)
	}
	return fmt.Sprintf("组件 %s 版本漂移:实际 %s，期望 %s", c.Name, c.Actual, c.Expected)
}

func versionView(c *version.Coordinate) *webui.VersionView {
	if c == nil {
		return nil
	}
	return &webui.VersionView{
		Commit: c.Commit, Binary: c.Binary, Tag: c.Tag, Platform: c.Platform,
		Go: c.Go, Dirty: c.Dirty, Error: c.BinaryErr,
	}
}

func rolloutView(r *RolloutState, now time.Time) *webui.RolloutView {
	if r == nil {
		return nil
	}
	v := &webui.RolloutView{
		Snapshot: r.Snapshot, Stage: r.Stage, EnteredAt: r.EnteredAt,
		LastGood: r.LastGood, Error: r.Error,
	}
	if r.Stage == "failed" {
		v.Problem = true
	}
	if r.InFlight() {
		if d, ok := r.StuckFor(now); ok {
			v.AgeSec = int(d.Seconds())
			v.Stuck = d > RolloutStuckAfter
			v.Problem = v.Stuck
		} else {
			v.Problem, v.Stuck = true, true
		}
	}
	return v
}

func agentView(a *AgentState, source string, now time.Time) *webui.AgentView {
	if a == nil {
		return nil
	}
	v := &webui.AgentView{Node: a.Node, UpdatedAt: a.TS, Source: source}
	for _, s := range a.Selections {
		chain := []string{a.Node}
		chain = append(chain, s.Chain...)
		scopeKind, scopeID, policyID := routeScope(s.Selector)
		r := webui.RouteView{
			Node: a.Node, Declaration: s.Declaration, Selector: s.Selector,
			ScopeKind: scopeKind, ScopeID: scopeID, PolicyID: policyID,
			Candidate: s.Candidate, Chain: chain, Reason: s.Reason,
			ObservedAt: s.UpdatedAt, Source: source + " · sing-box selector",
			Health: agentHealthView(s.Health),
		}
		if t, err := time.Parse(time.RFC3339, s.UpdatedAt); err != nil ||
			now.Sub(t) > AgentStateStaleAfter || now.Sub(t) < -2*time.Minute {
			r.Stale = true
		}
		v.Selections = append(v.Selections, r)
	}
	return v
}

// routeScope 从真实 selector tag 识别选路作用域。AgentState.Declaration 是
// 历史兼容字段：服务 selector 写服务 ID，声明 selector 写策略 ID，单看它
// 无法区分两个命名空间，所以这里绝不猜。
func routeScope(selector string) (kind, id, policyID string) {
	switch {
	case strings.HasPrefix(selector, "svc:") && len(selector) > len("svc:"):
		return webui.ScopeService, strings.TrimPrefix(selector, "svc:"), ""
	case strings.HasPrefix(selector, "decl:") && len(selector) > len("decl:"):
		id = strings.TrimPrefix(selector, "decl:")
		return webui.ScopePolicy, id, id
	default:
		return "", "", ""
	}
}

func agentHealthProblems(a *AgentState) []string {
	if a == nil {
		return nil
	}
	var out []string
	for _, selection := range a.Selections {
		h := selection.Health
		if h != nil && h.Candidates > 0 && h.RecentFailed == h.Candidates {
			out = append(out, fmt.Sprintf("Agent %s 的 %d 个候选近期全部失败",
				selection.Declaration, h.Candidates))
		}
	}
	return out
}

func agentHealthView(h *AgentCandidateHealth) *webui.CandidateHealthView {
	if h == nil {
		return nil
	}
	metric := func(p50, p95, kbps *int) string {
		var parts []string
		if p50 != nil {
			parts = append(parts, fmt.Sprintf("p50 %dms", *p50))
		}
		if p95 != nil {
			parts = append(parts, fmt.Sprintf("p95 %dms", *p95))
		}
		if kbps != nil {
			parts = append(parts, fmt.Sprintf("%d KB/s", *kbps))
		}
		return strings.Join(parts, " · ")
	}
	return &webui.CandidateHealthView{
		Candidates: h.Candidates, RecentSuccess: h.RecentSuccess,
		RecentDegraded: h.RecentDegraded, RecentFailed: h.RecentFailed,
		Stale: h.Stale, Unknown: h.Unknown, SelectedState: h.SelectedState,
		SelectedMetrics: metric(h.SelectedP50MS, h.SelectedP95MS, h.SelectedKBps),
		BestMetrics:     metric(h.BestP50MS, nil, h.BestKBps),
	}
}

// topologyLinks 先放 SSOT 常驻 WG 底图，再叠真实观测；没有观测的边保持
// unknown。RouteCandidate 只形成 candidate/unverified 候选跳，实际选择另由
// selector 实读的黄色 overlay 表示。
func topologyLinks(cfg *Config, nodes []webui.NodeView) []webui.LinkView {
	by := map[string]webui.LinkView{}
	directByDirection := map[string]string{}
	keyFor := func(from, to string) (string, string, string) {
		a, b := from, to
		if b < a {
			a, b = b, a
		}
		return a + "\x00" + b, a, b
	}
	for _, e := range cfg.ExpectedTunnels {
		if e.From == "" || e.To == "" || e.From == e.To {
			continue
		}
		key, a, b := keyFor(e.From, e.To)
		by[key] = webui.LinkView{From: a, To: b, Kind: "tunnel", State: "unknown",
			Source: "SSOT 常驻 WG · 尚无可信承载可达性观测"}
	}
	for _, e := range cfg.ExpectedDirectLinks {
		if e.From == "" || e.To == "" || e.From == e.To ||
			e.Transport != "hysteria2" || e.Carrier != "public" {
			continue
		}
		key, a, b := keyFor(e.From, e.To)
		if existing, ok := by[key]; ok && existing.Kind == "tunnel" {
			continue
		}
		by[key] = webui.LinkView{
			From: a, To: b, Kind: "direct-hy2", State: "unknown",
			ObservedFrom: e.From, ObservedTo: e.To,
			Source: "SSOT 公网 Hysteria2 单跳 · 尚无可信主动探测",
		}
		directByDirection[e.From+"\x00"+e.To] = key
	}
	stateRank := map[string]int{"unknown": 0, "active": 1, "degraded": 2, "failed": 3}
	for _, n := range nodes {
		for _, e := range n.Edges {
			if n.ID == "" || e.To == "" || n.ID == e.To {
				continue
			}
			key, _, _ := keyFor(n.ID, e.To)
			l, ok := by[key]
			if !ok || l.Kind != "tunnel" {
				// Observation.Edges 是运行时测量，不是拓扑声明。即使 v3
				// attestation 已证明来源，允许它创建 carrier 仍会把任意陌生
				// 测量边冒充成“SSOT 常驻 WG”。观测只能升级声明过的底图。
				continue
			}
			// 身份可信仍不等于测量成功：必须有实际样本才能升级承载边。
			// 零样本不能仅凭 Error 为空就变绿。
			if e.Samples <= 0 {
				continue
			}
			observedState := "active"
			switch {
			case e.Failures >= e.Samples:
				observedState = "failed"
			case e.Failures > 0:
				observedState = "degraded"
			}
			// A displayed observation must remain an observation, not a synthetic
			// mix of one endpoint's source, the other's RTT and a third timestamp.
			// Keep the worst endpoint state; for equal states keep the freshest
			// complete sample, replacing source/RTT/time atomically.
			replace := stateRank[observedState] > stateRank[l.State] ||
				(stateRank[observedState] == stateRank[l.State] && e.ObservedAt > l.ObservedAt)
			if replace {
				l.State = observedState
				l.Source = fmt.Sprintf("%s→%s report.neighbors 承载可达性 · %d 样本/%d 失败 · SSOT 常驻 WG",
					n.ID, e.To, e.Samples, e.Failures)
				l.MS = e.MS
				l.Samples = e.Samples
				l.Failures = e.Failures
				l.ObservedAt = e.ObservedAt
			}
			by[key] = l
		}
	}
	// A signed attachment may only upgrade the exact directional direct-hop
	// inventory that renderer derived from SSOT.  It cannot create a new edge or
	// turn an end-to-end Agent candidate measurement into a physical hop.
	for _, n := range nodes {
		for _, metric := range n.VerifiedLinkMetrics {
			key, ok := directByDirection[n.ID+"\x00"+metric.PeerNode]
			if !ok || metric.Transport != "hysteria2" || metric.Carrier != "public" {
				continue
			}
			link := by[key]
			link.ObservedFrom, link.ObservedTo = n.ID, metric.PeerNode
			link.MS, link.Samples, link.Failures = metric.RTTMS, metric.Samples, metric.Failures
			link.ObservedAt = metric.ObservedAt
			link.QualityP50MS, link.QualityP95MS = metric.P50MS, metric.P95MS
			link.QualityObservations, link.QualityFailed = metric.Samples, metric.Failures
			link.ProbeBytes, link.ProbeDurationMS = metric.TransferBytes, metric.DurationMS
			link.ProbeSamples = metric.Samples - metric.Failures
			link.MetricsObservedAt = metric.ObservedAt
			link.MetricsWindow = "Hy2 active probe · response latency 15m · 64KiB achieved rate 5m"
			link.MetricsSource = "independently signed loom-linkmetric-v1"
			switch {
			case metric.Failures >= metric.Samples:
				link.State = "failed"
				link.Source = fmt.Sprintf("%s→%s 公网 Hysteria2 单跳主动探测 · %d/%d 失败",
					n.ID, metric.PeerNode, metric.Failures, metric.Samples)
			case metric.Failures > 0:
				link.State = "degraded"
				link.Source = fmt.Sprintf("%s→%s 公网 Hysteria2 单跳主动探测 · %d 样本/%d 失败",
					n.ID, metric.PeerNode, metric.Samples, metric.Failures)
			default:
				link.State = "active"
				link.Source = fmt.Sprintf("%s→%s 公网 Hysteria2 单跳主动探测 · %d 样本",
					n.ID, metric.PeerNode, metric.Samples)
			}
			by[key] = link
		}
	}
	// 候选链让没有直连 WG 的节点在业务层仍有路径关系，但 ExpectedRoute 只
	// 是声明，不证明在线。只聚合非 WG hop；当前实际选择由黄色 overlay 表示。
	for _, r := range cfg.ExpectedRoutes {
		chain := append([]string{r.Access}, r.Chain...)
		for i := 0; i+1 < len(chain); i++ {
			key, a, b := keyFor(chain[i], chain[i+1])
			if existing, ok := by[key]; ok &&
				(existing.Kind == "tunnel" || existing.Kind == "direct-hy2") {
				continue
			}
			by[key] = webui.LinkView{
				From: a, To: b, Kind: "candidate", State: "unverified",
				Source: "SSOT RouteCandidate.ServerChain · 候选跳，未核验",
			}
		}
	}
	out := make([]webui.LinkView, 0, len(by))
	for _, l := range by {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		return fmt.Sprintf("%s/%s/%s", out[i].Kind, out[i].From, out[i].To) <
			fmt.Sprintf("%s/%s/%s", out[j].Kind, out[j].From, out[j].To)
	})
	return out
}
