package report

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"loom/internal/version"
	"loom/internal/webui"
)

// buildView 把 /status 的同一份 Status 变成界面视图。这里不重新探测网络，
// 也不从事件历史猜当前路径；版本、rollout、Agent 选择都来自 Status 或已验签
// 的 Observation。
func buildView(cfg *Config, self *Status, now time.Time) webui.View {
	now = now.UTC()
	v := webui.View{Self: cfg.Node, Applied: self.Applied, ObservedAt: now.Format(time.RFC3339)}
	attestationAge, err := cfg.ObsStale()
	if err != nil {
		attestationAge = AttestationMaxAge
		v.Warnings = append(v.Warnings, "observation_stale 无法解析，验签新鲜度回退到 "+AttestationMaxAge.String()+":"+err.Error())
	}
	byNode := map[string]webui.NodeView{}
	byNode[cfg.Node] = nodeView(cfg.Node, true, true, self, self.Observation, nil, "", now)

	var ca []byte
	var caErr error
	caLoaded := false
	for i := range self.Learned {
		o := &self.Learned[i]
		var trusted *AttestedState
		identityErr := ""
		if o.Attest != nil {
			if !caLoaded {
				ca, caErr = os.ReadFile(caPath)
				caLoaded = true
			}
			if caErr != nil {
				identityErr = "读签名 CA:" + caErr.Error()
			} else if got, err := VerifyObservation(o, ca, now, attestationAge); err != nil {
				identityErr = err.Error()
			} else {
				trusted = got
			}
		}
		if o.Node == "" || o.Node == cfg.Node {
			continue
		}
		byNode[o.Node] = nodeView(o.Node, false, false, nil, o, trusted, identityErr, now)
	}
	for _, id := range cfg.ExpectedNodes {
		if id == "" {
			continue
		}
		if _, ok := byNode[id]; !ok {
			byNode[id] = webui.NodeView{
				ID: id, Health: "unknown", Source: "SSOT 期望 · 未收到观测",
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
	}
	if st == nil {
		if n.Rollout != nil && n.Rollout.Problem {
			n.Health = "problem"
		}
		// A trusted v3 uplink failure is a positive fault signal even though a
		// relayed Observation cannot prove the rest of the remote Status healthy.
		// Ordinary Targets are pruning data and must leave node health unknown.
		for _, r := range n.Targets {
			if r.Uplink && r.Err != "" {
				n.Health = "problem"
				n.Problems = append(n.Problems,
					fmt.Sprintf("直连探测失败:%s:%s", r.Target, r.Err))
			}
		}
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
	n.Rotating = append(n.Rotating, st.Rotating...)
	for i := range st.Tunnels {
		t := &st.Tunnels[i]
		tv := webui.TunnelView{
			Interface: t.Interface, State: t.UnitState,
			AgeSec: int(t.HandshakeAgeSec), OK: !t.Down && !t.Stale && t.HandshakeAgeSec >= 0,
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
	n.Problems = append(n.Problems, st.Errors...)
	return n
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
		r := webui.RouteView{
			Node: a.Node, Declaration: s.Declaration, Selector: s.Selector,
			Candidate: s.Candidate, Chain: chain, Reason: s.Reason,
			ObservedAt: s.UpdatedAt, Source: source + " · sing-box selector",
		}
		if t, err := time.Parse(time.RFC3339, s.UpdatedAt); err != nil ||
			now.Sub(t) > AgentStateStaleAfter || now.Sub(t) < -2*time.Minute {
			r.Stale = true
		}
		v.Selections = append(v.Selections, r)
	}
	return v
}

// topologyLinks 先放 SSOT 常驻 WG 底图，再叠真实观测；没有观测的边保持
// unknown。RouteCandidate 只形成 candidate/unverified 候选跳，实际选择另由
// selector 实读的黄色 overlay 表示。
func topologyLinks(cfg *Config, nodes []webui.NodeView) []webui.LinkView {
	by := map[string]webui.LinkView{}
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
	stateRank := map[string]int{"unknown": 0, "active": 1, "degraded": 2, "failed": 3}
	for _, n := range nodes {
		for _, e := range n.Edges {
			if n.ID == "" || e.To == "" || n.ID == e.To {
				continue
			}
			key, _, _ := keyFor(n.ID, e.To)
			l, ok := by[key]
			if !ok {
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
				l.ObservedAt = e.ObservedAt
			}
			by[key] = l
		}
	}
	// 候选链让没有直连 WG 的节点在业务层仍有路径关系，但 ExpectedRoute 只
	// 是声明，不证明在线。只聚合非 WG hop；当前实际选择由黄色 overlay 表示。
	for _, r := range cfg.ExpectedRoutes {
		chain := append([]string{r.Access}, r.Chain...)
		for i := 0; i+1 < len(chain); i++ {
			key, a, b := keyFor(chain[i], chain[i+1])
			if existing, ok := by[key]; ok && existing.Kind == "tunnel" {
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
