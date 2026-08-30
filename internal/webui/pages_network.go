package webui

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

func pageNodes(d Deps, isAuthed bool, added string) string {
	v := d.Snapshot()
	now := d.Now().UTC()
	intentSource := intentSourceLabel(v)
	declared, healthy, problem, unknown, joining, draining, decommissioned := 0, 0, 0, 0, 0, 0, 0
	for _, n := range v.Nodes {
		if !n.Declared {
			continue
		}
		declared++
		if n.Decommission {
			decommissioned++
			continue
		}
		if n.Drain {
			draining++
		}
		switch n.Health {
		case "healthy":
			healthy++
		case "problem":
			problem++
		default:
			unknown++
		}
		if n.Applied == "" {
			joining++
		}
	}

	var b strings.Builder
	if added != "" {
		fmt.Fprintf(&b, `<div class=callout><b>%s declaration was saved to SSOT; its remote WireGuard identity was prepared.</b><br><span class=small>Publication is automatic, but this does not install or start the Loom Agent and does not prove the node is online. Until the first trusted report arrives, the node remains explicitly unknown / joining.</span></div><div class=section></div>`, esc(added))
	}
	fmt.Fprintf(&b, `<div class=grid>
<div class="card span3"><div class=label>Declared</div><div class=metric>%d <small>nodes</small></div><div class=dim>%s</div></div>
<div class="card span3"><div class=label>Healthy</div><div class="metric ok">%d <small>trusted</small></div><div class=dim>%d status unknown</div></div>
<div class="card span3"><div class=label>Attention</div><div class="metric %s">%d <small>problems</small></div><div class=dim>positive fault evidence</div></div>
<div class="card span3"><div class=label>Lifecycle</div><div class=metric>%d <small>joining</small></div><div class=dim>%d draining · %d decommissioned</div></div>
	</div>`, declared, esc(intentSource), healthy, unknown, map[bool]string{true: "bad", false: "ok"}[problem > 0], problem, joining, draining, decommissioned)

	fmt.Fprintf(&b, `<div class=section><div class=sectionhead><h2>Node inventory</h2><span class=dim>Declarations from %s plus retained runtime observations</span><span class=sp>`, esc(intentSource))
	if d.Control != nil {
		b.WriteString(`<a class="button primary" href="/nodes/add">＋ Add node</a>`)
	} else {
		b.WriteString(`<span class="button" aria-disabled=true>Read-only node</span>`)
	}
	b.WriteString(`</span></div><div class=node-inventory-help><span><b>接入</b> 承接本机或客户端流量并执行选路</span><span><b>转发</b> 参与隧道和代理链路</span><span><b>可作出口</b> 可作为路径末端访问公网</span><span><b>节点 ID</b> 加入时确定，不随系统 hostname 自动变化</span></div><div class=card><table><thead><tr><th>节点 / 生命周期<th>声明地址 / SSH 端口<th>用途 / 建连方式<th>观测来源<th>配置版本<th>常驻隧道<th>最后上报<th></thead><tbody>`)
	for _, n := range v.Nodes {
		stateClass, stateLabel := healthVisual(n.Health)
		lifecycleClass, lifecycleLabel := nodeLifecycleVisual(n)
		carrierTotal, active := carrierTunnelCount(n.Tunnels)
		role := nodeRoleLabel(n)
		direction := nodeDirectionLabel(n.Direction)
		if direction == "" {
			direction = "—"
		}
		declarationMark := ""
		endpointMeta := fmt.Sprintf("UDP ingress unverified · SSH port %d · host/user not retained", n.SSHPort)
		if !n.Declared {
			declarationMark = `<br><span class="tiny warn">◇ Undeclared observed</span>`
			endpointMeta = "Not in " + intentSource + " · observation retained"
			role = "undeclared observed"
			direction = "runtime evidence only"
		}
		fmt.Fprintf(&b, `<tr class=rowlink><td><a href="/nodes/%s"><b class=mono>%s</b></a><br><span class="tiny %s">● %s</span> · <span class="tiny %s">%s</span>%s<td class=w><span class=mono>%s</span><br><span class="tiny dim">%s</span><td class=w>%s<br><span class="tiny dim">%s</span><td class=w>%s<td class=mono>%s<td>%d / %d active<td>%s<td><a href="/nodes/%s">→</a></tr>`,
			url.PathEscape(n.ID), esc(n.ID), stateClass, esc(stateLabel), lifecycleClass, esc(lifecycleLabel), declarationMark, esc(orDash(n.PublicEndpoint)), esc(endpointMeta), esc(role), esc(direction), esc(n.Source), esc(short(n.Applied)), active, carrierTotal, esc(ageText(n.ObservedAt, now)), url.PathEscape(n.ID))
	}
	if len(v.Nodes) == 0 {
		b.WriteString(`<tr><td colspan=8><div class=empty>No declared nodes are available in this view.</div></tr>`)
	}
	b.WriteString(`</tbody></table></div></div>`)

	// Enrollment is a control-local capability. Regular nodes can still show
	// the learned fleet inventory when reached directly, but must not advertise
	// a dead /nodes/add workflow or control key management.
	if d.Control != nil {
		b.WriteString(`<div class=section><details class="card enrollment-access"><summary class=enrollment-summary><span class=enrollment-summary-copy><b>Enrollment SSH access</b><span>Shared control identity and trust boundary</span></span><span class=enrollment-summary-hint>Access setup</span></summary><div class=enrollment-access-body><div class=enrollment-access-grid><section class=enrollment-identity-panel><div class=enrollment-panel-head><div><div class=label>Control bootstrap identity</div><h3>One reusable control identity</h3></div></div><p class=enrollment-intro>Every enrollment reuses this SSH public key. Platform signing trust and each node's WireGuard identity remain separate.</p>`)
		if d.Control.BootstrapIdentity == nil {
			b.WriteString(`<div class="callout warnline"><b>Unavailable on this node</b><br><span class=small>The shared bootstrap identity is a control-local capability.</span></div>`)
		} else if key, err := d.Control.BootstrapIdentity.Status(); err != nil {
			fmt.Fprintf(&b, `<div class="notice badline enrollment-state"><b>Bootstrap identity cannot be read</b><br><span class=small>%s</span></div>`, esc(err.Error()))
		} else if !key.Ready {
			b.WriteString(`<div class="callout warnline enrollment-state"><b>Not generated</b><br><span class=small>Generate this once, then authorize the exported public key on every host that may be enrolled.</span></div><div class=enrollment-state-action>`)
			if isAuthed {
				b.WriteString(`<form method=post action="/nodes/bootstrap-key/generate"><button class=primary>Generate shared key pair</button></form>`)
			} else {
				b.WriteString(`<a class="button primary" href="/login">Sign in to generate</a>`)
			}
			b.WriteString(`</div>`)
		} else {
			fmt.Fprintf(&b, `<div class=enrollment-identity-meta><div><span class=label>Status</span><span class="edge-status ok"><span class=dot></span>Ready · shared by every enrollment</span></div><div><span class=label>Fingerprint</span><span class=mono>%s</span></div><div><span class=label>Public file</span><span class=mono>%s</span></div></div><div class=enrollment-public-key><div class=enrollment-public-key-head><div><span class=label>Shared public key</span><span class="tiny dim">Safe to distribute to enrollment targets</span></div><a class=button href="/nodes/bootstrap-key.pub">Download .pub</a></div><code aria-label="Shared control public key">%s</code></div>`, esc(key.Fingerprint), esc(key.PublicPath), esc(key.PublicKey))
		}
		b.WriteString(`</section><aside class=enrollment-boundary-panel><div class=label>Enrollment boundary</div><h3>What the workflow may decide</h3><div class=enrollment-boundary-list><div><span>Manual input</span><b>SSH host or IP, user, port</b></div><div><span>Discovered</span><b>Hostname, host key, system, reachability</b></div><div><span>Reviewed</span><b>Direction policy</b></div><div><span>Default</span><b>Egress enabled</b></div></div><a class="button primary enrollment-workflow" href="/nodes/add">Open enrollment workflow <span aria-hidden=true>→</span></a></aside></div><div class=enrollment-key-note><span class=enrollment-key-note-icon aria-hidden=true>◆</span><div><b>Private key boundary</b><span>The control private key never leaves this node. Each enrolled node creates or reuses its own WireGuard identity; only its public key may enter SSOT.</span></div></div></div></details></div>`)
	}

	return shell(d, "Nodes", b.String(), isAuthed, v)
}

func pageTopology(d Deps, isAuthed bool, selectedEntry ...string) string {
	v := d.Snapshot()
	now := d.Now().UTC()
	intentSource := intentSourceLabel(v)
	requested := ""
	if len(selectedEntry) > 0 {
		requested = selectedEntry[0]
	}
	focused := ""
	var focusedRoute *RouteView
	for i := range v.Routes {
		if routingRouteKey(v.Routes[i]) == requested {
			focused = requested
			focusedRoute = &v.Routes[i]
			break
		}
	}
	var overlay []RouteView
	for _, route := range v.Routes {
		if route.Stale {
			continue
		}
		// The map is an observation surface, not a route picker. By default it
		// shows every fresh Agent decision generated from the managed Service
		// rules. A deep link may isolate one decision for diagnosis, but never
		// changes the selector or desired state.
		if focused == "" || routingRouteKey(route) == focused {
			overlay = append(overlay, route)
		}
	}
	tunnels, active, directDeclared, directSampled, candidates := 0, 0, 0, 0, 0
	for _, l := range v.Links {
		switch l.Kind {
		case "tunnel":
			tunnels++
			if l.State == "active" {
				active++
			}
		case "direct-hy2":
			directDeclared++
			if l.Samples > 0 {
				directSampled++
			}
		case "candidate":
			candidates++
		}
	}
	fresh := 0
	for _, r := range v.Routes {
		if !r.Stale {
			fresh++
		}
	}
	links := append([]LinkView(nil), v.Links...)
	sort.Slice(links, func(i, j int) bool {
		return links[i].Kind+links[i].From+links[i].To < links[j].Kind+links[j].From+links[j].To
	})
	carrierLinks := make([]LinkView, 0, tunnels)
	candidateLinks := make([]LinkView, 0, candidates)
	for _, link := range links {
		switch link.Kind {
		case "tunnel":
			carrierLinks = append(carrierLinks, link)
		case "candidate":
			candidateLinks = append(candidateLinks, link)
		}
	}
	directClass, directHint := "dim", "no direct links declared"
	if directDeclared > 0 {
		directClass = "warn"
		directHint = fmt.Sprintf("%d warming up / unknown", directDeclared-directSampled)
		if directSampled == directDeclared {
			directClass = "ok"
			directHint = "signed public single-hop evidence"
		}
	}
	carrierMetricClass, carrierState := "dim", "No carriers"
	if tunnels > 0 {
		carrierMetricClass, carrierState = "warn", "Partial evidence"
		if active == tunnels {
			carrierMetricClass, carrierState = "ok", "All observed"
		}
	}

	var b strings.Builder
	b.WriteString(`<div class=sectionhead><h2>Network layers</h2><span class=dim>内圈是可接受反向建连的锚点，外圈是主动接入的出口节点；节点在各自环上等距排列。</span><span class=sp><span class="badge intent">Read-only · automatic Agent decisions</span></span></div>`)
	b.WriteString(`<div class="grid topology-layout"><div class="card span9 topology-stage">`)
	if focusedRoute != nil {
		stateClass, state := "ok", "Fresh signed observation"
		if focusedRoute.Stale {
			stateClass, state = "warn", "Stale observation · not drawn as current"
		}
		fmt.Fprintf(&b, `<div class=topology-route-focus><div><span class=label>Focused automatic decision</span><b>%s</b><span class=mono>%s</span><span class="tiny %s">%s · %s</span></div><a class="button" href="/topology">Show all current decisions</a></div>`, esc(overviewRouteName(v, *focusedRoute)), esc(automaticRoutePath(*focusedRoute)), stateClass, esc(state), esc(ageText(focusedRoute.ObservedAt, now)))
	}
	fmt.Fprintf(&b, `%s<div class=legend><span><i class=key></i>Persistent WireGuard</span><span><i class="key direct-hy2"></i>Hy2 direct · 主动探测</span><span><i class="key candidate"></i>On-demand route hop</span><span><i class="key route"></i>Automatic Agent route · read-only</span><span><i class="key degraded"></i>Degraded carrier</span><span><i class="key failed"></i>Failed carrier</span></div><div class=topology-layer-note><div class=topology-layer-summary><b>动态双环 · 自动路径只读叠加</b><span>新增节点按 direction 自动进入对应环；Agent 选中路径只叠加颜色，不参与节点排序或改变布局。</span></div><details class=topology-evidence-details><summary>指标与交互口径</summary><p>路径由 Host → Service → Policy 规则和接入节点探测自动产生；本页只展示，不改变客户端偏好、selector 或 SSOT。悬停节点可预览，点击后锁定相邻链路；标签统一为延迟 · Δ波动 · 速率。WireGuard 速率来自近 5 分钟相邻可信计数器差值；Hy2 direct 显示公网 Hysteria2 单跳响应延迟和主动探测速率，其速率是固定响应的 achieved probe throughput，不是业务流量或链路容量。虚线仅是 %s 允许的未测量按需路径，不伪装成在线隧道（not broken tunnels）。</p></details></div></div>`, topologySVG(v, overlay...), esc(intentSource))
	b.WriteString(`<aside class="span3 topology-side"><section class="card topology-status-card">`)
	fmt.Fprintf(&b, `
<div class=topology-status-head><div><h2>Layer status</h2><span>Intent matched with signed evidence</span></div><span class="badge %s"><span class=dot></span>%s</span></div>
<div class=topology-carrier-status><div><div class=label>WireGuard carriers</div><div class="metric %s">%d <small>/ %d active</small></div></div><div class=topology-status-source><b>%d declared</b><span>%s inventory</span></div></div>
<div class=topology-status-grid><div class=topology-status-item><div class=label>Hy2 direct</div><div class="metric %s">%d <small>/ %d sampled</small></div><div class=dim>%s</div></div><div class=topology-status-item><div class=label>On-demand</div><div class=metric>%d <small>possible hops</small></div><div class=dim>intent only · no tunnel health</div></div></div>
</section>`, carrierMetricClass, esc(carrierState), carrierMetricClass, active, tunnels, tunnels, esc(intentSource), directClass, directSampled, directDeclared, esc(directHint), candidates)
	writeAutomaticRoutingCard(&b, v, focused, fresh, now)
	b.WriteString(`</aside></div>`)

	writeTopologyTraffic(&b, v)

	b.WriteString(`<div class=section><div class=sectionhead><h2>Connectivity details</h2><span class=dim>Runtime carrier evidence stays separate from configured route intent.</span></div><div class=topology-edge-grid><section class="card topology-edge-card"><div class=edge-panel-head><div><h3>Persistent WireGuard carriers</h3><p>Always-on interfaces declared in inventory, with signed health evidence.</p></div>`)
	carrierBadgeClass, carrierBadgeLabel := "warn", fmt.Sprintf("%d / %d active", active, tunnels)
	if active == tunnels && tunnels > 0 {
		carrierBadgeClass, carrierBadgeLabel = "ok", fmt.Sprintf("%d / %d active", active, tunnels)
	}
	fmt.Fprintf(&b, `<span class="badge %s"><span class=dot></span>%s</span></div><table><thead><tr><th>Carrier edge<th>Health<th>Current RTT<th>5m actual rate<th>15m RTT variation<th>Last observed<th>Evidence</tr></thead><tbody>`, carrierBadgeClass, carrierBadgeLabel)
	for _, l := range carrierLinks {
		cls := "dim"
		state := "Awaiting evidence"
		switch l.State {
		case "active":
			cls, state = "ok", "Active"
		case "degraded":
			cls, state = "warn", "Degraded"
		case "failed":
			cls, state = "bad", "Failed"
		}
		rtt := "—"
		if l.Samples > l.Failures && l.ObservedAt != "" {
			rtt = fmt.Sprintf("%dms", l.MS)
		}
		rate := "—"
		if l.RateSamples > 0 && l.RateWindowSeconds > 0 {
			rate = topologyBitRate(l.RecentTXBytes, l.RateWindowSeconds)
		}
		variation := "—"
		if l.QualityObservations-l.QualityFailed >= 2 && l.QualityP95MS >= l.QualityP50MS {
			variation = fmt.Sprintf("Δ%dms", l.QualityP95MS-l.QualityP50MS)
		}
		fmt.Fprintf(&b, `<tr><td class=mono>%s ↔ %s<td><span class="edge-status %s"><span class=dot></span>%s</span><td class=mono>%s<td class=mono>%s<td class=mono>%s<td>%s<td class=edge-source>%s</tr>`, esc(l.From), esc(l.To), cls, state, rtt, rate, variation, esc(ageText(l.ObservedAt, now)), esc(l.Source))
	}
	if len(carrierLinks) == 0 {
		b.WriteString(`<tr><td colspan=7><div class=empty>No persistent carrier edges are declared in this view.</div></tr>`)
	}
	b.WriteString(`</tbody></table></section><section class="card topology-edge-card"><div class=edge-panel-head><div><h3>On-demand route hops</h3><p>Possible public hops derived from configured candidate paths.</p></div>`)
	fmt.Fprintf(&b, `<span class="badge intent"><span class=dot></span>%d configured</span></div><div class=route-hop-list>`, len(candidateLinks))
	for _, l := range candidateLinks {
		source := l.Source
		if i := strings.Index(source, " · "); i >= 0 {
			source = source[:i]
		}
		fmt.Fprintf(&b, `<div class=route-hop><span class="route-hop-pair mono">%s ↔ %s</span><span class=route-hop-state><span class=dot></span>Available by intent</span><span class=route-hop-meta>Created only when a route uses this hop · no continuous RTT or heartbeat · %s</span></div>`, esc(l.From), esc(l.To), esc(source))
	}
	if len(candidateLinks) == 0 {
		b.WriteString(`<div class=empty>No on-demand route hops are present in this view.</div>`)
	}
	b.WriteString(`</div><p class=route-hop-note>These dashed relationships are not failed WireGuard links. Their availability is declared by routing intent; actual automatic use appears in the read-only Agent route projection.</p></section></div></div>`)
	return shell(d, "Topology", b.String(), isAuthed, v)
}

func pageRouting(d Deps, isAuthed bool, selectedEntry ...string) string {
	v := d.Snapshot()
	now := d.Now().UTC()
	intentSource := intentSourceLabel(v)
	entries := routingEntryOptions(v)
	selected := ""
	if len(selectedEntry) > 0 {
		selected = selectedEntry[0]
	}
	if selected == "" && len(entries) > 0 {
		selected = entries[0].Key
	}
	var routes []RouteView
	for _, route := range v.Routes {
		if routingRouteKey(route) == selected {
			routes = append(routes, route)
		}
	}
	var candidatesForEntry []CandidatePathView
	for _, candidate := range v.Candidates {
		if routingCandidateKey(candidate) == selected {
			candidatesForEntry = append(candidatesForEntry, candidate)
		}
	}
	fresh := 0
	for _, r := range v.Routes {
		if !r.Stale {
			fresh++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<div class="grid routing-summary"><div class="card span4"><div class=label>Automatic Agent decisions</div><div class=metric>%d</div><div class=dim>read-only runtime observations · generated from managed rules</div></div><div class="card span4"><div class=label>Fresh</div><div class="metric ok">%d <small>/ %d</small></div><div class=dim>each decision has its own signed timestamp</div></div><div class="card span4"><div class=label>Inventory candidates</div><div class=metric>%d</div><div class=dim>%s · evaluated by Agent, not selected by clients</div></div></div>`, len(v.Routes), fresh, len(v.Routes), len(v.Candidates), esc(intentSource))
	b.WriteString(`<div class="section routing-scopes"><div class=sectionhead><h2>Automatic routing scopes</h2><span class=dim>Host → Service → Policy creates each scope; the access Agent continuously chooses its current route.</span></div><nav class=routing-entry-grid aria-label="Automatic routing scopes">`)
	for _, entry := range entries {
		className, current := "routing-entry-card", ""
		if entry.Key == selected {
			className += " active"
			current = ` aria-current="page"`
		}
		name, meta, path, stateClass, state := entry.Label, "Managed routing rule", "Awaiting Agent observation", "warn", "No current decision"
		for _, route := range v.Routes {
			if routingRouteKey(route) != entry.Key {
				continue
			}
			name = overviewRouteName(v, route)
			meta = automaticRouteMeta(route)
			path = automaticRoutePath(route)
			stateClass, state = "ok", "Fresh"
			if route.Stale {
				stateClass, state = "warn", "Stale"
			}
			break
		}
		fmt.Fprintf(&b, `<a class="%s" href="/routing?entry=%s"%s><span><b>%s</b><small>%s</small></span><span class=mono>%s</span><span class="tiny %s">%s · View evidence</span></a>`, className, queryEscape(entry.Key), current, esc(name), esc(meta), esc(path), stateClass, esc(state))
	}
	b.WriteString(`</nav></div>`)
	b.WriteString(`<div class="card routing-decision-card"><div class="sectionhead routing-decision-head"><h2>Current automatic decision</h2><span class=dim>Read-only selector state reported by the access Agent; it is not a client path choice.</span>`)
	if len(routes) > 0 {
		b.WriteString(`<span class=sp><a class=tiny href="/topology?entry=` + queryEscape(selected) + `">Inspect in topology →</a></span>`)
	}
	b.WriteString(`</div>`)
	if len(routes) == 0 {
		b.WriteString(`<div class=empty>No verifiable current Agent decisions are available. Historical events are not used as current state.</div>`)
	} else {
		b.WriteString(`<table class=routing-decision-table><tr><th>Access node<th>Managed rule<th>Agent-selected path<th>Candidate health<th>Observed / source<th>Reason</tr>`)
		for _, r := range routes {
			path := automaticRoutePath(r)
			entry := overviewRouteName(v, r) + " · " + automaticRouteMeta(r)
			cls := "route-text"
			if r.Stale {
				cls = "warn"
			}
			health := candidateHealthText(r.Health)
			fmt.Fprintf(&b, `<tr><td class=mono>%s<td class=w>%s<td class="w mono %s">%s<td class=w>%s<td class=w>%s<br><span class="tiny dim">%s</span><td class=w>%s</tr>`, esc(r.Node), esc(entry), cls, esc(path), health, esc(ageText(r.ObservedAt, now)), esc(r.Source), esc(r.Reason))
		}
		b.WriteString(`</table>`)
	}
	b.WriteString(`</div>`)

	b.WriteString(`<div class="section routing-candidates"><div class=sectionhead><h2>Agent candidate set for this rule</h2><span class=dim>Generated from SSOT and evaluated automatically; these are not client-selectable paths.</span></div><div class="card routing-candidate-card">`)
	if len(candidatesForEntry) == 0 {
		b.WriteString(`<div class=empty>No configured candidate paths are available for this routing entry.</div>`)
	} else {
		b.WriteString(`<table><tr><th>Access node<th>Entry<th>Path<th>Evidence<th>Source</tr>`)
		for _, p := range candidatesForEntry {
			path := strings.Join(p.Chain, " → ")
			if len(p.Chain) <= 1 {
				path = p.Node + " → direct"
			}
			cls, label := "warn", "Configured candidate"
			if p.State == "selected" {
				cls, label = "ok", "Current automatic decision"
			}
			fmt.Fprintf(&b, `<tr><td class=mono>%s<td>%s<td class="w mono">%s<td class=%s>%s<td class="w tiny">%s</tr>`, esc(p.Node), esc(candidateEntryLabel(p)), esc(path), cls, label, esc(p.Source))
		}
		b.WriteString(`</table>`)
	}
	b.WriteString(`</div></div>`)
	return shell(d, "Live paths", b.String(), isAuthed, v)
}

func pageDeployments(d Deps, isAuthed bool) string {
	v := d.Snapshot()
	now := d.Now().UTC()
	verified, inFlight, failed, missing := 0, 0, 0, 0
	for _, n := range v.Nodes {
		if n.Rollout == nil {
			missing++
			continue
		}
		switch {
		case n.Rollout.Problem:
			failed++
		case n.Rollout.Stage == "verified" || n.Rollout.Stage == "decommissioned":
			verified++
		default:
			inFlight++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<div class=grid><div class="card span3"><div class=label>Verified</div><div class="metric ok">%d</div><div class=dim>terminal success</div></div><div class="card span3"><div class=label>In progress</div><div class=metric>%d</div><div class=dim>staging / activating</div></div><div class="card span3"><div class=label>Problems</div><div class="metric %s">%d</div><div class=dim>failed or stuck</div></div><div class="card span3"><div class=label>Not reported</div><div class=metric>%d</div><div class=dim>not assumed successful</div></div></div>`, verified, inFlight, map[bool]string{true: "bad", false: "ok"}[failed > 0], failed, missing)
	publisherCadence := "not reported"
	if v.Publisher != nil && v.Publisher.IntervalSeconds > 0 {
		publisherCadence = fmt.Sprintf("≤ %ds", v.Publisher.IntervalSeconds)
	}
	fmt.Fprintf(&b, `<div class=card><div class=sectionhead><h2>Convergence clocks</h2><span class=dim>These are separate states; a saved SSOT is not an applied route decision.</span></div><div class=steps>
<div class=step><span class=label>1 · Publish</span><b>%s</b><span class="tiny dim">validate, render, sign and distribute desired state</span></div>
<div class=step><span class=label>2 · Discover</span><b>≤ 60s</b><span class="tiny dim">45s pull timer + up to 15s jitter</span></div>
<div class=step><span class=label>3 · Apply &amp; verify</span><b>Variable</b><span class="tiny dim">configuration or binary transaction</span></div>
<div class=step><span class=label>4 · Agent decision</span><b>Policy cadence</b><span class="tiny dim">usually 5–10m; not deployment latency</span></div>
</div><p class="tiny dim">The 20-minute value in transfer code is a failure ceiling for slow SSH/blob movement, not an expected configuration wait.</p></div><div class=section></div>`, esc(publisherCadence))
	b.WriteString(`<div class=grid><div class="card span4"><h2>Publisher</h2>`)
	if v.Publisher == nil {
		b.WriteString(`<div class=empty>Publisher state is not reported by this node.</div>`)
	} else {
		cls, label := "bad", "Unhealthy"
		if v.Publisher.Healthy {
			cls, label = "ok", "Healthy"
		}
		fmt.Fprintf(&b, `<div class="badge %s"><span class=dot></span>%s</div><div class=metric>PID %d</div><dl class=kv><dt>Heartbeat<dd>%s<dt>Interval<dd>%ds<dt>Commit<dd class=mono>%s<dt>Binary<dd class=mono>%s<dt>Last success<dd>%s<dt>Snapshot<dd class=mono>%s</dl>`, cls, label, v.Publisher.PID, esc(ageText(v.Publisher.UpdatedAt, now)), v.Publisher.IntervalSeconds, esc(short(v.Publisher.Commit)), esc(short(v.Publisher.Binary)), esc(v.Publisher.LastSuccess), esc(short(v.Publisher.LastSnapshot)))
		if v.Publisher.LastError != "" {
			fmt.Fprintf(&b, `<div class="card notice badline"><span class=small>%s · %s</span></div>`, esc(v.Publisher.LastErrorAt), esc(v.Publisher.LastError))
		}
	}
	b.WriteString(`</div><div class="card span8"><div class=sectionhead><h2>Node convergence</h2><span class=dim>Current applied snapshot and explicit rollout stage</span></div><table><tr><th>Node<th>Applied<th>Target<th>Stage<th>Entered<th>Last good<th>Detail</tr>`)
	for _, n := range v.Nodes {
		if n.Rollout == nil {
			fmt.Fprintf(&b, `<tr><td class=mono>%s<td class=mono>%s<td>—<td class=warn>Not reported<td>—<td>—<td class=w>Rollout state cannot be inferred from applied snapshot alone.</tr>`, esc(n.ID), esc(short(n.Applied)))
			continue
		}
		fmt.Fprintf(&b, `<tr><td class=mono>%s<td class=mono>%s<td class=mono>%s<td class=%s>%s<td>%s<td class=mono>%s<td class="w bad">%s</tr>`, esc(n.ID), esc(short(n.Applied)), esc(short(n.Rollout.Snapshot)), rolloutCSS(n.Rollout), esc(n.Rollout.Stage), esc(n.Rollout.EnteredAt), esc(short(n.Rollout.LastGood)), esc(n.Rollout.Error))
	}
	b.WriteString(`</table></div></div>`)
	return shell(d, "Deployments", b.String(), isAuthed, v)
}

func healthVisual(health string) (class, label string) {
	switch health {
	case "healthy":
		return "ok", "Healthy"
	case "problem":
		return "bad", "Problem"
	default:
		return "warn", "Status unknown"
	}
}

func nodeLifecycleVisual(n NodeView) (class, label string) {
	switch {
	case !n.Declared:
		return "warn", "Undeclared observed"
	case n.Decommission:
		return "dim", "Decommissioned"
	case n.Drain:
		return "warn", "Draining"
	case n.Applied == "":
		return "warn", "Joining"
	default:
		return "ok", "Active"
	}
}

func nodeRoleLabel(n NodeView) string {
	if len(n.Roles) > 0 {
		labels := make([]string, 0, len(n.Roles))
		for _, role := range n.Roles {
			switch role {
			case "control":
				labels = append(labels, "中控")
			case "access":
				labels = append(labels, "接入")
			case "server":
				labels = append(labels, "转发")
			case "egress":
				labels = append(labels, "可作出口")
			default:
				labels = append(labels, role)
			}
		}
		return strings.Join(labels, " + ")
	}
	if n.Agent != nil && hasCarrierTunnel(n.Tunnels) {
		return "access + topology"
	}
	if n.Agent != nil {
		return "access"
	}
	if hasCarrierTunnel(n.Tunnels) {
		return "topology"
	}
	return "not reported"
}

func nodeDirectionLabel(direction string) string {
	switch direction {
	case "bidirectional":
		return "可主动连接，也可接受入站"
	case "reverse_only":
		return "只主动连接，不接受入站"
	case "direct_only":
		return "只接受入站，不主动连接"
	case "":
		return "—"
	default:
		return direction
	}
}

func nodeLocationLabel(n NodeView) string {
	parts := []string{}
	for _, value := range []string{n.Name, n.City, n.Country, n.Provider} {
		if value != "" {
			parts = append(parts, value)
		}
	}
	if len(parts) == 0 {
		return "Not declared in this view"
	}
	return strings.Join(parts, " · ")
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func tunnelAge(t TunnelView) string {
	if t.State == "down" {
		return "interface down"
	}
	if t.AgeSec < 0 || t.State == "未握手" {
		return "never handshook"
	}
	return fmt.Sprintf("%ds", t.AgeSec)
}

func writeAutomaticRoutingCard(b *strings.Builder, v View, focused string, fresh int, now time.Time) {
	fmt.Fprintf(b, `<div class="card automatic-routing-card"><div class=automatic-routing-head><h2>Automatic routing</h2><span class="tiny ok">%d / %d fresh</span></div><p>Agent-selected state from Host → Service → Policy. Read-only; not proof of active application traffic.</p>`, fresh, len(v.Routes))
	routes := append([]RouteView(nil), v.Routes...)
	sort.SliceStable(routes, func(i, j int) bool {
		a, z := routingRouteKey(routes[i]), routingRouteKey(routes[j])
		return a < z
	})
	if len(routes) == 0 {
		b.WriteString(`<div class="empty tiny">No Agent routing decisions have been reported.</div>`)
	} else {
		b.WriteString(`<div class=automatic-route-list>`)
		for _, route := range routes {
			key := routingRouteKey(route)
			className, stateClass, state := "automatic-route-row", "ok", "Fresh"
			if key == focused {
				className += " active"
			}
			if route.Stale {
				stateClass, state = "warn", "Stale"
			}
			fmt.Fprintf(b, `<div class="%s"><div class=automatic-route-heading><b>%s</b><span class="tiny %s">%s</span></div><div class=mono>%s</div><div class=automatic-route-meta><span>%s · %s</span>`, className, esc(overviewRouteName(v, route)), stateClass, esc(state), esc(automaticRoutePath(route)), esc(automaticRouteMeta(route)), esc(ageText(route.ObservedAt, now)))
			if !route.Stale {
				if key == focused {
					b.WriteString(`<span class=info>Focused on map</span>`)
				} else {
					fmt.Fprintf(b, `<a href="/topology?entry=%s">Isolate on map</a>`, queryEscape(key))
				}
			}
			b.WriteString(`</div></div>`)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`<a class=automatic-routing-all href="/routing">View decision evidence →</a></div>`)
}

func automaticRoutePath(r RouteView) string {
	if len(r.Chain) <= 1 {
		return r.Node + " → local exit"
	}
	return strings.Join(r.Chain, " → ")
}

func automaticRouteMeta(r RouteView) string {
	scope := "Managed rule"
	switch r.ScopeKind {
	case ScopeService:
		scope = "Service rule"
	case ScopePolicy:
		scope = "Access policy"
	}
	parts := []string{r.Node, scope}
	if r.PolicyID != "" {
		parts = append(parts, r.PolicyID)
	}
	return strings.Join(parts, " · ")
}

func routeEntryLabel(r RouteView) string {
	if r.ScopeID != "" {
		if r.PolicyID != "" && r.PolicyID != r.ScopeID {
			return r.ScopeKind + " · " + r.ScopeID + " · policy " + r.PolicyID
		}
		return r.ScopeKind + " · " + r.ScopeID
	}
	if r.Declaration == "" {
		return "Unidentified entry"
	}
	return r.Declaration
}

type routingEntryOption struct {
	Key, Label string
}

func routingRouteKey(r RouteView) string {
	id := r.ScopeID
	if id == "" {
		id = r.Declaration
	}
	return r.Node + "/" + r.ScopeKind + "/" + id
}

func routingCandidateKey(p CandidatePathView) string {
	id := p.ScopeID
	if id == "" {
		id = p.Declaration
	}
	return p.Node + "/" + p.ScopeKind + "/" + id
}

func routingEntryOptions(v View) []routingEntryOption {
	byKey := map[string]string{}
	for _, route := range v.Routes {
		byKey[routingRouteKey(route)] = route.Node + " · " + routeEntryLabel(route)
	}
	for _, candidate := range v.Candidates {
		key := routingCandidateKey(candidate)
		if _, ok := byKey[key]; !ok {
			byKey[key] = candidate.Node + " · " + candidateEntryLabel(candidate)
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]routingEntryOption, 0, len(keys))
	for _, key := range keys {
		out = append(out, routingEntryOption{Key: key, Label: byKey[key]})
	}
	return out
}

func candidateEntryLabel(p CandidatePathView) string {
	if p.ScopeID != "" {
		if p.PolicyID != "" && p.PolicyID != p.ScopeID {
			return p.ScopeKind + " · " + p.ScopeID + " · policy " + p.PolicyID
		}
		return p.ScopeKind + " · " + p.ScopeID
	}
	if p.Declaration == "" {
		return "Unidentified entry"
	}
	return p.Declaration
}

func candidateHealthText(h *CandidateHealthView) string {
	if h == nil {
		return `<span class=warn>Not reported by this Agent</span>`
	}
	cls := "ok"
	if h.Candidates > 0 && h.RecentFailed == h.Candidates {
		cls = "bad"
	} else if h.RecentSuccess+h.RecentDegraded == 0 {
		cls = "warn"
	}
	return fmt.Sprintf(`<span class=%s>%d success · %d degraded · %d failed · %d stale · %d unknown</span>`, cls, h.RecentSuccess, h.RecentDegraded, h.RecentFailed, h.Stale, h.Unknown)
}

func byteSize(value int64) string {
	if value <= 0 {
		return "0 B"
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	n := float64(value)
	unit := 0
	for n >= 1024 && unit < len(units)-1 {
		n /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d B", value)
	}
	return fmt.Sprintf("%.2f %s", n, units[unit])
}

// Keep the import-time contract explicit: all relative ages use the injected clock.
var _ = time.Time{}
