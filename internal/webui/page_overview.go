package webui

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

func pageOverview(d Deps, isAuthed bool) string {
	v := d.Snapshot()
	now := d.Now().UTC()
	intentSource := intentSourceLabel(v)
	declared, decommissioned, healthy, problems, unknown := 0, 0, 0, 0, 0
	for _, n := range v.Nodes {
		if !n.Declared {
			continue
		}
		declared++
		if n.Decommission {
			decommissioned++
			continue
		}
		switch n.Health {
		case "healthy":
			healthy++
		case "problem":
			problems++
		default:
			unknown++
		}
	}
	activeDeclared := declared - decommissioned
	tunnelTotal, tunnelActive := 0, 0
	for _, link := range v.Links {
		if link.Kind != "tunnel" {
			continue
		}
		tunnelTotal++
		if link.State == "active" {
			tunnelActive++
		}
	}
	freshRoutes := 0
	for _, route := range v.Routes {
		if !route.Stale {
			freshRoutes++
		}
	}

	var b strings.Builder
	healthClass := "warn"
	healthText := fmt.Sprintf("%d 故障 · %d 未知", problems, unknown)
	if activeDeclared == 0 {
		if declared > 0 {
			healthText = fmt.Sprintf("%d decommissioned · no active nodes", decommissioned)
		} else {
			healthText = "No nodes declared in " + intentSource
		}
	} else if problems > 0 {
		healthClass = "bad"
	} else if unknown == 0 {
		healthClass, healthText = "ok", "All active declared nodes are healthy"
	}
	fmt.Fprintf(&b, `<div class="overview-health %s"><span class="status-check %s">✓</span><span>%s</span></div>`, healthClass, healthClass, esc(healthText))
	snapshotMeta := "observed " + ageText(v.ObservedAt, now)
	if overviewFleetConverged(v) && v.Publisher != nil && v.Publisher.Commit != "" {
		snapshotMeta = "fleet converged · publisher code " + short(v.Publisher.Commit)
	}
	fmt.Fprintf(&b, `<div id=overview class=steps>
<div class=step><span class=label>Nodes</span><b>%d <small>/ %d healthy</small></b></div>
<div class=step><span class=label>WireGuard</span><b>%d / %d <small>observed</small></b></div>
<div class=step><span class=label>Current traffic paths</span><b>%d / %d <small>reported</small></b></div>
<div class=step><span class=label>Snapshot</span><b class=mono>%s</b><span class="tiny dim">%s</span></div>
	</div>`, healthy, activeDeclared, tunnelActive, tunnelTotal, freshRoutes, len(v.Routes), esc(short(v.Applied)), esc(snapshotMeta))

	writeSnapshotVerdict(&b, v)

	var unresolved []UnresolvedView
	if d.Unresolved != nil {
		unresolved = d.Unresolved()
	}
	overlay := overviewRouteOverlay(v)
	b.WriteString(`<div class=overview-primary><section class="card overview-topology-card"><div class=overview-card-head><h2>Network topology</h2><span class="small dim" title="近实时拓扑 · 采样约 1 分钟 · 页面每 30 秒刷新">Agent decisions · newest trusted observation</span><span class=sr-only>近实时拓扑 · 候选跳（未核验） · 部分失败 · 故障</span><div class=legend><span><i class=key></i>WireGuard</span><span><i class="key candidate"></i>Candidate</span>`)
	if len(overlay) > 0 {
		fmt.Fprintf(&b, `<span><i class="key route"></i>%s</span>`, esc(overviewRouteName(v, overlay[0])))
	}
	b.WriteString(`</div></div>`)
	b.WriteString(topologySVG(v, overlay...))
	b.WriteString(`</section><aside class=overview-side>`)
	writeOverviewTrafficCompact(&b, v)
	writeOverviewRolloutCompact(&b, d, v, activeDeclared, now)
	b.WriteString(`</aside></div>`)

	b.WriteString(`<div class=overview-secondary>`)
	writeOverviewNodesCompact(&b, v, now)
	writeOverviewRoutesCompact(&b, v)
	b.WriteString(`</div>`)
	writeOverviewEventsCompact(&b, d)

	if len(unresolved) > 0 || unknown > 0 {
		b.WriteString(`<section class="card overview-attention"><div class=sectionhead><h2>Current attention</h2><span class=dim>present state, not reconstructed from event history</span></div>`)
		if len(unresolved) == 0 {
			fmt.Fprintf(&b, `<div class="callout warnline"><b class=warn>No confirmed fault, but %d node(s) are unknown / 状态未知</b><br><span class=small>unknown 不等于 healthy</span></div>`, unknown)
		}
		for _, issue := range unresolved {
			cls := "issue"
			if issue.Level == "problem" {
				cls += " problem"
			}
			fmt.Fprintf(&b, `<div class="%s"><b>%s · %s %s</b><br><span class=bad>%s · %s</span><br><span class="tiny dim">%s</span></div>`, cls, esc(issue.Node), esc(issue.Kind), esc(issue.Subject), esc(issue.State), esc(issue.LastedText()), esc(issue.Detail))
		}
		b.WriteString(`</section>`)
	}

	writeOverviewTraffic(&b, v)
	writeOverviewDiagnostics(&b, v, now)
	return shell(d, "总览", b.String(), isAuthed, v)
}

func overviewFleetConverged(v View) bool {
	want, count := "", 0
	for _, node := range v.Nodes {
		if !node.Declared || node.Decommission {
			continue
		}
		if node.Applied == "" {
			return false
		}
		if want == "" {
			want = node.Applied
		} else if node.Applied != want {
			return false
		}
		count++
	}
	return count > 0
}

func writeSnapshotVerdict(b *strings.Builder, v View) {
	versions := map[string][]string{}
	unknown := 0
	for _, n := range v.Nodes {
		if !n.Declared || n.Decommission {
			continue
		}
		if n.Applied == "" {
			unknown++
			continue
		}
		versions[n.Applied] = append(versions[n.Applied], n.ID)
	}
	if len(versions) > 1 {
		keys := make([]string, 0, len(versions))
		for key := range versions {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i] == v.Applied {
				return true
			}
			if keys[j] == v.Applied {
				return false
			}
			return keys[i] < keys[j]
		})
		total, current := 0, 0
		for key, nodes := range versions {
			total += len(nodes)
			if key == v.Applied {
				current = len(nodes)
			}
		}
		fmt.Fprintf(b, `<aside class="status-alert warning snapshot-alert snapshot-verdict" role=status><span class=status-alert-icon aria-hidden=true>↻</span><div class=status-alert-body><div class=status-alert-title><strong>Snapshot convergence pending</strong><span>%d snapshots observed</span></div><div class=snapshot-groups>`, len(keys))
		for _, key := range keys {
			sort.Strings(versions[key])
			className := "snapshot-group"
			if key == v.Applied {
				className += " current"
			}
			fmt.Fprintf(b, `<span class="%s"><span class=mono>%s</span><span class=snapshot-group-nodes>%s</span></span>`, className, esc(short(key)), esc(strings.Join(versions[key], " · ")))
		}
		b.WriteString(`</div></div>`)
		if current > 0 {
			fmt.Fprintf(b, `<span class=status-alert-note>%d / %d nodes on the control-plane snapshot</span>`, current, total)
		} else {
			fmt.Fprintf(b, `<span class=status-alert-note>%d declared nodes reported a snapshot</span>`, total)
		}
		b.WriteString(`</aside>`)
	} else if len(versions) == 1 && unknown == 0 {
		for key := range versions {
			fmt.Fprintf(b, `<div class="badge ok snapshot-verdict converged"><span class=dot></span>快照 %s · 全网一致</div>`, esc(short(key)))
		}
	} else if len(versions) == 1 {
		for key := range versions {
			fmt.Fprintf(b, `<aside class="status-alert warning snapshot-alert snapshot-verdict" role=status><span class=status-alert-icon aria-hidden=true>?</span><div class=status-alert-body><div class=status-alert-title><strong>Snapshot evidence incomplete</strong><span>%d nodes unverified</span></div><div class=snapshot-groups><span class="snapshot-group current"><span class=mono>%s</span><span class=snapshot-group-nodes>observed nodes</span></span></div></div><span class=status-alert-note>Waiting for signed node evidence</span></aside>`, unknown, esc(short(key)))
		}
	} else if unknown > 0 {
		fmt.Fprintf(b, `<aside class="status-alert warning snapshot-alert snapshot-verdict" role=status><span class=status-alert-icon aria-hidden=true>?</span><div class=status-alert-body><div class=status-alert-title><strong>Snapshot evidence unavailable</strong><span>%d nodes unverified</span></div></div><span class=status-alert-note>Waiting for signed node evidence</span></aside>`, unknown)
	}
}

// overviewRouteOverlay chooses one fresh routing entry for the overview. A
// single attributed overlay stays readable; drawing every Agent decision at
// once would turn the carrier topology into an unauditable green tangle.
func overviewRouteOverlay(v View) []RouteView {
	best := -1
	for i, route := range v.Routes {
		if route.Stale || len(route.Chain) < 2 {
			continue
		}
		if best == -1 || len(route.Chain) > len(v.Routes[best].Chain) {
			best = i
		}
	}
	if best == -1 {
		return nil
	}
	return []RouteView{v.Routes[best]}
}

func writeOverviewTrafficCompact(b *strings.Builder, v View) {
	b.WriteString(`<section class="card overview-compact-card"><div class=sectionhead><h2>WireGuard traffic</h2><span class="sp tiny ok">Retained centrally · last 24h</span></div>`)
	history := v.TrafficHistory
	if history == nil || len(history.Buckets) == 0 {
		b.WriteString(`<div class=traffic-compact-body><div><div class=label>Last 24h</div><div class=metric>Unavailable</div><div class="tiny dim">No retained delta window</div></div><div class="empty tiny">Current counters are kept separate.</div></div></section>`)
		return
	}
	points := make([]trafficBucketPoint, 0, len(history.Buckets))
	var total, maxValue int64
	covered, resets, gaps := 0, 0, 0
	for _, bucket := range history.Buckets {
		point := trafficBucketPoint{Start: bucket.Start, End: bucket.End, Samples: bucket.Samples, Resets: bucket.Resets, Gaps: bucket.Gaps}
		for _, node := range bucket.Nodes {
			point.RXBytes = saturatingCounterAdd(point.RXBytes, node.RXBytes)
			point.TXBytes = saturatingCounterAdd(point.TXBytes, node.TXBytes)
			if node.Samples > 0 {
				point.Present = true
			}
		}
		if bucket.Samples > 0 {
			point.Present = true
		}
		value := saturatingCounterAdd(point.RXBytes, point.TXBytes)
		if point.Present {
			covered++
			total = saturatingCounterAdd(total, value)
			if value > maxValue {
				maxValue = value
			}
		}
		resets += bucket.Resets
		gaps += bucket.Gaps
		points = append(points, point)
	}
	if maxValue == 0 {
		maxValue = 1
	}
	fmt.Fprintf(b, `<div class=traffic-compact-body><div><div class=label>Last 24h</div><div class=metric>%s</div><div class="tiny dim">%d / %d buckets · %d reset · %d gap</div></div><div><div class=traffic-spark role=img aria-label="Retained WireGuard forwarding deltas">`, esc(byteSize(total)), covered, len(points), resets, gaps)
	start := 0
	if len(points) > 16 {
		start = len(points) - 16
	}
	for _, point := range points[start:] {
		if !point.Present {
			b.WriteString(`<span class=missing title="Missing accepted delta"></span>`)
			continue
		}
		class, flag := "", ""
		if point.Resets > 0 || point.Gaps > 0 {
			class = " class=flagged"
			switch {
			case point.Resets > 0 && point.Gaps > 0:
				flag = ` data-flag="R/G"`
			case point.Resets > 0:
				flag = ` data-flag="R"`
			default:
				flag = ` data-flag="G"`
			}
		}
		value := saturatingCounterAdd(point.RXBytes, point.TXBytes)
		fmt.Fprintf(b, `<span%s%s style="--height:%d%%" title="%s"></span>`, class, flag, trafficBarHeight(value, maxValue), esc(byteSize(value)))
	}
	fmt.Fprintf(b, `</div><div class=traffic-compact-scale><span>%s</span><span>now</span></div></div></div></section>`, esc(historyTimeLabel(history.WindowStart)))
}

func writeOverviewRolloutCompact(b *strings.Builder, d Deps, v View, activeDeclared int, now time.Time) {
	b.WriteString(`<section class="card overview-compact-card"><div class=sectionhead><h2>Latest fleet rollout</h2>`)
	if d.Control != nil {
		b.WriteString(`<a class="sp tiny" href="/deployments">Deployments →</a>`)
	}
	b.WriteString(`</div>`)
	if v.Publisher == nil {
		b.WriteString(`<div class=empty>Publisher state is not available in this view.</div></section>`)
		return
	}
	verified := 0
	for _, node := range v.Nodes {
		if !node.Declared || node.Decommission || node.Rollout == nil {
			continue
		}
		if node.Rollout.Stage == "verified" || node.Rollout.Stage == "decommissioned" {
			verified++
		}
	}
	fmt.Fprintf(b, `<div class=rollout-summary>Snapshot <b class=mono>%s</b><br><span class=dim>%d / %d verified</span></div><div class=rollout-stages aria-label="Signed, distributed, applied and verified"><span class=rollout-stage>Signed</span><span class=rollout-stage>Distributed</span><span class=rollout-stage>Applied</span><span class=rollout-stage>Verified</span></div><div class="tiny dim">publisher code <span class=mono>%s</span> · last success %s</div></section>`, esc(short(v.Publisher.LastSnapshot)), verified, activeDeclared, esc(short(v.Publisher.Commit)), esc(compactAge(v.Publisher.LastSuccess, now)))
}

type overviewNodeTraffic struct{ rx, tx int64 }

func overviewNodeTrafficTotals(v View) map[string]overviewNodeTraffic {
	totals := map[string]overviewNodeTraffic{}
	if v.TrafficHistory == nil {
		return totals
	}
	for _, bucket := range v.TrafficHistory.Buckets {
		for _, node := range bucket.Nodes {
			if node.Samples == 0 && node.RXBytes == 0 && node.TXBytes == 0 {
				continue
			}
			total := totals[node.Node]
			total.rx = saturatingCounterAdd(total.rx, node.RXBytes)
			total.tx = saturatingCounterAdd(total.tx, node.TXBytes)
			totals[node.Node] = total
		}
	}
	return totals
}

func writeOverviewNodesCompact(b *strings.Builder, v View, now time.Time) {
	totals := overviewNodeTrafficTotals(v)
	b.WriteString(`<section class="card overview-list-card"><div class=sectionhead><h2>Nodes</h2><span class="tiny ok">24h trusted adjacent-sample deltas</span><a class="sp tiny" href="/nodes">All nodes →</a></div><table><thead><tr><th>Name<th>Location<th>Status<th>WG RX / TX · 24h<th>Last seen</tr></thead><tbody>`)
	shown := 0
	for _, node := range overviewOrderedNodes(v) {
		if shown == 5 {
			break
		}
		stateClass, stateLabel := healthVisual(node.Health)
		place := strings.TrimSpace(node.City)
		if place == "" {
			place = strings.TrimSpace(node.Name)
		}
		if place == "" {
			place = "—"
		}
		traffic := "—"
		if total, ok := totals[node.ID]; ok {
			traffic = byteSize(total.rx) + " / " + byteSize(total.tx)
		}
		fmt.Fprintf(b, `<tr><td><span class=dot></span><span class=mono>%s</span><td>%s<td class=%s>%s<td class=mono>%s<td>%s</tr>`, esc(node.ID), esc(place), stateClass, esc(stateLabel), esc(traffic), esc(compactAge(node.ObservedAt, now)))
		shown++
	}
	if shown == 0 {
		b.WriteString(`<tr><td colspan=5 class=dim>No nodes in this view.</tr>`)
	}
	b.WriteString(`</tbody></table></section>`)
}

func overviewOrderedNodes(v View) []NodeView {
	nodes := append([]NodeView(nil), v.Nodes...)
	selected := map[string]bool{}
	for _, route := range overviewRouteOverlay(v) {
		for _, id := range route.Chain {
			selected[id] = true
		}
	}
	priority := func(node NodeView) int {
		switch {
		case node.Self:
			return 0
		case node.Direction != "reverse_only":
			return 1
		case selected[node.ID]:
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		pi, pj := priority(nodes[i]), priority(nodes[j])
		if pi != pj {
			return pi < pj
		}
		return nodes[i].ID < nodes[j].ID
	})
	return nodes
}

func writeOverviewRoutesCompact(b *strings.Builder, v View) {
	b.WriteString(`<section class="card overview-list-card"><div class=sectionhead><h2>Current traffic paths</h2><span class="tiny ok">Reported · signed Agent state</span><a class="sp tiny" href="/routing">All paths →</a></div><table><thead><tr><th>Name<th>Type<th>Current path<th>Status</tr></thead><tbody>`)
	routes := append([]RouteView(nil), v.Routes...)
	sort.SliceStable(routes, func(i, j int) bool {
		rank := func(route RouteView) int {
			if route.ScopeKind == ScopeService {
				return 0
			}
			return 1
		}
		return rank(routes[i]) < rank(routes[j])
	})
	shown := 0
	for _, route := range routes {
		if shown == 5 {
			break
		}
		path := strings.Join(route.Chain, " → ")
		if len(route.Chain) <= 1 {
			path = route.Node + " → direct"
		}
		kind := "Access policy"
		if route.ScopeKind == ScopeService {
			kind = "Service"
		}
		statusClass, status := "ok", "Reported"
		if route.Stale {
			statusClass, status = "warn", "Stale"
		}
		fmt.Fprintf(b, `<tr><td>%s<td class=dim>%s<td class=mono>%s<td class=%s><span class=dot></span>%s</tr>`, esc(overviewRouteName(v, route)), esc(kind), esc(path), statusClass, esc(status))
		shown++
	}
	if shown == 0 {
		b.WriteString(`<tr><td colspan=4 class=dim>No current Agent paths reported.</tr>`)
	}
	b.WriteString(`</tbody></table></section>`)
}

func overviewRouteName(v View, route RouteView) string {
	if route.ScopeID != "" {
		switch route.ScopeKind {
		case ScopeService:
			for _, service := range v.Services {
				if service.ID == route.ScopeID {
					if service.Name != "" {
						return service.Name
					}
					return service.ID
				}
			}
		case ScopePolicy:
			for _, policy := range v.Policies {
				if policy.ID == route.ScopeID {
					if policy.Name != "" {
						return policy.Name
					}
					return policy.ID
				}
			}
		}
		return route.ScopeID
	}
	return routeEntryLabel(route)
}

func writeOverviewEventsCompact(b *strings.Builder, d Deps) {
	if d.Control == nil {
		return
	}
	b.WriteString(`<section class="card overview-events"><div class=sectionhead><h2>Recent events</h2><a class="sp tiny" href="/events">View all events →</a></div>`)
	if d.Events == nil {
		b.WriteString(`<div class="tiny dim">Event history is unavailable.</div></section>`)
		return
	}
	events := d.Events(3)
	if len(events) == 0 {
		b.WriteString(`<div class="tiny dim">No recent transitions. A quiet system produces no events.</div></section>`)
		return
	}
	for _, event := range events {
		text := event.Detail
		if text == "" {
			text = event.Node + " · " + event.Kind + " " + event.Subject + " · " + event.From + " → " + event.To
		}
		fmt.Fprintf(b, `<div class=overview-event-row><time>%s</time><span class=dot></span><span class=clip>%s</span></div>`, esc(compactEventTime(event.TS)), esc(text))
	}
	b.WriteString(`</section>`)
}

func compactEventTime(ts string) string {
	if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
		return parsed.Format("15:04")
	}
	return shortTS(ts)
}

func compactAge(ts string, now time.Time) string {
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		if ts == "" {
			return "—"
		}
		return ts
	}
	age := now.Sub(parsed)
	if age < 0 {
		age = 0
	}
	switch {
	case age < time.Minute:
		return fmt.Sprintf("%ds", int(age.Seconds()))
	case age < time.Hour:
		return fmt.Sprintf("%dm", int(age.Minutes()))
	default:
		return fmt.Sprintf("%.0fh", age.Hours())
	}
}

func writeOverviewTraffic(b *strings.Builder, v View) {
	var tunnels []TunnelView
	for _, n := range v.Nodes {
		if n.Self {
			tunnels = presentCounterTunnels(n.Tunnels)
			break
		}
	}
	var total int64
	for _, tunnel := range tunnels {
		total = saturatingCounterAdd(total, tunnelCounterBytes(tunnel))
	}
	b.WriteString(`<div class=section><section class=card><div class=sectionhead><h2>WireGuard forwarding</h2><span class="sp tiny dim">retained deltas and current local counters stay separate</span><a class=tiny href="/traffic.json">Traffic JSON →</a></div>`)
	writeFleetTrafficHistory(b, v)
	b.WriteString(`<div class=section><div class=sectionhead><h3>Current local interface counters</h3><span class="sp tiny dim">direct self observation · cumulative</span></div>`)
	// A sampled zero is positive counter evidence: it means the interface was
	// observed and idle. Only an absent tunnel/counter payload means that this
	// view has no current counters.
	if len(tunnels) == 0 {
		b.WriteString(`<div class=empty>Current local counters are not present in this view.<br><span class=tiny>No synthetic current-counter comparison is shown.</span></div></div></section></div>`)
		return
	}
	max := int64(1)
	for _, tunnel := range tunnels {
		if value := tunnelCounterBytes(tunnel); value > max {
			max = value
		}
	}
	b.WriteString(`<div class=bars aria-label="Current cumulative counters by local interface">`)
	for _, tunnel := range tunnels {
		value := tunnelCounterBytes(tunnel)
		class, state := "bar", ""
		if value == 0 {
			class, state = "bar idle", " · idle"
		}
		fmt.Fprintf(b, `<div class="%s" style="height:%d%%" title="%s %s%s"></div>`, class, overviewCounterHeight(value, max), esc(tunnel.Interface), esc(byteSize(value)), state)
	}
	summary := byteSize(total) + ` combined`
	if total == 0 {
		summary = `Idle · 0 B sampled`
	}
	b.WriteString(`</div><div class=barlabel><span>current interface totals</span><span>` + esc(summary) + `</span></div><p class="tiny dim">Direct self /status only · cumulative WireGuard peer counters · not a time series. A reboot, interface-index or peer-key change, or a counter decrease starts a new retained epoch; non-WireGuard traffic is excluded.</p></div></section></div>`)
}

func writeOverviewDiagnostics(b *strings.Builder, v View, nowTime time.Time) {
	// The overview stays visually quiet; operators can open this native details
	// element when they need evidence without leaving the page.
	b.WriteString(`<details class="card section"><summary><b>Diagnostic evidence</b> <span class=dim>carrier sources, configured candidates, component parity and reachability</span></summary>`)
	b.WriteString(`<div class=section><h2>Carrier and candidate layers</h2><table><tr><th>Edge<th>Type / state<th>Observation<th>Source</tr>`)
	for _, l := range v.Links {
		fmt.Fprintf(b, `<tr><td class=mono>%s ↔ %s<td>%s / %s<td>%s<td class="w tiny">%s</tr>`, esc(l.From), esc(l.To), esc(l.Kind), esc(l.State), esc(l.ObservedAt), esc(l.Source))
	}
	fmt.Fprintf(b, `</table><p class="tiny dim">%s 常驻 WG + 承载可达性观测；无直边 ≠ 无路径。</p></div>`, esc(intentSourceLabel(v)))

	b.WriteString(`<div class=section><h2>Configured candidate paths</h2><table><tr><th>Access<th>Entry<th>Path<th>Evidence<th>Source</tr>`)
	for _, p := range v.Candidates {
		path := strings.Join(p.Chain, " → ")
		if len(p.Chain) <= 1 {
			path = p.Node + " → direct"
		}
		cls, label := "warn", "候选（未核验）"
		if p.State == "selected" {
			cls, label = "ok", "当前选中"
		}
		fmt.Fprintf(b, `<tr><td class=mono>%s<td>%s<td class="w mono">%s<td class=%s>%s<td class="w tiny">%s</tr>`, esc(p.Node), esc(candidateEntryLabel(p)), esc(path), cls, label, esc(p.Source))
	}
	b.WriteString(`</table></div>`)

	b.WriteString(`<div class=section><h2>Node evidence</h2>`)
	for _, n := range v.Nodes {
		lifecycleClass, lifecycleLabel := nodeLifecycleVisual(n)
		fmt.Fprintf(b, `<div class=nodecard><div class=nodehead><b class=mono>%s</b><span class="tiny %s">%s</span><span class="sp tiny dim">%s</span></div>`, esc(n.ID), lifecycleClass, esc(lifecycleLabel), esc(n.Source))
		for _, c := range n.Components {
			cls := "bad"
			if c.OK {
				cls = "ok"
			}
			actual := c.Actual
			if c.Error != "" {
				actual = "无法核对"
			}
			fmt.Fprintf(b, `<div class="tiny %s clip">%s %s / 期望 %s</div>`, cls, esc(c.Name), esc(actual), esc(c.Expected))
		}
		for _, target := range n.Targets {
			observed := ageText(target.ObservedAt, nowTime)
			if target.Err == "" {
				fmt.Fprintf(b, `<div class="tiny ok clip">target · %s · %dms · %s</div>`, esc(target.Target), target.MS, esc(observed))
			} else if target.Uplink {
				fmt.Fprintf(b, `<div class="tiny bad clip">uplink · %s · %s · %s</div>`, esc(target.Target), esc(brief(target.Err)), esc(observed))
			} else {
				fmt.Fprintf(b, `<div class="tiny info clip">target · %s · 不可达（剪枝数据） · %s · %s</div>`, esc(target.Target), esc(brief(target.Err)), esc(observed))
			}
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div><div class=section><h2>Agent candidate health</h2><table><tr><th>Node<th>Entry<th>Current path<th>Candidate health</tr>`)
	for _, r := range v.Routes {
		path := strings.Join(r.Chain, " → ")
		if len(r.Chain) <= 1 {
			path = r.Node + " → direct"
		}
		fmt.Fprintf(b, `<tr><td class=mono>%s<td>%s<td class="w mono">%s<td class=w>%s</tr>`, esc(r.Node), esc(routeEntryLabel(r)), esc(path), overviewRouteHealth(r.Health))
	}
	b.WriteString(`</table></div></details>`)
}

func overviewRouteHealth(h *CandidateHealthView) string {
	if h == nil {
		return `<span class=warn>未上报（旧 Agent）</span>`
	}
	cls := "ok"
	if h.Candidates > 0 && h.RecentFailed == h.Candidates {
		cls = "bad"
	} else if h.RecentSuccess+h.RecentDegraded == 0 {
		cls = "warn"
	}
	out := fmt.Sprintf(`<span class=%s>%d 正常 · %d 波动 · %d 失败 · %d 过期 · %d 未知</span>`, cls, h.RecentSuccess, h.RecentDegraded, h.RecentFailed, h.Stale, h.Unknown)
	if h.SelectedState != "" {
		label := map[string]string{"success": "正常", "degraded": "波动", "failed": "失败", "stale": "过期", "unknown": "未知"}[h.SelectedState]
		if label == "" {
			label = h.SelectedState
		}
		detail := "当前候选 " + label
		if h.SelectedMetrics != "" {
			detail += " · " + h.SelectedMetrics
		}
		out += `<br><span class=tiny>` + esc(detail) + `</span>`
	}
	if h.BestMetrics != "" {
		out += `<br><span class="tiny dim">窗口最佳 ` + esc(h.BestMetrics) + `</span>`
	}
	return out
}
