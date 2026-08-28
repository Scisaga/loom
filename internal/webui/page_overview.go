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
	fmt.Fprintf(&b, `<div id=overview class=steps>
<div class=step><span class=label>Active nodes</span><b>%d <small>/ %d healthy</small></b><span class="tiny %s">%s</span></div>
<div class=step><span class=label>Persistent WireGuard</span><b>%d <small>/ %d observed active</small></b><span class="tiny dim">%s carrier layer</span></div>
<div class=step><span class=label>Current traffic paths</span><b>%d <small>/ %d fresh</small></b><span class="tiny dim">reported Agent decisions</span></div>
<div class=step><span class=label>Snapshot</span><b class=mono>%s</b><span class="tiny dim">observed %s</span></div>
	</div>`, healthy, activeDeclared, healthClass, esc(healthText), tunnelActive, tunnelTotal, esc(intentSource), freshRoutes, len(v.Routes), esc(short(v.Applied)), esc(ageText(v.ObservedAt, now)))

	writeSnapshotVerdict(&b, v)

	var unresolved []UnresolvedView
	if d.Unresolved != nil {
		unresolved = d.Unresolved()
	}
	b.WriteString(`<div class=section><div class=grid><div class="card span8"><div class=sectionhead><h2>近实时拓扑</h2><span class=dim>采样约 1 分钟 · 页面每 30 秒刷新</span><a class="sp tiny" href="/topology">Full topology →</a></div>`)
	b.WriteString(topologySVG(v))
	fmt.Fprintf(&b, `<div class=legend><span><i class=key></i>常驻 WG</span><span><i class="key candidate"></i>候选跳（未核验）</span><span><i class="key degraded"></i>部分失败</span><span><i class="key failed"></i>故障</span></div><div class="tiny dim">候选只表示 %s 意图；总览不叠加业务路径，避免多条 Agent 决策互相覆盖。每条承载可达性观测保留来源和时间。</div></div>`, esc(intentSource))

	b.WriteString(`<div class="card span4"><div class=sectionhead><h2>Current attention</h2><span class=dim>present state</span></div>`)
	if len(unresolved) == 0 {
		if unknown > 0 {
			fmt.Fprintf(&b, `<div class="callout warnline"><b class=warn>没有已确认故障，但 %d 个节点状态未知</b><br><span class=small>unknown 不等于 healthy</span></div>`, unknown)
		} else {
			b.WriteString(`<div class=callout><b class=ok>No unresolved problems</b><br><span class=small>Read from current state, not reconstructed from event history.</span></div>`)
		}
	} else {
		for _, issue := range unresolved {
			cls := "issue"
			if issue.Level == "problem" {
				cls += " problem"
			}
			fmt.Fprintf(&b, `<div class="%s"><b>%s · %s %s</b><br><span class=bad>%s · %s</span><br><span class="tiny dim">%s</span></div>`, cls, esc(issue.Node), esc(issue.Kind), esc(issue.Subject), esc(issue.State), esc(issue.LastedText()), esc(issue.Detail))
		}
	}
	b.WriteString(`</div></div></div>`)
	writeOverviewTraffic(&b, v)
	writeOverviewReleaseAndEvents(&b, d, v, now)
	writeOverviewDiagnostics(&b, v, now)
	return shell(d, "总览", b.String(), isAuthed, v)
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
		b.WriteString(`<div class="card notice"><b class=warn>全网不是同一个快照</b><table>`)
		keys := make([]string, 0, len(versions))
		for key := range versions {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			sort.Strings(versions[key])
			fmt.Fprintf(b, `<tr><td class=mono>%s<td class=w>%s</tr>`, esc(short(key)), esc(strings.Join(versions[key], " · ")))
		}
		b.WriteString(`</table></div>`)
	} else if len(versions) == 1 && unknown == 0 {
		for key := range versions {
			fmt.Fprintf(b, `<div class="badge ok"><span class=dot></span>快照 %s · 全网一致</div>`, esc(short(key)))
		}
	} else if len(versions) == 1 {
		for key := range versions {
			fmt.Fprintf(b, `<div class="badge warn"><span class=dot></span>已观测节点为快照 %s · %d 个节点未核验</div>`, esc(short(key)), unknown)
		}
	} else if unknown > 0 {
		fmt.Fprintf(b, `<div class="badge warn"><span class=dot></span>%d 个节点没有快照观测</div>`, unknown)
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

func writeOverviewReleaseAndEvents(b *strings.Builder, d Deps, v View, now time.Time) {
	// Deployment and event-journal pages are control capabilities. A regular
	// node may receive rollout observations through the shared View, but that
	// does not make it a deployment console or an event archive. Keep those
	// entry points out of the local diagnostic UI.
	if d.Control == nil {
		return
	}
	// The injected clock is already reflected in View ages above; this compact
	// section intentionally keeps raw publisher timestamps for auditability.
	_ = now
	b.WriteString(`<div class=section><div class=grid><div class="card span5"><div class=sectionhead><h2>Latest fleet rollout</h2><a class="sp tiny" href="/deployments">Deployments →</a></div>`)
	if v.Publisher == nil {
		b.WriteString(`<div class=empty>Publisher state is not available in this view.</div>`)
	} else {
		cls, label := "bad", "Publisher unhealthy"
		if v.Publisher.Healthy {
			cls, label = "ok", "Publisher healthy"
		}
		fmt.Fprintf(b, `<div class="badge %s"><span class=dot></span>%s</div><div class=metric>Snapshot <span class=mono>%s</span></div><div class="tiny dim">last success %s · interval %ds · publisher code %s</div>`, cls, label, esc(short(v.Publisher.LastSnapshot)), esc(v.Publisher.LastSuccess), v.Publisher.IntervalSeconds, esc(short(v.Publisher.Commit)))
	}
	b.WriteString(`</div><div class="card span7"><div class=sectionhead><h2>Recent events</h2><a class="sp tiny" href="/events">View all events →</a></div>`)
	if d.Events == nil {
		b.WriteString(`<div class=empty>Event history is retained on the control node only.</div>`)
	} else {
		events := d.Events(5)
		if len(events) == 0 {
			b.WriteString(`<div class=empty>No recent transitions. A quiet system produces no events.</div>`)
		} else {
			b.WriteString(`<table>`)
			for _, e := range events {
				cls := "dim"
				if e.Level == "problem" {
					cls = "bad"
				} else if e.Level == "ok" {
					cls = "ok"
				}
				fmt.Fprintf(b, `<tr><td class=mono>%s<td>%s<td class=w>%s · %s<td class=%s>%s → %s</tr>`, esc(shortTS(e.TS)), esc(e.Node), esc(e.Kind), esc(e.Subject), cls, esc(e.From), esc(e.To))
			}
			b.WriteString(`</table>`)
		}
	}
	b.WriteString(`</div></div></div>`)
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
