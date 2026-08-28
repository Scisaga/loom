package webui

import (
	"fmt"
	"net/url"
	"strings"
)

// pageNodeDetail keeps runtime, observation and traffic at the same visual
// level. It deliberately preserves all evidence from the former right-heavy
// layout; the change is a redistribution, not a summary that drops detail.
func pageNodeDetail(d Deps, nodeID string, isAuthed bool) (string, bool) {
	v := d.Snapshot()
	now := d.Now().UTC()
	intentSource := intentSourceLabel(v)
	var node *NodeView
	for i := range v.Nodes {
		if v.Nodes[i].ID == nodeID {
			node = &v.Nodes[i]
			break
		}
	}
	if node == nil {
		return "", false
	}
	n := *node
	stateClass, stateLabel := healthVisual(n.Health)
	lifecycleClass, lifecycleLabel := nodeLifecycleVisual(n)
	carrierTotal, active := carrierTunnelCount(n.Tunnels)
	counterTunnels := presentCounterTunnels(n.Tunnels)
	var rxTotal, txTotal int64
	for _, tunnel := range counterTunnels {
		rxTotal = saturatingCounterAdd(rxTotal, tunnel.RxBytes)
		txTotal = saturatingCounterAdd(txTotal, tunnel.TxBytes)
	}

	versionCommit, versionBinary := "Not reported", "Not reported"
	if n.Version != nil {
		versionCommit, versionBinary = short(n.Version.Commit), short(n.Version.Binary)
	}
	rollout, rolloutClass := "Not reported", "warn"
	if n.Rollout != nil {
		rollout = n.Rollout.Stage + " · " + short(n.Rollout.Snapshot)
		rolloutClass = rolloutCSS(n.Rollout)
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<div class=steps>
<div class=step><span class=label>Health</span><b class=%s>● %s</b><span class="tiny dim">missing evidence remains unknown</span></div>
<div class=step><span class=label>Snapshot</span><b class=mono>%s</b><span class="tiny dim">current applied state</span></div>
<div class=step><span class=label>Loom / binary</span><b class=mono>%s / %s</b><span class="tiny dim">reported identity</span></div>
<div class=step><span class=label>Persistent tunnels</span><b>%d / %d active</b><span class="tiny dim">interface + handshake evidence</span></div>
	</div>`, stateClass, esc(stateLabel), esc(short(n.Applied)), esc(versionCommit), esc(versionBinary), active, carrierTotal)
	if !n.Declared {
		fmt.Fprintf(&b, `<div class="card notice section"><b class=warn>Undeclared observed node</b><br><span class=small>This node is absent from %s. Its retained runtime evidence remains visible for removal and drift diagnosis.</span></div>`, esc(intentSource))
	} else if n.Decommission {
		b.WriteString(`<div class="card notice section"><b>Lifecycle · Decommissioned</b><br><span class=small>This is a successful terminal lifecycle state. The node is not required to remain online or participate in candidate selection.</span></div>`)
	} else if n.Drain {
		b.WriteString(`<div class="card notice section"><b class=warn>Lifecycle · Draining</b><br><span class=small>The node remains observable but should not receive new routing work.</span></div>`)
	}

	identityScope := "Declaration from " + intentSource + " and reported release state"
	sshPort := "—"
	if n.Declared {
		if n.SSHPort > 0 {
			sshPort = fmt.Sprintf("%d", n.SSHPort)
		}
	} else {
		identityScope = "Runtime evidence only · no current declaration"
	}
	fmt.Fprintf(&b, `<div class=section><div class=grid><section class="card span6"><div class=sectionhead><h2>Identity &amp; runtime</h2><span class=dim>%s</span></div><div class=grid>`, esc(identityScope))
	fmt.Fprintf(&b, `<div class=span6><dl class=kv><dt>Node ID<dd class=mono>%s<dt>Lifecycle<dd class=%s>%s<dt>Name / location<dd>%s<dt>Role<dd>%s<dt>Direction<dd class=mono>%s<dt>Egress<dd>%s<dt>Declared endpoint<dd class=mono>%s<br><span class="tiny warn">UDP ingress unverified</span><dt>SSH port<dd class=mono>%s</dl></div>`,
		esc(n.ID), lifecycleClass, esc(lifecycleLabel), esc(nodeLocationLabel(n)), esc(nodeRoleLabel(n)), esc(orDash(n.Direction)), enabledText(n.EgressCapable), esc(orDash(n.PublicEndpoint)), esc(sshPort))
	fmt.Fprintf(&b, `<div class=span6><dl class=kv><dt>Observation<dd>%s<dt>Source<dd>%s<dt>Observed at<dd>%s<dt>Rollout<dd class=%s>%s`, esc(ageText(n.ObservedAt, now)), esc(n.Source), esc(orDash(n.ObservedAt)), rolloutClass, esc(rollout))
	if n.Version != nil {
		fmt.Fprintf(&b, `<dt>Platform<dd>%s<dt>Go<dd>%s`, esc(orDash(n.Version.Platform)), esc(orDash(n.Version.Go)))
	}
	b.WriteString(`</dl></div></div><div class=section><div class=sectionhead><h2>Component parity</h2><span class=dim>Expected and actual remain separate</span></div>`)
	writeNodeComponents(&b, n.Components)
	b.WriteString(`</div></section>`)

	b.WriteString(`<section class="card span6"><div class=sectionhead><h2>Observation &amp; WireGuard I/O</h2><span class=dim>Newest evidence for this node</span></div>`)
	fmt.Fprintf(&b, `<div class=kv><dt>Trust source<dd>%s<dt>Reachability<dd>%s<dt>Reported<dd>%s<dt>Carrier state<dd>%d active · %d observed carrier row(s)</div>`, esc(n.Source), map[bool]string{true: "direct /status", false: "trusted learned state or unknown"}[n.Reached], esc(orDash(n.ObservedAt)), active, carrierTotal)
	b.WriteString(`<div class=section><table><tr><th>Interface<th>State<th>Handshake<th>RX total<th>TX total</tr>`)
	for _, tunnel := range n.Tunnels {
		cls, state, handshake := "dim", tunnel.State, "—"
		if tunnel.CarrierPresent {
			cls = "bad"
			if tunnel.OK {
				cls = "ok"
			}
			handshake = tunnelAge(tunnel)
		} else {
			// A verified traffic attachment can outlive or arrive without carrier
			// state. Keep its counters visible, but do not paint the row as a
			// failed tunnel or invent handshake evidence.
			state = "traffic counters only"
		}
		rx, tx := "—", "—"
		if tunnel.CounterPresent {
			rx, tx = byteSize(nonNegative(tunnel.RxBytes)), byteSize(nonNegative(tunnel.TxBytes))
		}
		fmt.Fprintf(&b, `<tr><td class=mono>%s<td class=%s>%s<td>%s<td>%s<td>%s</tr>`, esc(tunnel.Interface), cls, esc(state), esc(handshake), esc(rx), esc(tx))
	}
	if len(n.Tunnels) == 0 {
		b.WriteString(`<tr><td colspan=5><div class=empty>No interface detail was reported. This is not proof that no edge is declared.</div></tr>`)
	}
	b.WriteString(`</table></div>`)
	if n.IdentityError != "" {
		fmt.Fprintf(&b, `<div class="callout warnline section"><b>Identity claim rejected</b><br><span class=small>%s</span></div>`, esc(n.IdentityError))
	}
	b.WriteString(`</section></div></div>`)

	historyLabel := `current cumulative counters · retained history attached`
	historyClass := "dim"
	if v.TrafficHistory == nil {
		historyLabel = `current cumulative counters · history not retained`
		historyClass = "warn"
	}
	trafficJSONLabel := "This node traffic JSON →"
	if !n.Self {
		// /traffic.json is intentionally node-local. The selected remote node's
		// independently signed counters are visible in this page, but the link is
		// served by the control/current host and must not pretend otherwise.
		trafficJSONLabel = "Serving host traffic JSON →"
	}
	fmt.Fprintf(&b, `<div class=section><section class=card><div class=sectionhead><h2>Forwarding traffic</h2><span class="sp tiny %s">%s</span><a class=tiny href="/traffic.json">%s</a></div>`, historyClass, historyLabel, esc(trafficJSONLabel))
	// CounterPresent rows are current evidence even when both sampled values are
	// zero. Byte sums answer "busy or idle"; they must not answer "was sampled".
	if len(counterTunnels) > 0 {
		idle := ""
		if rxTotal == 0 && txTotal == 0 {
			idle = `<br><b class=ok>Idle · 0 B sampled.</b>`
		}
		fmt.Fprintf(&b, `<div class=grid><div class="span3"><div class=label>WG RX total</div><div class=metric>%s</div></div><div class="span3"><div class=label>WG TX total</div><div class=metric>%s</div></div><div class="span6"><div class=label>Trust / reset boundary</div><p class=small>%s A reboot, interface-index or peer-key change, or an observed counter decrease starts a new retained epoch. A same-key peer recreation with no decrease is not distinguishable. Only Loom WireGuard interfaces are included; direct non-WireGuard, service/sing-box and Hysteria2 traffic are excluded.%s</p></div></div>`, esc(byteSize(rxTotal)), esc(byteSize(txTotal)), esc(currentCounterTrustText(n)), idle)
		writeCurrentCounterBars(&b, counterTunnels)
		if v.TrafficHistory == nil {
			b.WriteString(`<div class="callout warnline section"><b>Current raw counters only</b><br><span class=small>Time buckets are not retained centrally, so no synthetic history chart is shown.</span></div>`)
		} else {
			b.WriteString(`<p class="tiny dim">The interface bars above compare cumulative counters. The retained delta buckets below are a separate data set and reset/gap rules apply before bytes enter them.</p>`)
		}
	} else {
		b.WriteString(`<div class="callout warnline"><b>No current cumulative counters for this node</b><br><span class=small>The interface table remains empty/zero instead of inferring a current total from historical buckets.</span></div>`)
	}
	writeNodeTrafficHistory(&b, v, n.ID)
	b.WriteString(`</section></div>`)

	b.WriteString(`<div class=section><div class=grid><section class="card span6"><div class=sectionhead><h2>Agent route decisions</h2><span class=dim>Current selector state on this access node</span></div>`)
	if n.Agent == nil || len(n.Agent.Selections) == 0 {
		b.WriteString(`<div class=empty>No Agent route decision was reported for this node.</div>`)
	} else {
		b.WriteString(`<table><tr><th>Entry<th>Current path<th>Observed<th>Reason</tr>`)
		for _, route := range n.Agent.Selections {
			path := strings.Join(route.Chain, " → ")
			if len(route.Chain) <= 1 {
				path = route.Node + " → direct"
			}
			cls := "ok"
			if route.Stale {
				cls = "warn"
			}
			fmt.Fprintf(&b, `<tr><td class=w>%s<td class="mono w %s">%s<td>%s<td class=w>%s</tr>`, esc(routeEntryLabel(route)), cls, esc(path), esc(ageText(route.ObservedAt, now)), esc(route.Reason))
		}
		b.WriteString(`</table>`)
	}
	b.WriteString(`</section><section class="card span6"><div class=sectionhead><h2>Measurements &amp; attention</h2><span class=dim>Uplink faults and route-pruning data stay distinct</span></div>`)
	writeNodeAttention(&b, n)
	if len(n.Targets) == 0 {
		b.WriteString(`<div class="empty section">No reachability samples were reported.</div>`)
	} else {
		b.WriteString(`<div class=section><table><tr><th>Type<th>Target<th>Result<th>Observed</tr>`)
		for _, target := range n.Targets {
			kind := "target · pruning data"
			if target.Uplink {
				kind = "uplink · node health"
			}
			result, cls := fmt.Sprintf("%dms", target.MS), "ok"
			if target.Err != "" {
				result, cls = brief(target.Err), "info"
				if target.Uplink {
					cls = "bad"
				}
			}
			fmt.Fprintf(&b, `<tr><td class=w>%s<td class="mono w">%s<td class="w %s">%s<td>%s</tr>`, esc(kind), esc(target.Target), cls, esc(result), esc(ageText(target.ObservedAt, now)))
		}
		b.WriteString(`</table></div>`)
	}
	b.WriteString(`</section></div></div>`)

	fmt.Fprintf(&b, `<div class=toolbar><a class=button href="/nodes">← Nodes</a><a class=button href="/topology">View in topology →</a><a class=button href="/nodes/%s">Refresh observation</a></div>`, url.PathEscape(n.ID))
	return shell(d, "Node · "+n.ID, b.String(), isAuthed, v), true
}

func writeNodeComponents(b *strings.Builder, components []ComponentView) {
	if len(components) == 0 {
		b.WriteString(`<div class=empty>Component versions were not reported by this node.</div>`)
		return
	}
	b.WriteString(`<table><tr><th>Component<th>Expected<th>Actual<th>Result<th>Detail</tr>`)
	for _, component := range components {
		cls, state := "bad", "Drift"
		if component.OK {
			cls, state = "ok", "Matched"
		}
		fmt.Fprintf(b, `<tr><td>%s<td class=mono>%s<td class=mono>%s<td class=%s>%s<td class=w>%s</tr>`, esc(component.Name), esc(component.Expected), esc(component.Actual), cls, state, esc(brief(component.Error)))
	}
	b.WriteString(`</table>`)
}

func writeNodeAttention(b *strings.Builder, n NodeView) {
	if len(n.Problems) == 0 && n.IdentityError == "" {
		if n.Health == "unknown" {
			b.WriteString(`<div class="callout warnline"><b class=warn>Status unknown</b><br><span class=small>Missing trusted evidence is not treated as healthy.</span></div>`)
		} else {
			b.WriteString(`<div class=callout><b class=ok>No current problems</b><br><span class=small>Based on newest state, not reconstructed from event history.</span></div>`)
		}
		return
	}
	for _, problem := range n.Problems {
		fmt.Fprintf(b, `<div class="callout warnline"><span class=small>%s</span></div>`, esc(problem))
	}
}

func writeCurrentCounterBars(b *strings.Builder, tunnels []TunnelView) {
	var maxValue int64
	for _, tunnel := range tunnels {
		if tunnel.RxBytes > maxValue {
			maxValue = tunnel.RxBytes
		}
		if tunnel.TxBytes > maxValue {
			maxValue = tunnel.TxBytes
		}
	}
	idle := maxValue <= 0
	if idle {
		maxValue = 1
	}
	b.WriteString(`<div class=counterchart role=img aria-label="Current cumulative WireGuard receive and transmit counters by interface">`)
	for _, tunnel := range tunnels {
		rxClass, txClass := "counterrx", "countertx"
		rxState, txState := "", ""
		if tunnel.RxBytes <= 0 {
			rxClass, rxState = "counterrx idle", " · idle"
		}
		if tunnel.TxBytes <= 0 {
			txClass, txState = "countertx idle", " · idle"
		}
		fmt.Fprintf(b, `<div class=countergroup><div class=counterbars><i class="%s" style="height:%d%%" title="%s RX %s%s"></i><i class="%s" style="height:%d%%" title="%s TX %s%s"></i></div><span class="tiny mono clip">%s</span></div>`, rxClass, counterHeight(tunnel.RxBytes, maxValue), esc(tunnel.Interface), esc(byteSize(nonNegative(tunnel.RxBytes))), rxState, txClass, counterHeight(tunnel.TxBytes, maxValue), esc(tunnel.Interface), esc(byteSize(nonNegative(tunnel.TxBytes))), txState, esc(tunnel.Interface))
	}
	b.WriteString(`</div><div class=legend><span><i class="counterkey rx"></i>RX total</span><span><i class="counterkey tx"></i>TX total</span><span>Bars compare current counters; they are not time buckets.</span>`)
	if idle {
		b.WriteString(`<span class=ok>Idle · 0 B sampled</span>`)
	}
	b.WriteString(`</div>`)
}

func counterHeight(value, maxValue int64) int {
	if value <= 0 || maxValue <= 0 {
		return 1
	}
	height := scaledCounterValue(value, maxValue, 100)
	if height < 4 {
		return 4
	}
	return height
}

func overviewCounterHeight(value, maxValue int64) int {
	if value <= 0 || maxValue <= 0 {
		return 2
	}
	return 8 + scaledCounterValue(value, maxValue, 82)
}

// scaledCounterValue computes a presentation ratio without multiplying int64
// counters first. WireGuard counters can approach MaxInt64; value*scale would
// overflow before the division even though the final percentage is small.
func scaledCounterValue(value, maxValue int64, scale int) int {
	if value <= 0 || maxValue <= 0 || scale <= 0 {
		return 0
	}
	if value >= maxValue {
		return scale
	}
	scaled := int((float64(value) / float64(maxValue)) * float64(scale))
	if scaled < 0 {
		return 0
	}
	if scaled > scale {
		return scale
	}
	return scaled
}

const maxCounterValue int64 = 1<<63 - 1

func saturatingCounterAdd(total, value int64) int64 {
	total, value = nonNegative(total), nonNegative(value)
	if value > maxCounterValue-total {
		return maxCounterValue
	}
	return total + value
}

func tunnelCounterBytes(tunnel TunnelView) int64 {
	return saturatingCounterAdd(tunnel.RxBytes, tunnel.TxBytes)
}

func presentCounterTunnels(tunnels []TunnelView) []TunnelView {
	present := make([]TunnelView, 0, len(tunnels))
	for _, tunnel := range tunnels {
		if tunnel.CounterPresent {
			present = append(present, tunnel)
		}
	}
	return present
}

func currentCounterTrustText(n NodeView) string {
	switch {
	case n.Self && n.Reached:
		return "Direct-self /status counter evidence."
	case n.TrafficVerified:
		return "Independently signed loom-traffic-v1 relay counter evidence."
	case n.Reached:
		return "Direct /status counter evidence from this node."
	case n.TrafficTrusted:
		return "Trusted current counter evidence."
	default:
		return "Current tunnel counter evidence is present."
	}
}

func enabledText(enabled bool) string {
	if enabled {
		return "Enabled"
	}
	return "Disabled / not applicable"
}
