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
	b.WriteString(`</span></div><div class=card><table><thead><tr><th>Node / lifecycle<th>Declared endpoint / SSH port<th>Role / direction<th>Observation<th>Snapshot<th>Tunnels<th>Last seen<th></thead><tbody>`)
	for _, n := range v.Nodes {
		stateClass, stateLabel := healthVisual(n.Health)
		lifecycleClass, lifecycleLabel := nodeLifecycleVisual(n)
		carrierTotal, active := carrierTunnelCount(n.Tunnels)
		role := nodeRoleLabel(n)
		direction := n.Direction
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
		b.WriteString(`<div class=section><details class=card><summary><b>Enrollment SSH access</b> <span class=dim>shared control identity and trust boundary</span></summary><div class="grid section"><div class=span8><h2>Control bootstrap identity</h2><h3>One identity for the control plane</h3><p class=dim>A node enrollment reuses the same control SSH public key. It does not create a per-node control key, replace platform signing trust, or export a node WireGuard private key.</p>`)
		if d.Control.BootstrapIdentity == nil {
			b.WriteString(`<div class="callout warnline"><b>Unavailable on this node</b><br><span class=small>The shared bootstrap identity is a control-local capability.</span></div>`)
		} else if key, err := d.Control.BootstrapIdentity.Status(); err != nil {
			fmt.Fprintf(&b, `<div class="card notice badline"><b>Bootstrap identity cannot be read</b><br><span class=small>%s</span></div>`, esc(err.Error()))
		} else if !key.Ready {
			b.WriteString(`<div class="callout warnline"><b>Not generated</b><br><span class=small>Generate this once, then manually authorize the exported public key on every host that may be enrolled.</span></div><div class=section>`)
			if isAuthed {
				b.WriteString(`<form method=post action="/nodes/bootstrap-key/generate"><button class=primary>Generate shared key pair</button></form>`)
			} else {
				b.WriteString(`<a class="button primary" href="/login">Sign in to generate</a>`)
			}
			b.WriteString(`</div>`)
		} else {
			fmt.Fprintf(&b, `<div class=kv><dt>Status<dd class=ok>Ready · reused by every enrollment<dt>Fingerprint<dd class=mono>%s<dt>Public file<dd class=mono>%s</div><textarea class=compact readonly aria-label="Shared control public key">%s</textarea><div class=toolbar><a class=button href="/nodes/bootstrap-key.pub">Download public key</a></div>`, esc(key.Fingerprint), esc(key.PublicPath), esc(key.PublicKey))
		}
		b.WriteString(`<div class=callout><b>Key boundary</b><br><span class=small>The private half stays on the control node. A new node creates or reuses its own WireGuard identity during bootstrap; only that public key may enter SSOT.</span></div></div>
<div class=span4><h2>Enrollment boundary</h2><div class=kv><dt>Manual input<dd>SSH host or IP, user, port<dt>Discovered<dd>Hostname, host key, system, reachability<dt>Reviewed<dd>Direction policy<dt>Default<dd>Egress enabled</div><div class=section><a class=button href="/nodes/add">Open enrollment workflow →</a></div></div></div></details></div>`)
	}

	return shell(d, "Nodes", b.String(), isAuthed, v)
}

func pageTopology(d Deps, isAuthed bool, selectedEntry ...string) string {
	v := d.Snapshot()
	now := d.Now().UTC()
	intentSource := intentSourceLabel(v)
	selected := ""
	if len(selectedEntry) > 0 {
		selected = selectedEntry[0]
	}
	entries := routingEntryOptions(v)
	var overlay []RouteView
	for _, route := range v.Routes {
		if routingRouteKey(route) == selected && !route.Stale {
			overlay = append(overlay, route)
		}
	}
	tunnels, active, candidates := 0, 0, 0
	for _, l := range v.Links {
		if l.Kind == "tunnel" {
			tunnels++
			if l.State == "active" {
				active++
			}
		} else if l.Kind == "candidate" {
			candidates++
		}
	}
	fresh := 0
	for _, r := range v.Routes {
		if !r.Stale {
			fresh++
		}
	}

	var b strings.Builder
	b.WriteString(`<div class=sectionhead><h2>Network layers</h2><span class=dim>Carrier and observation are always shown; one Agent path may be overlaid for attribution.</span><span class=sp><form method=get action="/topology"><select name=entry aria-label="Agent path overlay"><option value="">No Agent path overlay</option>`)
	for _, entry := range entries {
		attr := ""
		if entry.Key == selected {
			attr = " selected"
		}
		fmt.Fprintf(&b, `<option value="%s"%s>%s</option>`, esc(entry.Key), attr, esc(entry.Label))
	}
	b.WriteString(`</select> <button>Apply</button></form></span></div>`)
	fmt.Fprintf(&b, `<div class=grid><div class="card span9">%s<div class=legend><span><i class=key></i>Persistent WG</span><span><i class="key candidate"></i>Inventory candidate</span><span><i class="key route"></i>Selected Agent path only</span><span><i class="key degraded"></i>Degraded observation</span><span><i class="key failed"></i>Failed observation</span></div><p class="tiny dim">Layers do not collapse into one another: a candidate comes from %s, a WireGuard edge is carrier structure, and an Agent path is shown only when one routing entry is selected above.</p></div>`, topologySVG(v, overlay...), esc(intentSource))
	fmt.Fprintf(&b, `<div class="card span3"><h2>Layer status</h2><div class=stack>
<div><div class=label>Inventory intent</div><div class=metric>%d <small>WG edges</small></div><div class=dim>%d candidate hops · %s</div></div>
<div><div class=label>Trusted observation</div><div class="metric %s">%d <small>/ %d active</small></div><div class=dim>unknown remains unknown</div></div>
<div><div class=label>Agent decisions</div><div class=metric>%d <small>fresh</small></div><div class=dim>%d current entries · %d overlaid</div></div>
</div></div></div>`, tunnels, candidates, esc(intentSource), map[bool]string{true: "ok", false: "warn"}[active == tunnels && tunnels > 0], active, tunnels, fresh, len(v.Routes), len(overlay))

	writeTopologyTraffic(&b, v)

	b.WriteString(`<div class=section><div class=sectionhead><h2>Persistent and candidate edges</h2><span class=dim>Observation state, timestamp and source stay together</span></div><div class=card><table><tr><th>Edge<th>Layer<th>State<th>RTT<th>Observed<th>Source</tr>`)
	links := append([]LinkView(nil), v.Links...)
	sort.Slice(links, func(i, j int) bool {
		return links[i].Kind+links[i].From+links[i].To < links[j].Kind+links[j].From+links[j].To
	})
	for _, l := range links {
		cls := "dim"
		switch l.State {
		case "active":
			cls = "ok"
		case "degraded":
			cls = "warn"
		case "failed":
			cls = "bad"
		}
		rtt := "—"
		if l.MS > 0 {
			rtt = fmt.Sprintf("%dms", l.MS)
		}
		fmt.Fprintf(&b, `<tr><td class=mono>%s ↔ %s<td>%s<td class=%s>%s<td>%s<td>%s<td class="w tiny">%s</tr>`, esc(l.From), esc(l.To), esc(l.Kind), cls, esc(l.State), rtt, esc(ageText(l.ObservedAt, now)), esc(l.Source))
	}
	if len(links) == 0 {
		b.WriteString(`<tr><td colspan=6><div class=empty>No topology edges are present in the current view.</div></tr>`)
	}
	b.WriteString(`</table></div></div>`)
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
	fmt.Fprintf(&b, `<div class=grid><div class="card span4"><div class=label>Agent path decisions</div><div class=metric>%d</div><div class=dim>runtime observations · not desired state</div></div><div class="card span4"><div class=label>Fresh</div><div class="metric ok">%d <small>/ %d</small></div><div class=dim>each entry has its own timestamp</div></div><div class="card span4"><div class=label>Inventory candidates</div><div class=metric>%d</div><div class=dim>%s · intent, not health claims</div></div></div>`, len(v.Routes), fresh, len(v.Routes), len(v.Candidates), esc(intentSource))
	b.WriteString(`<div class=section><div class=sectionhead><h2>Routing entry</h2><span class=dim>Focus one service or access policy; alternatives below belong to the same entry.</span><span class=sp><form method=get action="/routing"><select name=entry aria-label="Routing entry">`)
	for _, entry := range entries {
		attr := ""
		if entry.Key == selected {
			attr = " selected"
		}
		fmt.Fprintf(&b, `<option value="%s"%s>%s</option>`, esc(entry.Key), attr, esc(entry.Label))
	}
	b.WriteString(`</select> <button>View</button></form></span></div>`)
	b.WriteString(`<div class=card><div class=sectionhead><h2>Current Agent path</h2><span class=dim>Reported by the access Agent; historical events are not current state.</span><span class=sp><a class=tiny href="/topology?entry=` + queryEscape(selected) + `">Overlay in topology →</a></span></div>`)
	if len(routes) == 0 {
		b.WriteString(`<div class=empty>No verifiable current Agent decisions are available. Historical events are not used as current state.</div>`)
	} else {
		b.WriteString(`<table><tr><th>Access node<th>Entry<th>Current path<th>Candidate health<th>Observed / source<th>Reason</tr>`)
		for _, r := range routes {
			path := strings.Join(r.Chain, " → ")
			if len(r.Chain) <= 1 {
				path = r.Node + " → direct"
			}
			entry := routeEntryLabel(r)
			cls := "ok"
			if r.Stale {
				cls = "warn"
			}
			health := candidateHealthText(r.Health)
			fmt.Fprintf(&b, `<tr><td class=mono>%s<td class=w>%s<td class="w mono %s">%s<td class=w>%s<td class=w>%s<br><span class="tiny dim">%s</span><td class=w>%s</tr>`, esc(r.Node), esc(entry), cls, esc(path), health, esc(ageText(r.ObservedAt, now)), esc(r.Source), esc(r.Reason))
		}
		b.WriteString(`</table>`)
	}
	b.WriteString(`</div></div>`)

	b.WriteString(`<div class=section><div class=sectionhead><h2>Allowed alternatives for this entry</h2><span class=dim>A missing persistent edge does not mean two topology nodes have no candidate path</span></div><div class=card>`)
	if len(candidatesForEntry) == 0 {
		b.WriteString(`<div class=empty>No configured candidate paths are available for this routing entry.</div>`)
	} else {
		b.WriteString(`<table><tr><th>Access node<th>Entry<th>Path<th>Evidence<th>Source</tr>`)
		for _, p := range candidatesForEntry {
			path := strings.Join(p.Chain, " → ")
			if len(p.Chain) <= 1 {
				path = p.Node + " → direct"
			}
			cls, label := "warn", "Configured · unverified"
			if p.State == "selected" {
				cls, label = "ok", "Current Agent decision"
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
		return strings.Join(n.Roles, " + ")
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

func nodeLocationLabel(n NodeView) string {
	parts := []string{}
	for _, value := range []string{n.Name, n.City, n.Provider} {
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
