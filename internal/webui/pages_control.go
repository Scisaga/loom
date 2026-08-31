package webui

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func pageServices(d Deps, selected string, create bool, message string, failed bool, submitted *ServiceInput, isAuthed bool) string {
	v := d.Snapshot()
	if submitted != nil {
		selected = submitted.ID
	}
	if selected == "" && !create && len(v.Services) > 0 {
		selected = v.Services[0].ID
	}
	var current *ServiceView
	if !create {
		for i := range v.Services {
			if v.Services[i].ID == selected {
				current = &v.Services[i]
				break
			}
		}
	}
	revision := ""
	revisionErr := error(nil)
	if d.Control != nil && d.Control.Revision != nil {
		revision, revisionErr = d.Control.Revision()
	}
	hostRules := 0
	for _, svc := range v.Services {
		hostRules += len(svc.Hosts)
	}
	var b strings.Builder
	if message != "" {
		cls := "callout"
		if failed {
			cls = "callout warnline"
		}
		fmt.Fprintf(&b, `<div class="%s"><b>%s</b></div>`, cls, esc(message))
	}
	if revisionErr != nil {
		fmt.Fprintf(&b, `<div class="card notice badline"><b>Structured writes unavailable</b><br><span class=small>%s</span></div>`, esc(revisionErr.Error()))
	}
	fmt.Fprintf(&b, `<div class=services-summary>
<div class=services-summary-item><div class=label>Services</div><div class=metric>%d <small>configured</small></div><div class=dim>request destination groups</div></div>
<div class=services-summary-item><div class=label>Host rules</div><div class=metric>%d</div><div class=dim>exact host or DNS suffix</div></div>
<div class=services-summary-item><div class=label>Access policies</div><div class=metric>%d</div><div class=dim>govern path selection</div></div>
</div>
<div class=services-flow><span class=services-flow-label>Request routing</span><b>Host</b><span aria-hidden=true>→</span> Service <span aria-hidden=true>→</span> Policy <span aria-hidden=true>→</span> live path</div>`, len(v.Services), hostRules, len(v.Policies))

	b.WriteString(`<div class=services-workspace><aside class="card service-catalog"><div class=service-catalog-head><div><h2>Service catalog</h2><span class=dim>Destination groups</span></div>`)
	if d.Control != nil {
		b.WriteString(`<span class=sp><a class=button href="/services?new=1">＋ Add</a></span>`)
	}
	b.WriteString(`</div><div class=service-catalog-list>`)
	if len(v.Services) == 0 {
		b.WriteString(`<div class=empty>No services are configured. Unmatched request hosts remain fail-closed.</div>`)
	} else {
		for _, svc := range v.Services {
			cls := "catalogrow"
			ariaCurrent := ""
			if svc.ID == selected {
				cls += " selected"
				ariaCurrent = ` aria-current=page`
			}
			name := svc.Name
			if name == "" {
				name = svc.ID
			}
			fmt.Fprintf(&b, `<a href="/services?service=%s"%s><div class="%s"><div class=service-catalog-name>%s</div><div class=service-catalog-id><span class=mono>%s</span><span class="badge intent">%s</span></div><div class="tiny dim">%d host rules</div></div></a>`, queryEscape(svc.ID), ariaCurrent, cls, esc(name), esc(svc.ID), esc(svc.PolicyID), len(svc.Hosts))
		}
	}
	b.WriteString(`</div></aside>`)

	b.WriteString(`<section class="card service-editor">`)
	if current == nil && !create && submitted == nil {
		b.WriteString(`<div class=service-editor-empty><div class=empty>Select a service to inspect its SSOT definition.</div></div>`)
	} else {
		svc := ServiceView{}
		if current != nil {
			svc = *current
		}
		if submitted != nil {
			svc.ID = submitted.ID
			svc.Name = submitted.Name
			svc.PolicyID = submitted.Declaration
			svc.Addresses = append([]string(nil), submitted.Addresses...)
		}
		title, status := "Edit service", `<span class="badge ok"><span class=dot></span>In SSOT</span>`
		if create {
			title, status = "Add service", `<span class="badge warn"><span class=dot></span>Not saved</span>`
		} else if failed && submitted != nil {
			status = `<span class="badge warn"><span class=dot></span>Submitted values · not saved</span>`
		}
		fmt.Fprintf(&b, `<div class=service-editor-head><div><h2>%s</h2><span class=dim>Host group and routing governance</span></div><span class=sp>%s</span></div><div class=service-editor-body>`, title, status)
		canWrite := d.Control != nil && d.Control.Services != nil && isAuthed && revisionErr == nil
		if canWrite {
			fmt.Fprintf(&b, `<form class="blockform service-form" data-submit-progress method=post action="/services/save"><input type=hidden name=revision value="%s"><div class=service-primary-fields><div class=field><label>Service ID</label><input class=mono name=id value="%s" %s required><span class=field-hint>Stable ID · cannot be renamed after creation</span></div><div class=field><label>Display name</label><input name=name value="%s" placeholder="Human-readable name"><span class=field-hint>Operator-facing label used across the control center</span></div><div class=field><label>Access policy</label><select name=declaration required>%s</select><span class=field-hint>Fixed exit pins the final node; relay selection still minimizes latency, with threshold-based anti-flap</span></div></div><div class=service-host-rules><div class=service-subhead><div><label>Host rules</label><span>One exact hostname or <code>.suffix</code> per line</span></div><span class="badge dim">%d rules</span></div><textarea class=compact name=addresses spellcheck=false required aria-label="Host rules">%s</textarea><div class=service-rule-help><span><code>api.example.com</code> exact host</span><span><code>.example.com</code> DNS suffix</span><span>Unmatched hosts are rejected (fail closed)</span></div></div><div class=service-form-actions><span class="small dim">Saving validates SSOT and triggers signed distribution.</span><div class=toolbar><a class=button href="/services?service=%s">Discard changes</a><button class="green progress-submit" name=action value=save><span class=button-idle>Validate &amp; save</span><span class=button-busy><i class=button-spinner aria-hidden=true></i>Saving…</span></button></div></div></form>`,
				esc(revision), esc(svc.ID), map[bool]string{true: "", false: "readonly"}[create], esc(svc.Name), policyOptions(v.Policies, svc.PolicyID), len(svc.Addresses), esc(strings.Join(svc.Addresses, "\n")), queryEscape(svc.ID))
			if !create {
				fmt.Fprintf(&b, `<div class=service-danger><div><b>Danger zone</b><span>Delete this destination group from the next SSOT revision.</span></div><form method=post action="/services/delete"><input type=hidden name=revision value="%s"><input type=hidden name=id value="%s"><input type=hidden name=name value="%s"><input type=hidden name=declaration value="%s"><textarea hidden name=addresses>%s</textarea><button class=danger-button name=action value=delete>Delete service</button></form></div>`, esc(revision), esc(svc.ID), esc(svc.Name), esc(svc.PolicyID), esc(strings.Join(svc.Addresses, "\n")))
			}
		} else {
			fmt.Fprintf(&b, `<div class=service-primary-fields><div class=field><label>Service ID</label><div class="readonly-value mono">%s</div></div><div class=field><label>Display name</label><div class=readonly-value>%s</div></div><div class=field><label>Access policy</label><div class="readonly-value mono">%s</div></div></div><div class=service-host-rules><div class=service-subhead><div><label>Host rules</label><span>Every matching hostname is carried as this Service</span></div><span class="badge dim">%d rules</span></div><div class=service-rule-list>`, esc(svc.ID), esc(svc.Name), esc(svc.PolicyID), len(svc.Hosts))
			for _, h := range svc.Hosts {
				fmt.Fprintf(&b, `<div><code>%s</code><span class=badge>%s</span></div>`, esc(h.Host), esc(h.Match))
			}
			b.WriteString(`</div><div class=service-rule-help><span>Unmatched hosts are rejected (fail closed)</span></div></div>`)
		}
		b.WriteString(`<div class=service-state-note><span class=service-state-icon>i</span><span>This page edits desired state. Current path and health remain observations in <a href="/routing">Live paths</a>.</span></div>`)
		if d.Control == nil {
			b.WriteString(`<p class="small warn service-editor-access">Structured writes are available only on the control node.</p>`)
		} else if !isAuthed {
			b.WriteString(`<p class="small service-editor-access"><a class="button primary" href="/login">Sign in to edit</a></p>`)
		} else if d.Control.Services == nil {
			b.WriteString(`<p class="small service-editor-access"><a class=button href="/settings">Open validated SSOT editor</a> <span class=dim>Structured Service transactions are unavailable in this build.</span></p>`)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</section></div>`)

	fmt.Fprintf(&b, `<details class="card services-policy-library"><summary><span><b>Access policies</b><small>Policy is governance; Service is the request-derived routing unit</small></span><span class="sp">%d available · View all</span></summary><div class=policy-grid>`, len(v.Policies))
	if len(v.Policies) == 0 {
		b.WriteString(`<div class=empty>No access policies are available in the validated control view.</div>`)
	} else {
		policies := append([]PolicyView(nil), v.Policies...)
		sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
		for _, p := range policies {
			fmt.Fprintf(&b, `<article class=policy-card><div class=policy-card-head><div><b class=mono>%s</b><span>%s</span></div><span class="badge intent">%s</span></div><div class=policy-card-servers><span>Eligible nodes</span><code>%s</code></div><div class=policy-card-meta><span><b>%d</b> max hops</span><span><b>%s</b> tuning</span><span><b>%s</b> window · %d samples</span><span><b>%s</b> fallback</span></div></article>`, esc(p.ID), esc(p.Name), esc(objectiveLabel(p.Objective)), esc(strings.Join(p.AllowedServers, " · ")), p.MaxHops, esc(p.TuningPeriod), esc(p.Window), p.MinSamples, esc(p.Fallback))
		}
	}
	b.WriteString(`</div></details>`)
	return shell(d, "Services", b.String(), isAuthed, v)
}

type nodeAddPageState struct {
	Phase        string
	Connection   EnrollmentConnection
	HostKey      EnrollmentHostKey
	DisableGeoIP bool
	Review       *EnrollmentReview
	Error        string
	Committed    bool
}

func pageNodeAdd(d Deps, state nodeAddPageState, isAuthed bool) string {
	if state.Phase == "" {
		state.Phase = "connect"
	}
	var b strings.Builder
	stepState := func(step string) string {
		if state.Phase == step {
			return `<span class="badge ok"><span class=dot></span>Current</span>`
		}
		order := map[string]int{"connect": 1, "confirm": 2, "review": 3}
		if order[state.Phase] > order[step] {
			return `<span class="badge ok"><span class=dot></span>Complete</span>`
		}
		return `<span class="badge dim"><span class=dot></span>Next</span>`
	}
	fmt.Fprintf(&b, `<div class=steps>
<div class=step><span class=label>1 · Connect</span><b>SSH coordinates</b>%s</div>
<div class=step><span class=label>2 · Trust</span><b>Confirm host identity</b>%s</div>
<div class=step><span class=label>3 · Review</span><b>Identity, direction and plan</b>%s</div>
<div class=step><span class=label>4 · Commit</span><b>Prepare WG identity + save declaration</b></div>
</div>`, stepState("connect"), stepState("confirm"), stepState("review"))

	if state.Error != "" {
		title := "Enrollment stopped without changing SSOT"
		note := ""
		if state.Committed {
			title = "SSOT content changed, but durability confirmation failed"
		} else if strings.Contains(state.Error, "local control service stopped or restarted") {
			title = "Enrollment was interrupted locally — safe to retry"
			note = `<br><span class="small dim">The remote host did not reject enrollment. Submit the preflight again after the control service is stable.</span>`
		} else if strings.Contains(state.Error, "install wireguard-tools") || strings.Contains(state.Error, "did not find the wg command after automatic installation") {
			title = "Automatic WireGuard tools installation failed"
			note = `<br><span class="small dim">The trusted preflight installs <code>wireguard-tools</code> through a supported package manager when root or passwordless sudo is available. Review the package-manager error and retry; SSOT was not changed.</span>`
		} else if strings.Contains(state.Error, "cannot be normalized into a valid Node ID") {
			title = "Remote hostname cannot be converted to a Node ID"
			note = `<br><span class="small dim">Loom automatically lowercases the remote short hostname and converts separator runs to hyphens. This hostname still has no safe canonical result, so SSOT was not changed.</span>`
		}
		fmt.Fprintf(&b, `<div class="card notice badline section"><b>%s</b><br><span class=small>%s</span>%s</div>`, esc(title), esc(state.Error), note)
	}
	if d.Control == nil {
		b.WriteString(`<div class="card notice section"><span class=warn>This machine is not the control node; enrollment is intentionally unavailable here.</span></div>`)
		return shell(d, "Add node", b.String(), isAuthed)
	}
	if !isAuthed {
		b.WriteString(`<div class="card section"><h2>Write session required</h2><p>The SSH trust store and SSOT are control-local write boundaries.</p><a class="button primary" href="/login">Sign in to enroll nodes</a></div>`)
		return shell(d, "Add node", b.String(), false)
	}
	if d.Control.Enrollment == nil {
		b.WriteString(`<div class="card notice section"><b>Enrollment executor unavailable</b><br><span class=small>This build can manage the shared public key, but cannot safely scan, preflight and transact a node.</span></div>`)
		return shell(d, "Add node", b.String(), true)
	}

	key, keyErr := BootstrapIdentityView{}, error(nil)
	if d.Control.BootstrapIdentity == nil {
		keyErr = fmt.Errorf("shared control SSH identity is unavailable")
	} else {
		key, keyErr = d.Control.BootstrapIdentity.Status()
	}
	if keyErr != nil {
		fmt.Fprintf(&b, `<div class="card notice badline section"><b>Cannot read shared control identity</b><br><span class=small>%s</span></div>`, esc(keyErr.Error()))
		return shell(d, "Add node", b.String(), true)
	}
	if !key.Ready {
		b.WriteString(`<div class="card section"><h2>Generate the control identity first</h2><p class=dim>One key pair is generated once and reused for every enrollment; adding a node never creates another control key.</p><form method=post action="/nodes/bootstrap-key/generate"><button class=primary>Generate shared key pair</button></form></div>`)
		return shell(d, "Add node", b.String(), true)
	}

	switch state.Phase {
	case "confirm":
		writeNodeAddConfirm(&b, state, key)
	case "review":
		if state.Review == nil {
			b.WriteString(`<div class="card notice badline section">The review payload is unavailable. Run SSH discovery again.</div>`)
			writeNodeAddConnect(&b, state.Connection, key)
		} else {
			writeNodeAddReview(&b, d, *state.Review, key)
		}
	default:
		writeNodeAddConnect(&b, state.Connection, key)
	}
	return shell(d, "Add node", b.String(), true)
}

func writeNodeAddConnect(b *strings.Builder, connection EnrollmentConnection, key BootstrapIdentityView) {
	if connection.Port == 0 {
		connection.Port = 22
	}
	fmt.Fprintf(b, `<div class=section><div class=grid>
<div class="card span5"><div class=sectionhead><h2>Connect to the remote host</h2><span class="sp badge ok"><span class=dot></span>Shared key ready</span></div>
<p class=small>The public key below must already be present in the remote account's <code>authorized_keys</code>.</p>
<textarea class=compact readonly aria-label="Shared control public key">%s</textarea><div class="tiny dim mono">%s</div>
<div class=section><form class=blockform data-submit-progress method=post action="/nodes/add/scan"><div class=fields>
<div class="field span6"><label>Host or IP address</label><input name=host value="%s" placeholder="203.0.113.42" required></div>
<div class="field span4"><label>SSH user</label><input name=user value="%s" placeholder="loom-bootstrap" required></div>
<div class="field span2"><label>Port</label><input name=port type=number min=1 max=65535 value="%d" required></div>
</div><div class="toolbar section"><button class="primary progress-submit"><span class=button-idle>Scan SSH host key</span><span class=button-busy><i class=button-spinner aria-hidden=true></i>Scanning SSH key…</span></button><a class=button href="/nodes">Cancel</a></div></form></div></div>
<div class="card span7"><h2>What the control plane will and will not infer</h2>
<div class=kv><dt>Initial input<dd>SSH host or IP, user and port only<dt>Node ID<dd>Derived from verified remote <code>hostname -s</code>; case and separators are normalized<dt>Location<dd>Country and city are suggested from the public endpoint IP, then remain editable and require declaration review; the lookup can be disabled before preflight<dt>Prerequisite<dd>Missing <code>wireguard-tools</code> is installed automatically through root or passwordless sudo<dt>Egress<dd>Enabled for every new server node<dt>Direction<dd>Reviewed after preflight; Automatic is conservative without UDP evidence<dt>WG identity<dd>Generated or reused on the remote host; only its public key returns</div>
<div class="callout warnline section"><b>SSH reachability is not UDP reachability</b><br><span class=small>A successfully authenticated SSH host that resolves to a global address may become a control-observed endpoint candidate. Private/local-only addresses stop the workflow, and no page labels an untested UDP endpoint as verified.</span></div>
</div></div></div>`, esc(key.PublicKey), esc(key.Fingerprint), esc(connection.Host), esc(connection.User), connection.Port)
}

func writeNodeAddConfirm(b *strings.Builder, state nodeAddPageState, key BootstrapIdentityView) {
	c := state.Connection
	h := state.HostKey
	disableGeoIPChecked := ""
	if state.DisableGeoIP {
		disableGeoIPChecked = " checked"
	}
	fmt.Fprintf(b, `<div class=section><div class=grid>
<div class="card span5"><h2>Connection request</h2><div class=kv><dt>Destination<dd class=mono>%s@%s:%d<dt>Control identity<dd class=mono>%s<dt>Use<dd>Shared bootstrap management credential</div><p class="small dim">Changing any coordinate requires a new scan. Loom does not remove this key from remote <code>authorized_keys</code>; rotate or revoke it through the host's management process.</p><a class=button href="/nodes/add">Use different coordinates</a></div>
<div class="card span7"><div class=sectionhead><h2>Confirm SSH host identity</h2><span class="sp badge warn"><span class=dot></span>Operator decision</span></div>
<p>Compare this fingerprint with an independent source for the remote host. The control plane re-scans immediately before trusting it; a changed key fails closed.</p>
<div class=callout><div class=label>Ed25519 fingerprint</div><div class="metric mono">%s</div><div class="tiny mono clip">%s %s</div></div>
<form class=blockform data-submit-progress method=post action="/nodes/add/review">%s
<label class="checkline section"><input type=checkbox name=confirm_host_key value=yes required> I independently confirmed this host fingerprint</label>
<label class=checkline><input type=checkbox name=disable_geoip value=yes%s> Do not send the public endpoint IP to the advisory GeoIP service</label>
<div class="toolbar section"><button class="green progress-submit"><span class=button-idle>Trust key &amp; run preflight</span><span class=button-busy role=status aria-live=polite><i class=button-spinner aria-hidden=true></i>Checking and installing prerequisites…</span></button><a class=button href="/nodes/add">Cancel</a></div></form>
</div></div></div>`, esc(c.User), esc(c.Host), c.Port, esc(key.Fingerprint), esc(h.Fingerprint), esc(h.Algorithm), esc(h.PublicKey), enrollmentHidden(c, h), disableGeoIPChecked)
}

func writeNodeAddReview(b *strings.Builder, d Deps, review EnrollmentReview, key BootstrapIdentityView) {
	c, h := review.Connection, review.HostKey
	country := strings.ToUpper(strings.TrimSpace(review.Country))
	city := strings.TrimSpace(review.City)
	locationParts := make([]string, 0, 2)
	if city != "" {
		locationParts = append(locationParts, city)
	}
	if country != "" {
		locationParts = append(locationParts, country)
	}
	locationDisplay, locationMetricClass := strings.Join(locationParts, " · "), "metric"
	if locationDisplay == "" {
		locationDisplay, locationMetricClass = "Not set", "metric dim"
	}
	geoIPEvidence := strings.TrimSpace(review.GeoIPEvidence)
	if geoIPEvidence == "" {
		geoIPEvidence = "GeoIP suggestion status is unavailable; country and city remain operator-editable."
	}
	geoIPClass := "callout"
	if strings.Contains(strings.ToLower(geoIPEvidence), "unavailable") {
		geoIPClass += " warnline"
	}
	disableGeoIPChecked := ""
	if review.DisableGeoIP {
		disableGeoIPChecked = " checked"
	}
	wgToolsNote := ""
	if review.WireGuardToolsInstalled {
		wgToolsNote = `<br><span class="tiny ok">wireguard-tools installed automatically during this preflight</span>`
	}
	reviewedDirection := strings.TrimSpace(review.RequestedDirection)
	if reviewedDirection == "" {
		reviewedDirection = "automatic"
	}
	reviewToken := mintEnrollmentReviewToken(d, EnrollmentCommitInput{
		EnrollmentReviewInput: EnrollmentReviewInput{
			Connection: c, HostKey: h, Country: country, City: city,
			DisableGeoIP: review.DisableGeoIP, RequestedDirection: reviewedDirection,
		},
		ExpectedNodeID: review.NodeID, ExpectedEndpoint: review.PublicEndpoint,
		ExpectedEndpointResolution: review.EndpointResolution, ExpectedRevision: review.Revision,
	})
	fmt.Fprintf(b, `<div class=section><div class=grid>
<div class="card span5"><div class=sectionhead><h2>Trusted remote observation</h2><span class="sp badge ok"><span class=dot></span>Preflight passed</span></div>
<div class=kv><dt>SSH destination<dd class=mono>%s@%s:%d<dt>Host key<dd class=mono>%s<dt>Node ID<dd><b class=mono>%s</b><br><span class="tiny dim">derived from remote hostname <code>%s</code></span><dt>System<dd>%s<dt>Privilege<dd>%s<dt>WireGuard<dd>kernel %s · tools %s%s</div>
<div class="callout section"><b>Shared control key</b><br><span class="small mono">%s</span><br><span class="tiny dim">Reused for SSH bootstrap only; not a node WG or platform signing key.</span></div></div>
<div class="card span7"><div class=sectionhead><h2>Review network declaration</h2><span class="sp badge warn"><span class=dot></span>Not committed</span></div>
<div class=grid><div class="span4"><div class=label>Public endpoint candidate</div><div class="metric mono">%s</div><div class="tiny dim">%s</div></div><div class="span4"><div class=label>Country / city</div><div class="%s">%s</div><div class="tiny dim">operator-reviewed declaration metadata</div></div><div class="span2"><div class=label>Direction</div><div class=metric>%s</div><div class="tiny dim">%s</div></div><div class="span2"><div class=label>Egress</div><div class="metric ok">Enabled</div><div class="tiny dim">new-node default</div></div></div>
<div class="%s section"><b>GeoIP is an editable suggestion, not proof</b><br><span class=small>%s The control node sends the selected public endpoint IP to <code>ipwho.is</code>; lookup failure never blocks enrollment.</span></div>
<div class="callout warnline"><b>Endpoint evidence boundary</b><br><span class=small>The authenticated SSH target resolves to a globally routable endpoint candidate, but the control plane has not verified WireGuard UDP ingress. Automatic therefore resolves to <code>reverse_only</code>; choose a more exposed direction only when that policy is independently justified.</span></div>
<div class=section><div class=sectionhead><h2>Proposed persistent tunnels</h2><span class=dim>Recomputed from direction and current SSOT</span></div>`, esc(c.User), esc(c.Host), c.Port, esc(h.Fingerprint), esc(review.NodeID), esc(review.ObservedHostname), esc(review.System), esc(review.Privilege), yesNo(review.KernelWireGuard), yesNo(review.WGCommand), wgToolsNote, esc(key.Fingerprint), esc(review.PublicEndpoint), esc(review.EndpointEvidence), locationMetricClass, esc(locationDisplay), esc(review.ResolvedDirection), esc(review.DirectionEvidence), geoIPClass, esc(geoIPEvidence))
	if len(review.Tunnels) == 0 {
		b.WriteString(`<div class=empty>No persistent WireGuard tunnel is required by the current direction matrix. Dynamic public paths remain separate routing candidates.</div>`)
	} else {
		b.WriteString(`<table><tr><th>Edge<th>Tunnel addresses<th>Initiator<th>Acceptor / listen</tr>`)
		for _, tunnel := range review.Tunnels {
			fmt.Fprintf(b, `<tr><td class=mono>%s ↔ %s<td class="mono w">%s ↔ %s<td class=mono>%s<td class=mono>%s · %d/udp</tr>`, esc(tunnel.From), esc(tunnel.To), esc(tunnel.FromAddress), esc(tunnel.ToAddress), esc(tunnel.Initiator), esc(tunnel.Acceptor), tunnel.ListenPort)
		}
		b.WriteString(`</table>`)
	}
	if review.FixedPolicyID != "" {
		fmt.Fprintf(b, `<div class="callout section"><b>Fixed exit policy added automatically</b><br><span class=small><code>%s</code> · %s · lowest latency (P50). The final egress is pinned to this node; secure credential provisioning activates it for access nodes.</span></div>`, esc(review.FixedPolicyID), esc(review.FixedPolicyName))
	}
	fmt.Fprintf(b, `</div><div class=section>
<form class=blockform data-submit-progress method=post action="/nodes/add/commit">%s
<div class=fields><div class="field span2"><label>Country</label><input class=mono name=country maxlength=2 pattern="[A-Za-z]{2}" value="%s" placeholder="HK"></div><div class="field span4"><label>City <span class=dim>(optional)</span></label><input name=city maxlength=80 value="%s" placeholder="e.g. Hong Kong"></div><div class="field span3"><label>Direction policy</label><select name=direction>%s</select></div><div class="field span3"><label>Effect</label><div class=callout>Recomputes the declaration; it cannot save SSOT.</div></div></div>
<label class=checkline><input type=checkbox name=disable_geoip value=yes%s> Do not use GeoIP suggestions for empty country or city fields</label>
<p class="tiny dim">Country is stored as an uppercase ISO 3166-1 alpha-2 code. Edit either suggestion and recompute so the exact country, city and direction are locked for commit.</p>
<div class=toolbar><button class=progress-submit name=action value=preview><span class=button-idle>Recompute &amp; review declaration</span><span class=button-busy><i class=button-spinner aria-hidden=true></i>Rechecking remote host…</span></button></div></form>
</div><div class=section><div class=callout><b>Reviewed direction is locked for commit</b><br><span class=small><code>%s</code> resolved to <code>%s</code>. To use another direction, recompute and review it above first.</span></div>
<form class=blockform data-submit-progress method=post action="/nodes/add/commit">%s
<input type=hidden name=direction value="%s"><input type=hidden name=reviewed_direction value="%s">
<input type=hidden name=country value="%s"><input type=hidden name=city value="%s"><input type=hidden name=disable_geoip value="%s">
<input type=hidden name=review_token value="%s">
<input type=hidden name=expected_node value="%s"><input type=hidden name=expected_endpoint value="%s"><input type=hidden name=expected_endpoint_resolution value="%s"><input type=hidden name=revision value="%s">
<div class=fields><div class="field span4"><label>Reviewed country / city</label><input value="%s" readonly></div><div class="field span4"><label>Reviewed direction</label><input class=mono value="%s → %s" readonly></div><div class="field span4"><label>SSOT revision</label><input class=mono value="%s" readonly></div></div>
<div class="toolbar section"><button class="green progress-submit" name=action value=commit><span class=button-idle>Prepare WG identity &amp; save SSOT declaration</span><span class=button-busy><i class=button-spinner aria-hidden=true></i>Preparing node safely…</span></button><a class=button href="/nodes/add">Cancel</a></div></form></div>
<div class="callout warnline section"><b>This is declaration bootstrap, not Agent installation</b><br><span class=small>On commit, the control plane re-checks the host key and hostname, prepares or reuses <code>/etc/wireguard/node.key</code> remotely, validates the complete node and tunnel edit, and revision-guards the SSOT save. It does not install or start the Loom Agent, start application services, or claim the node is online.</span></div>
</div></div></div>`, enrollmentHidden(c, h), esc(country), esc(city), directionOptions(reviewedDirection), disableGeoIPChecked, esc(reviewedDirection), esc(review.ResolvedDirection), enrollmentHidden(c, h), esc(reviewedDirection), esc(reviewedDirection), esc(country), esc(city), yesNoValue(review.DisableGeoIP), esc(reviewToken), esc(review.NodeID), esc(review.PublicEndpoint), esc(review.EndpointResolution), esc(review.Revision), esc(locationDisplay), esc(reviewedDirection), esc(review.ResolvedDirection), esc(short(review.Revision)))
}

func yesNoValue(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func enrollmentHidden(c EnrollmentConnection, h EnrollmentHostKey) string {
	return fmt.Sprintf(`<input type=hidden name=host value="%s"><input type=hidden name=user value="%s"><input type=hidden name=port value="%d"><input type=hidden name=host_key_algorithm value="%s"><input type=hidden name=host_key_public value="%s"><input type=hidden name=host_key_fingerprint value="%s">`, esc(c.Host), esc(c.User), c.Port, esc(h.Algorithm), esc(h.PublicKey), esc(h.Fingerprint))
}

func directionOptions(selected string) string {
	if selected == "" {
		selected = "automatic"
	}
	labels := []struct{ Value, Label string }{
		{"automatic", "Automatic · conservative"},
		{"bidirectional", "Bidirectional · initiate + accept"},
		{"reverse_only", "Reverse only · initiate"},
		{"direct_only", "Direct only · accept"},
	}
	var b strings.Builder
	for _, option := range labels {
		attr := ""
		if option.Value == selected {
			attr = " selected"
		}
		fmt.Fprintf(&b, `<option value="%s"%s>%s</option>`, option.Value, attr, option.Label)
	}
	return b.String()
}

func yesNo(value bool) string {
	if value {
		return "available"
	}
	return "missing"
}

func queryEscape(s string) string {
	return url.QueryEscape(s)
}

func policyOptions(policies []PolicyView, selected string) string {
	var b strings.Builder
	found := false
	for _, p := range policies {
		attr := ""
		if p.ID == selected {
			attr = " selected"
			found = true
		}
		if p.AvailabilityKnown && !p.Available {
			attr += " disabled"
		}
		fmt.Fprintf(&b, `<option value="%s"%s>%s</option>`, esc(p.ID), attr, esc(policyOptionLabel(p)))
	}
	if selected != "" && !found {
		fmt.Fprintf(&b, `<option value="%s" selected>%s · submitted value</option>`, esc(selected), esc(selected))
	}
	return b.String()
}

func policyOptionLabel(p PolicyView) string {
	name := p.Name
	if name == "" {
		name = p.ID
	}
	suffix := ""
	if p.AvailabilityKnown && !p.Available {
		suffix = " · credentials pending"
	}
	if p.EgressAxis == "any" {
		return name + " · automatic egress · " + objectiveLabel(p.Objective) + suffix
	}
	if node, ok := strings.CutPrefix(p.EgressAxis, "pinned:"); ok && node != "" {
		return name + " · fixed " + node + " · " + objectiveLabel(p.Objective) + suffix
	}
	return name + " · " + p.ID + " · " + objectiveLabel(p.Objective) + suffix
}

func objectiveLabel(objective string) string {
	switch objective {
	case "latency":
		return "lowest latency (P50)"
	case "stability":
		return "tail stability (P95)"
	case "throughput":
		return "highest throughput"
	default:
		return objective
	}
}

func serviceAddresses(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ','
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if host := strings.TrimSpace(part); host != "" {
			out = append(out, host)
		}
	}
	return out
}

func serviceExists(v View, id string) bool {
	for _, service := range v.Services {
		if service.ID == id {
			return true
		}
	}
	return false
}
