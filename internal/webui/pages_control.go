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
			returnTo := "/services"
			if create {
				returnTo = "/services?new=1"
			} else if svc.ID != "" {
				returnTo = "/services?service=" + queryEscape(svc.ID)
			}
			fmt.Fprintf(&b, `<p class="small service-editor-access"><a class="button primary" href="%s">Sign in to edit</a></p>`, esc(loginURL(returnTo)))
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
