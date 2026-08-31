package webui

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

type clientPageState struct {
	Create        bool
	Invite        *ClientInviteView
	SubmittedName string
	Error         string
	Package       LinuxClientPackageView
	PackageError  string
}

func pageClients(d Deps, state clientPageState, isAuthed bool) string {
	if d.Control == nil {
		return shell(d, "Clients", `<div class="card notice"><b>Client inventory is control-local</b><br><span class=small>This node has no client registry, invitation issuer or distribution catalog.</span></div>`, isAuthed)
	}
	state.Package, state.PackageError = clientLinuxPackage(d, state.Package, state.PackageError)
	if state.Create || state.Invite != nil {
		return pageClientEnrollment(d, state, isAuthed)
	}

	inventory, inventoryErr := loadClientInventory(d)

	total, ready, pending := len(inventory.Clients), 0, 0
	for _, client := range inventory.Clients {
		switch client.Status {
		case "online", "ready":
			ready++
		case "pending", "invite_expired", "provisioning":
			pending++
		}
	}
	var b strings.Builder
	if state.Error != "" {
		fmt.Fprintf(&b, `<div class="card notice badline"><b>Client operation failed</b><br><span class=small>%s</span></div>`, esc(state.Error))
	}
	if inventoryErr != nil {
		fmt.Fprintf(&b, `<div class="card notice badline"><b>Client inventory unavailable</b><br><span class=small>%s</span></div>`, esc(inventoryErr.Error()))
	}
	fmt.Fprintf(&b, `<section class="card clients-summary" aria-label="Client inventory summary">
<div class=clients-summary-item><div class=label>Client records</div><div class=metric>%d</div><div class=dim>registry and managed access identities</div></div>
<div class=clients-summary-item><div class=label>Bootstrap prepared</div><div class="metric ok">%d</div><div class=dim>server-side material ready; online still requires a trusted report</div></div>
<div class=clients-summary-item><div class=label>Enrollment work</div><div class=metric>%d <small>clients</small></div><div class=dim>%d unconsumed invitations</div></div>
</section>`, total, ready, pending, inventory.ActiveInvites)

	b.WriteString(`<div class=clients-layout><section class="card clients-list-card"><div class=clients-card-head><div><h2>Client inventory</h2><p class=dim>Registration state is not tunnel health or proof of traffic.</p></div>`)
	if isAuthed && d.Control != nil && d.Control.Clients != nil && d.Control.Clients.CreateInvite != nil {
		b.WriteString(`<a class="button primary sp" href="/clients?new=1">＋ Add client</a>`)
	} else if d.Control != nil && !isAuthed {
		b.WriteString(`<a class="button sp" href="/login">Sign in to add</a>`)
	}
	b.WriteString(`</div>`)
	if inventoryErr == nil && len(inventory.Clients) == 0 {
		b.WriteString(`<div class=client-empty><b>No client records exist.</b><span class=dim>Create a short-lived invitation when a device is ready to enroll.</span></div>`)
	} else if inventoryErr == nil {
		b.WriteString(`<div role=region aria-label="Client records" tabindex=0><table class=clients-table><thead><tr><th>Client<th>Platform<th>Status<th>Created<th>Claimed<th>Last seen</tr></thead><tbody>`)
		for _, client := range inventory.Clients {
			statusClass, statusLabel := clientStatusPresentation(client.Status)
			platform := client.Platform
			if platform == "" {
				platform = "Not reported"
			}
			fmt.Fprintf(&b, `<tr><td><div class=client-name><b>%s</b><span class="mono dim">%s</span></div><td><span class=client-platform>%s</span><td><span class="client-status %s"><span class=dot></span>%s</span><br><span class="tiny dim">%s</span><td class=mono>%s<td class=mono>%s<td class=mono>%s</tr>`,
				esc(client.Name), esc(client.ID), esc(platform), statusClass, esc(statusLabel),
				esc(clientRuntimeDetail(client)), esc(clientTime(client.CreatedAt)), esc(clientTime(client.EnrolledAt)), esc(clientTime(client.LastSeenAt)))
		}
		b.WriteString(`</tbody></table></div>`)
	}
	b.WriteString(`</section>`)
	writeLinuxDelivery(&b, state.Package, state.PackageError)
	b.WriteString(`</div>`)
	return shell(d, "Clients", b.String(), isAuthed)
}

// loadClientInventory is the single read boundary for both the HTML inventory
// and its control API. Registry state describes enrollment; only the current
// trusted runtime snapshot may promote a prepared client to online.
func loadClientInventory(d Deps) (ClientInventory, error) {
	if d.Control == nil || d.Control.Clients == nil || d.Control.Clients.List == nil {
		return ClientInventory{}, fmt.Errorf("client registry is unavailable on this node")
	}
	inventory, err := d.Control.Clients.List()
	if err != nil || d.Snapshot == nil {
		return inventory, err
	}
	now := time.Now().UTC()
	if d.Now != nil {
		now = d.Now().UTC()
	}
	return mergeClientRuntime(inventory, d.Snapshot(), now), nil
}

func pageClientEnrollment(d Deps, state clientPageState, isAuthed bool) string {
	state.Package, state.PackageError = clientLinuxPackage(d, state.Package, state.PackageError)
	var b strings.Builder
	if d.Control == nil {
		b.WriteString(`<div class="card notice badline"><b>Control role required</b><br><span class=small>Client enrollment is available only on the control node.</span></div>`)
		return shell(d, "Clients", b.String(), isAuthed)
	}
	if !isAuthed {
		b.WriteString(`<div class=client-add-grid><section class="card client-form-card"><h2>Operator session required</h2><p class=dim>Creating an invitation changes the control-local client registry.</p><a class="button primary" href="/login">Sign in</a></section></div>`)
		return shell(d, "Clients", b.String(), false)
	}
	if d.Control.Clients == nil || d.Control.Clients.CreateInvite == nil {
		b.WriteString(`<div class="card notice badline"><b>Client enrollment unavailable</b><br><span class=small>This build has no client registry capability.</span></div>`)
		return shell(d, "Clients", b.String(), true)
	}
	if state.Invite != nil {
		writeClientInvite(&b, *state.Invite, state.Package, state.PackageError)
		return shell(d, "Clients", b.String(), true)
	}
	if state.Error != "" {
		fmt.Fprintf(&b, `<div class="card notice badline"><b>Invitation was not created</b><br><span class=small>%s</span></div>`, esc(state.Error))
	}
	fmt.Fprintf(&b, `<div class=client-add-grid><section class="card client-form-card"><h2>Add client</h2><p class=dim>Name the device for operators. The client reports its supported platform when it claims the invitation.</p>
<form class=blockform data-submit-progress method=post action="/clients/create"><div class=field><label for=client-name>Display name</label><input id=client-name name=name maxlength=80 required autocomplete=off value="%s" placeholder="e.g. build server"><span class=field-hint>Do not enter a platform, exit node or route. Those are not invitation properties.</span></div>
<div class=client-form-actions><button class="primary progress-submit"><span class=button-idle>Create invitation</span><span class=button-busy><i class=button-spinner aria-hidden=true></i>Creating…</span></button><a class=button href="/clients">Cancel</a></div></form></section>
<aside class=card><h2>Enrollment boundary</h2><div class=client-boundary><div><span>Invitation</span><b>Short-lived and single-use</b></div><div><span>Platform</span><b>Reported by the installed client</b></div><div><span>Device key</span><b>Generated locally; private key never uploads</b></div><div><span>Routing</span><b>Chosen after enrollment: Direct, Auto or an authorized exit</b></div></div></aside></div>`, esc(state.SubmittedName))
	return shell(d, "Clients", b.String(), true)
}

func writeClientInvite(b *strings.Builder, invite ClientInviteView, pkg LinuxClientPackageView, packageError string) {
	qrURL := "/api/control/client-invites/" + url.PathEscape(invite.InviteID) + "/qr.png"
	downloadURL := "/api/control/client-invites/" + url.PathEscape(invite.InviteID) + "/download"
	fmt.Fprintf(b, `<div class=client-invite-grid><section class="card client-invite-qr"><div class="badge warn"><span class=dot></span>Pending claim</div><a href="%s" download aria-label="Download invitation file"><img src="%s" alt="Enrollment QR code for %s"></a><p><b>Scan or click the QR code</b><br><span class="small dim">Clicking downloads the same invitation as a <code>.loom-invite</code> file.</span></p></section>
<section class="card client-invite-copy"><div><div class=label>Client created</div><h2>%s</h2><span class="mono dim">%s</span></div>
<div class=client-invite-expiry><span class=dot></span><span>This invitation is a short-lived, single-use secret and expires at <b>%s</b>. Share it only with the intended device.</span></div>
<div class=field><label for=invite-link>Linux invitation link</label><div class=invite-link><input id=invite-link readonly spellcheck=false value="%s" aria-describedby=invite-link-help><a class=button href="%s" download>Download .loom-invite</a></div><span id=invite-link-help class=field-hint>Select and copy this link for a Linux client, or download the invitation file. It is not a permanent connection URL.</span></div>`,
		esc(downloadURL), esc(qrURL), esc(invite.ClientID), esc(invite.ClientName), esc(invite.ClientID), esc(clientTime(invite.ExpiresAt)), esc(invite.InviteURI), esc(downloadURL))
	if clientPackageAvailable(pkg) {
		fmt.Fprintf(b, `<div class=client-invite-actions><a class="button primary" href="%s" download>Download Linux client</a><a class=button href="/clients">Done</a></div>`, esc(pkg.URL))
	} else {
		b.WriteString(`<div class=client-invite-actions><a class=button href="/clients">Done</a></div><p class="small warn">The Linux client package is not currently available from this control node.</p>`)
		if packageError != "" {
			fmt.Fprintf(b, `<p class="tiny dim">%s</p>`, esc(packageError))
		}
	}
	b.WriteString(`</section></div><div class="card client-result-note"><b>Next step for Linux</b><br><span class=small>Download the Linux package, verify its checksum, extract it, then run <code>sudo ./install.sh --invite-file ../client.loom-invite</code> from the extracted directory. Claiming consumes the invitation; normal reconnects do not register the device again.</span></div>`)
}

func writeLinuxDelivery(b *strings.Builder, pkg LinuxClientPackageView, packageError string) {
	b.WriteString(`<aside class=linux-delivery><section class="card linux-package"><div class=linux-package-head><div><div class=label>Linux server</div><h2>Client distribution</h2><span class="small dim">Loom, pinned sing-box and systemd installation</span></div>`)
	if clientPackageAvailable(pkg) {
		fmt.Fprintf(b, `<a class="button primary sp" href="%s" download>Download</a></div><dl class=linux-package-meta><dt>File<dd class=mono>%s<dt>Version<dd>%s<dt>Target<dd class=mono>%s<dt>SHA-256<dd class=mono>%s</dl>`, esc(pkg.URL), esc(pkg.Filename), esc(orDash(pkg.Version)), esc(orDash(pkg.Arch)), esc(pkg.SHA256))
	} else {
		b.WriteString(`</div><div class="callout warnline"><b>Package unavailable</b><br><span class=small>No validated Linux artifact is published by this control node.</span></div>`)
		if packageError != "" {
			fmt.Fprintf(b, `<span class="tiny dim">%s</span>`, esc(packageError))
		}
	}
	b.WriteString(`</section><details class="card linux-install" open><summary>Install and enroll</summary><ol><li>Download the package and invitation file on the target Linux server.</li><li>Verify the package before extracting it.`)
	if clientPackageAvailable(pkg) && pkg.SHA256 != "" {
		fmt.Fprintf(b, `<code class=command-block>printf '%%s  %%s\n' '%s' '%s' | sha256sum -c -</code>`, esc(pkg.SHA256), esc(pkg.Filename))
	} else {
		b.WriteString(`<span class="small dim">The checksum appears here only when a package is available.</span>`)
	}
	b.WriteString(`</li><li>Extract, then install with the downloaded invitation.<code class=command-block>tar -xzf loom-client-linux-amd64.tar.gz
cd loom-client-linux-amd64
sudo ./install.sh --invite-file ../client.loom-invite</code></li><li>Point the application at <code>127.0.0.1:1080</code>. The default Linux server setup does not take over the host routing table.</li></ol></details></aside>`)
}

func clientStatusPresentation(status string) (className, label string) {
	switch status {
	case "online":
		return "ok", "Online"
	case "stale":
		return "warn", "Stale"
	case "problem":
		return "bad", "Problem"
	case "unknown":
		return "warn", "Status unknown"
	case "undeclared":
		return "warn", "Undeclared"
	case "decommissioned":
		return "dim", "Decommissioned"
	case "ready":
		return "ok", "Bootstrap ready"
	case "managed":
		return "info", "SSOT managed"
	case "provisioning":
		return "warn", "Provisioning"
	case "pending":
		return "warn", "Pending claim"
	case "invite_expired":
		return "bad", "Invite expired"
	case "revoked":
		return "bad", "Revoked"
	case "":
		return "dim", "Unknown"
	default:
		return "dim", status
	}
}

const clientRuntimeStaleAfter = 5 * time.Minute

// mergeClientRuntime 只改页面使用的切片副本。registry/SSOT 仍分别保存身份与
// 期望态；Online 必须来自当前 View 中直连或验签后的健康证据。
func mergeClientRuntime(inventory ClientInventory, view View, now time.Time) ClientInventory {
	out := inventory
	out.Clients = append([]ClientView(nil), inventory.Clients...)
	nodes := make(map[string]NodeView, len(view.Nodes))
	ambiguous := make(map[string]bool)
	for _, node := range view.Nodes {
		if node.ID == "" {
			continue
		}
		if _, exists := nodes[node.ID]; exists {
			ambiguous[node.ID] = true
			continue
		}
		nodes[node.ID] = node
	}
	for i := range out.Clients {
		client := &out.Clients[i]
		// registry 中即使残留 online 字样，也不能绕过本次运行态证据。
		if client.Status == "online" {
			client.Status = "unknown"
		}
		node, found := nodes[client.ID]
		if !found || ambiguous[client.ID] {
			continue
		}
		mergeClientNodeRuntime(client, node, now)
	}
	return out
}

func mergeClientNodeRuntime(client *ClientView, node NodeView, now time.Time) {
	if node.IdentityError != "" {
		client.DataPlaneStatus = "problem"
		client.ConfigState = "not reported"
		client.LastSeenAt = ""
		overrideClientRuntimeStatus(client, "problem")
		return
	}
	direct := node.Reached || node.Source == "直连 /status"
	trusted := direct || node.Source == "签名转述" || node.Source == "签名健康转述"
	if !trusted {
		if strings.TrimSpace(node.ObservedAt) == "" {
			client.DataPlaneStatus = "not observed"
		} else {
			client.DataPlaneStatus = "untrusted observation"
		}
		client.ConfigState = "not reported"
		client.LastSeenAt = ""
		return
	}

	observed, observedOK := parseClientObservedAt(node.ObservedAt)
	if observedOK {
		client.LastSeenAt = observed.Format(time.RFC3339)
	} else {
		client.LastSeenAt = ""
	}
	if strings.TrimSpace(node.Applied) == "" {
		client.ConfigState = "not reported"
	} else {
		client.ConfigState = "applied " + short(node.Applied)
	}

	stale := !direct && (!observedOK || node.AgeSec > int(clientRuntimeStaleAfter.Seconds()) ||
		now.Sub(observed) > clientRuntimeStaleAfter || observed.After(now.Add(time.Minute)))
	switch {
	case !node.Declared:
		client.DataPlaneStatus = "undeclared"
		overrideClientRuntimeStatus(client, "undeclared")
	case node.Decommission:
		client.DataPlaneStatus = "decommissioned"
		overrideClientRuntimeStatus(client, "decommissioned")
	case stale:
		client.DataPlaneStatus = "stale"
		overrideClientRuntimeStatus(client, "stale")
	case node.Health == "problem":
		client.DataPlaneStatus = "problem"
		overrideClientRuntimeStatus(client, "problem")
	case node.Health == "healthy":
		client.DataPlaneStatus = "online"
		overrideClientRuntimeStatus(client, "online")
	default:
		client.DataPlaneStatus = "unknown"
		if client.Status == "online" {
			client.Status = "unknown"
		}
	}
}

func parseClientObservedAt(value string) (time.Time, bool) {
	observed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, false
	}
	return observed.UTC(), true
}

func overrideClientRuntimeStatus(client *ClientView, status string) {
	switch client.Status {
	case "revoked", "pending", "invite_expired", "provisioning":
		return
	default:
		client.Status = status
	}
}

func clientTime(value string) string {
	if strings.TrimSpace(value) == "" {
		return "—"
	}
	return shortTS(value) + " UTC"
}

func clientRuntimeDetail(client ClientView) string {
	dataPlane := strings.TrimSpace(client.DataPlaneStatus)
	config := strings.TrimSpace(client.ConfigState)
	if dataPlane == "" {
		dataPlane = "not reported"
	}
	if config == "" {
		config = "not issued"
	}
	return "data: " + dataPlane + " · config: " + config
}

func clientPackageAvailable(pkg LinuxClientPackageView) bool {
	return strings.TrimSpace(pkg.Filename) != "" && strings.TrimSpace(pkg.URL) != "" && strings.TrimSpace(pkg.SHA256) != ""
}

func clientLinuxPackage(d Deps, provided LinuxClientPackageView, providedError string) (LinuxClientPackageView, string) {
	if clientPackageAvailable(provided) || providedError != "" {
		return provided, providedError
	}
	if d.Control == nil || d.Control.Clients == nil || d.Control.Clients.LinuxPackage == nil {
		return LinuxClientPackageView{}, "Linux client package capability is not configured."
	}
	pkg, err := d.Control.Clients.LinuxPackage()
	if err != nil {
		return LinuxClientPackageView{}, err.Error()
	}
	if !clientPackageAvailable(pkg) {
		return LinuxClientPackageView{}, "Linux client package metadata is incomplete."
	}
	return pkg, ""
}
