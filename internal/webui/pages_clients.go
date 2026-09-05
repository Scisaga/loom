package webui

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

type clientPageState struct {
	Create           bool
	Archived         bool
	Invite           *ClientInviteView
	SubmittedName    string
	SubmittedProfile string
	Error            string
	Package          LinuxClientPackageView
	PackageError     string
}

func pageDevices(d Deps, state clientPageState, isAuthed bool) string {
	if d.Control == nil {
		return shell(d, "Devices", `<div class="card notice"><b>Device inventory is control-local</b><br><span class=small>This machine cannot create Devices or issue join codes.</span></div>`, isAuthed)
	}
	state.Package, state.PackageError = clientLinuxPackage(d, state.Package, state.PackageError)
	if state.Create || state.Invite != nil {
		return pageDeviceEnrollment(d, state, isAuthed)
	}

	inventory, inventoryErr := loadDeviceInventory(d)
	archived := 0
	visible := make([]ClientView, 0, len(inventory.Clients))
	for _, device := range inventory.Clients {
		isArchived := device.Status == "revoked"
		if isArchived {
			archived++
		}
		if isArchived == state.Archived {
			visible = append(visible, device)
		}
	}
	inventory.Clients = visible

	total, members, pending := len(inventory.Clients), 0, 0
	for _, device := range inventory.Clients {
		switch device.Membership {
		case "active":
			members++
		case "identity only", "joining":
			pending++
		}
	}
	var b strings.Builder
	if state.Error != "" {
		fmt.Fprintf(&b, `<div class="card notice badline"><b>Device operation failed</b><br><span class=small>%s</span></div>`, esc(state.Error))
	}
	if inventoryErr != nil {
		fmt.Fprintf(&b, `<div class="card notice badline"><b>Device inventory unavailable</b><br><span class=small>%s</span></div>`, esc(inventoryErr.Error()))
	}
	fmt.Fprintf(&b, `<section class="card clients-summary" aria-label="Device inventory summary">
<div class=clients-summary-item><div class=label>Devices</div><div class=metric>%d</div><div class=dim>one identity inventory across all responsibilities</div></div>
<div class=clients-summary-item><div class=label>Members</div><div class="metric ok">%d</div><div class=dim>present in current desired state; not necessarily online</div></div>
<div class=clients-summary-item><div class=label>Waiting to join</div><div class=metric>%d <small>devices</small></div><div class=dim>%d unused join codes</div></div>
</section>`, total, members, pending, inventory.ActiveInvites)

	b.WriteString(`<div class=clients-layout><section class="card clients-list-card"><div class=clients-card-head><div><h2>Device inventory</h2><p class=dim>Identity, desired membership and runtime evidence remain separate facts.</p></div>`)
	control := deviceControl(d)
	if state.Archived {
		b.WriteString(`<a class="button sp" href="/devices">Current devices</a><span class=dim>Archived devices</span>`)
	} else if archived > 0 {
		fmt.Fprintf(&b, `<a class="button sp" href="/devices?archived=1">Archived devices (%d)</a>`, archived)
	}
	if isAuthed && control != nil && control.CreateInvite != nil {
		b.WriteString(`<a class="button primary sp" href="/devices?new=1">＋ Create Device</a>`)
	} else if d.Control != nil && !isAuthed {
		fmt.Fprintf(&b, `<a class="button sp" href="%s">Sign in to add</a>`, esc(loginURL("/devices?new=1")))
	}
	b.WriteString(`</div>`)
	if inventoryErr == nil && len(inventory.Clients) == 0 {
		b.WriteString(`<div class=client-empty><b>No Device records exist.</b><span class=dim>Create a Device when a machine is ready to join the network.</span></div>`)
	} else if inventoryErr == nil {
		b.WriteString(`<div class=clients-table-scroll role=region aria-label="Device records" tabindex=0><table class=clients-table><colgroup><col class=client-col-device><col class=client-col-membership><col class=client-col-responsibilities><col class=client-col-grants><col><col class=client-col-seen></colgroup><thead><tr><th>Device<th>Membership<th>Responsibilities<th>Destination grants<th>Runtime<th>Last seen <span class=client-time-zone>UTC</span></tr></thead><tbody>`)
		for _, device := range inventory.Clients {
			statusClass, statusLabel := clientStatusPresentation(device.Status)
			identityMeta := deviceListIdentityMeta(device)
			identityNote := ""
			if device.Legacy {
				identityNote = ` · <span class="tiny warn">Identity not indexed</span>`
			}
			fmt.Fprintf(&b, `<tr><td><div class=client-name><b><a href="/devices/%s">%s</a></b><span class="mono dim">%s%s</span></div><td><b>%s</b><td>%s<td>%s<td><span class="client-status %s"><span class=dot></span>%s</span><span class="client-runtime-detail tiny dim">%s</span><td>%s</tr>`,
				url.PathEscape(device.ID), esc(device.ID), esc(identityMeta), identityNote,
				esc(orDash(device.Membership)), deviceTagList(device.Responsibilities),
				deviceTagList(device.DestinationGrants), statusClass, esc(statusLabel),
				esc(clientRuntimeDetail(device)), clientTableTime(device.LastSeenAt))
		}
		b.WriteString(`</tbody></table></div>`)
	}
	b.WriteString(`</section>`)
	writeLinuxDelivery(&b, state.Package, state.PackageError)
	b.WriteString(`</div>`)
	return shell(d, "Devices", b.String(), isAuthed)
}

func deviceListIdentityMeta(device ClientView) string {
	name := strings.TrimSpace(device.Name)
	platform := strings.TrimSpace(device.Platform)
	if platform == "" {
		platform = "Not reported"
	}
	if name == "" || name == device.ID {
		return platform
	}
	return name + " · " + platform
}

func deviceTagList(values []string) string {
	if len(values) == 0 {
		return "—"
	}
	var b strings.Builder
	b.WriteString(`<span class=device-tag-list role=list>`)
	for _, value := range values {
		fmt.Fprintf(&b, `<span class=device-tag role=listitem>%s</span>`, esc(value))
	}
	b.WriteString(`</span>`)
	return b.String()
}

// pageClients remains only for source-level compatibility with older focused
// tests. Product routes and navigation use pageDevices.
func pageClients(d Deps, state clientPageState, isAuthed bool) string {
	return pageDevices(d, state, isAuthed)
}

func pageDeviceDetail(d Deps, deviceID string, isAuthed bool) string {
	inventory, err := loadDeviceInventory(d)
	if err != nil {
		return shell(d, "Device · "+deviceID, `<div class="card notice badline"><b>Device unavailable</b><br><span class=small>`+esc(err.Error())+`</span></div>`, isAuthed)
	}
	var device *ClientView
	for i := range inventory.Clients {
		if inventory.Clients[i].ID == deviceID {
			device = &inventory.Clients[i]
			break
		}
	}
	if device == nil {
		return shell(d, "Device · "+deviceID, `<div class="card notice"><b>Device not found</b><br><span class=small>The identity is not present in the current registry or desired state.</span></div>`, isAuthed)
	}
	statusClass, statusLabel := clientStatusPresentation(device.Status)
	identitySource := deviceIdentitySourceLabel(device.IdentitySource)
	if device.Legacy {
		identitySource = "Not indexed · certificate import required"
	}
	serverDeclaration := ""
	if deviceListContains(device.Responsibilities, "forward") {
		serverDeclaration = fmt.Sprintf(`<section class="card span12"><div class=label>Server declaration</div><dl class=kv><dt>Public endpoint<dd class=mono>%s:%d<dt>Tunnel direction<dd class=mono>%s<dt>Internet egress<dd>%s</dl><p class=dim>These are desired Device/SSOT facts. Reachability and signed ingress observations remain runtime evidence under Network diagnostics.</p></section>`,
			esc(orDash(device.PublicEndpoint)), device.InboundPort, esc(orDash(device.Direction)), yesNo(device.EgressCapable))
	}
	var b strings.Builder
	if device.ReplacedBy != "" {
		fmt.Fprintf(&b, `<section class="card notice"><b>Device replaced</b><p>This identity is archived. <a class=button href="/devices/%s">Open replacement Device %s</a></p></section>`, url.PathEscape(device.ReplacedBy), esc(device.ReplacedBy))
	}
	fmt.Fprintf(&b, `<div class=grid>
<section class="card span4"><div class=label>Identity</div><h2>%s</h2><dl class=kv><dt>Device ID<dd class=mono>%s<dt>Platform<dd>%s<dt>Identity source<dd>%s<dt>Profile version<dd class=mono>%s<dt>Key fingerprint<dd class=mono>%s</dl></section>
<section class="card span4"><div class=label>Membership</div><div class=metric>%s</div><p class=dim>Desired membership is separate from join progress and runtime health.</p><dl class=kv><dt>Created<dd>%s<dt>Joined<dd>%s</dl></section>
<section class="card span4"><div class=label>Runtime evidence</div><div class="client-status %s"><span class=dot></span>%s</div><p class=dim>%s</p><dl class=kv><dt>Last seen<dd>%s</dl></section>
</div>
<div class=grid><section class="card span6"><div class=label>Responsibilities</div><h2>%s</h2><p class=dim>“use_loom” means traffic originating on this Device may use Loom. It does not imply forwarding, public ingress or egress.</p></section>
<section class="card span6"><div class=label>Destination grants</div><h2>%s</h2><p class=dim>Explicit declaration references only; there is no blanket “network permission”.</p></section>%s</div>
<div class=toolbar section><a class=button href="/devices">← Device inventory</a><a class=button href="/nodes/%s">Network diagnostics</a></div>`,
		esc(device.Name), esc(device.ID), esc(orDash(device.Platform)), esc(identitySource), esc(orDash(device.ProfileVersion)), esc(orDash(device.KeyFingerprint)),
		esc(orDash(device.Membership)), esc(clientTime(device.CreatedAt)), esc(clientTime(device.EnrolledAt)),
		statusClass, esc(statusLabel), esc(clientRuntimeDetail(*device)), esc(clientTime(device.LastSeenAt)),
		esc(deviceList(device.Responsibilities)), esc(deviceList(device.DestinationGrants)), serverDeclaration, url.PathEscape(device.ID))
	if !device.Legacy && (device.Status == "pending" || device.Status == "invite_expired") {
		if control := deviceControl(d); control != nil && control.DiscardPending != nil {
			b.WriteString(`<div class=service-danger><div><b>Delete unjoined Device</b><span>This Device never used its join code. Deleting it removes the reservation and its unused join codes.</span></div>`)
			if isAuthed {
				fmt.Fprintf(&b, `<form method=post action="/devices/discard-pending"><input type=hidden name=id value="%s"><button class=danger-button>Delete Device</button></form>`, esc(device.ID))
			} else {
				fmt.Fprintf(&b, `<a class=button href="%s">Sign in to delete</a>`, esc(loginURL("/devices/"+url.PathEscape(device.ID))))
			}
			b.WriteString(`</div>`)
		}
	}
	writeDeviceJoinActions(&b, d, *device, isAuthed)
	return shell(d, "Device · "+device.ID, b.String(), isAuthed)
}

func deviceCanReplace(device ClientView) bool {
	if device.Legacy || device.IdentitySource != "enrollment" || device.ProfileVersion == "" ||
		device.ReplacedBy != "" || len(device.Responsibilities) != 1 || device.Responsibilities[0] != "use_loom" {
		return false
	}
	switch device.Status {
	case "ready", "online", "stale", "problem", "unknown", "undeclared":
		return true
	}
	return false
}

func writeDeviceJoinActions(b *strings.Builder, d Deps, device ClientView, isAuthed bool) {
	control := deviceControl(d)
	if control == nil || device.Legacy {
		return
	}
	pending := device.Status == "pending" || device.Status == "invite_expired"
	replace := deviceCanReplace(device)
	if (!pending || control.RenewInvite == nil) && (!replace || control.ReplaceDevice == nil) {
		return
	}
	b.WriteString(`<section class="card device-join-actions"><h2>Join network</h2>`)
	if pending {
		b.WriteString(`<p>Generate a fresh, one-time QR for this Device. Previous unused join codes will stop working.</p>`)
	} else {
		b.WriteString(`<p>Use this after deleting the client's local identity and configuration. The replacement gets a new Device ID with the same name and purpose. The old identity is archived; its access is revoked as the network applies the signed update.</p>`)
	}
	if !isAuthed {
		fmt.Fprintf(b, `<a class=button href="%s">Sign in to manage join QR</a>`, esc(loginURL("/devices/"+url.PathEscape(device.ID))))
	} else if pending {
		fmt.Fprintf(b, `<form method=post action="/devices/renew-invite"><input type=hidden name=id value="%s"><button class="button primary">Generate new join QR</button></form>`, esc(device.ID))
	} else {
		fmt.Fprintf(b, `<details><summary>Rejoin Device</summary><form method=post action="/devices/replace"><input type=hidden name=id value="%s"><label class=device-rejoin-confirm><input type=checkbox name=identity_deleted value=yes required> I deleted this client's local identity and configuration and want to revoke the old access.</label><button class="button primary">Replace Device and generate QR</button></form></details>`, esc(device.ID))
	}
	b.WriteString(`</section>`)
}

func deviceIdentitySourceLabel(source string) string {
	switch source {
	case "enrollment":
		return "QR join"
	case "managed-certificate":
		return "Verified existing certificate"
	case "":
		return "Not reported"
	default:
		return source
	}
}

func deviceControl(d Deps) *ClientControlDeps {
	if d.Control == nil {
		return nil
	}
	if d.Control.Devices != nil {
		return d.Control.Devices
	}
	return d.Control.Clients
}

func deviceList(values []string) string {
	if len(values) == 0 {
		return "—"
	}
	return strings.Join(values, " · ")
}

// loadDeviceInventory is the single read boundary for both the HTML inventory
// and its control API. Registry state describes identity enrollment; only the
// current trusted runtime snapshot may promote a prepared Device to online.
func loadDeviceInventory(d Deps) (ClientInventory, error) {
	control := deviceControl(d)
	if control == nil || control.List == nil {
		return ClientInventory{}, fmt.Errorf("device registry is unavailable on this machine")
	}
	inventory, err := control.List()
	if err != nil || d.Snapshot == nil {
		return inventory, err
	}
	now := time.Now().UTC()
	if d.Now != nil {
		now = d.Now().UTC()
	}
	return mergeClientRuntime(inventory, d.Snapshot(), now), nil
}

func loadClientInventory(d Deps) (ClientInventory, error) { return loadDeviceInventory(d) }

func pageDeviceEnrollment(d Deps, state clientPageState, isAuthed bool) string {
	state.Package, state.PackageError = clientLinuxPackage(d, state.Package, state.PackageError)
	var b strings.Builder
	if d.Control == nil {
		b.WriteString(`<div class="card notice badline"><b>Control role required</b><br><span class=small>Devices and their join codes can be created only on the control plane.</span></div>`)
		return shell(d, "Devices", b.String(), isAuthed)
	}
	if !isAuthed {
		fmt.Fprintf(&b, `<div class=client-add-grid><section class="card client-form-card"><h2>Operator session required</h2><p class=dim>Creating a Device and its one-time join code changes control-plane state.</p><a class="button primary" href="%s">Sign in</a></section></div>`, esc(loginURL("/devices?new=1")))
		return shell(d, "Devices", b.String(), false)
	}
	control := deviceControl(d)
	if control == nil || control.CreateInvite == nil {
		b.WriteString(`<div class="card notice badline"><b>Device creation unavailable</b><br><span class=small>This build has no Device identity registry capability.</span></div>`)
		return shell(d, "Devices", b.String(), true)
	}
	if state.Invite != nil {
		if state.Invite.Replaces != "" {
			fmt.Fprintf(&b, `<section class="card notice"><b>Replacement join QR ready</b><p>Device <span class=mono>%s</span> replaces <a href="/devices/%s">%s</a>. The name and purpose are preserved. Old access revocation takes effect as the network applies the signed update.</p></section>`, esc(state.Invite.ClientID), url.PathEscape(state.Invite.Replaces), esc(state.Invite.Replaces))
		}
		writeClientInvite(&b, *state.Invite, state.Package, state.PackageError)
		return shell(d, "Devices", b.String(), true)
	}
	if state.Error != "" {
		fmt.Fprintf(&b, `<div class="card notice badline"><b>Device was not created</b><br><span class=small>%s</span></div>`, esc(state.Error))
	}
	profiles, profileErr := deviceEnrollmentProfiles(d)
	profile := selectedEnrollmentProfile(profiles, state.SubmittedProfile)
	profileControl := enrollmentProfileControl(profiles, profile.Version)
	fmt.Fprintf(&b, `<div class=client-add-grid><section class="card client-form-card"><h2>Create Device</h2><p class=dim>Name the machine for operators. The client reports its supported platform when it imports this Device's join code.</p>
<form class=blockform data-submit-progress method=post action="/devices/create"><div class=field><label for=client-name>Display name</label><input id=client-name name=name maxlength=80 required autocomplete=off value="%s" placeholder="e.g. build server"><span class=field-hint>Platform is reported by the client running on the Device; its immutable purpose is pinned below.</span></div>%s
<div class=client-form-actions><button class="primary progress-submit"><span class=button-idle>Create Device</span><span class=button-busy><i class=button-spinner aria-hidden=true></i>Creating…</span></button><a class=button href="/devices">Cancel</a></div></form></section>
<aside class=card><h2>Pinned join profile</h2><div class=client-boundary><div><span>ProfileVersion</span><b id=profile-preview-version class=mono>%s</b></div><div><span>Identity</span><b>Local key + short-lived, single-use join code</b></div><div><span>Membership</span><b>Published desired state, separate from online status</b></div><div><span>Responsibilities</span><b id=profile-preview-responsibilities>%s</b></div><div><span>Destination grants</span><b id=profile-preview-grants>%s</b></div></div>%s</aside></div>`, esc(state.SubmittedName), profileControl, esc(orDash(profile.Version)), esc(deviceList(profile.Responsibilities)), esc(deviceList(profile.DestinationGrants)), enrollmentProfileError(profileErr))
	return shell(d, "Devices", b.String(), true)
}

func pageClientEnrollment(d Deps, state clientPageState, isAuthed bool) string {
	return pageDeviceEnrollment(d, state, isAuthed)
}

func writeClientInvite(b *strings.Builder, invite ClientInviteView, pkg LinuxClientPackageView, packageError string) {
	qrURL := "/api/control/device-invites/" + url.PathEscape(invite.InviteID) + "/qr.png"
	downloadURL := "/api/control/device-invites/" + url.PathEscape(invite.InviteID) + "/download"
	fmt.Fprintf(b, `<div class=client-invite-grid><section class="card client-invite-qr"><div class="badge warn"><span class=dot></span>Waiting to join</div><a href="%s" download aria-label="Download join QR code"><img src="%s" alt="Join QR code for %s"></a><p><b>Save or scan this QR code</b><br><span class="small dim">Import the image after starting the client. It binds the client to this existing Device.</span></p></section>
<section class="card client-invite-copy"><div><div class=label>Device created · join code ready</div><h2>%s</h2><span class="mono dim">%s</span></div>
<div class=client-invite-expiry><span class=dot></span><span>This join code is a short-lived, single-use secret and expires at <b>%s</b>. Share it only with the intended device.</span></div>
<div class=client-boundary><div><span>ProfileVersion</span><b class=mono>%s</b></div><div><span>Responsibilities</span><b>%s</b></div><div><span>Destination grants</span><b>%s</b></div></div>
<div class=field><label for=invite-link>Fallback join link</label><div class=invite-link><input id=invite-link readonly spellcheck=false autocomplete=off autocapitalize=none value="%s" aria-describedby=invite-link-help><a class=button href="%s" download>Download join file</a></div><span id=invite-link-help class=field-hint>The QR image, join file and this hidden protocol link are equivalent one-time inputs.</span></div>`,
		esc(qrURL), esc(qrURL), esc(invite.ClientID), esc(invite.ClientName), esc(invite.ClientID), esc(clientTime(invite.ExpiresAt)), esc(orDash(invite.ProfileVersion)), esc(deviceList(invite.Responsibilities)), esc(deviceList(invite.DestinationGrants)), esc(invite.InviteURI), esc(downloadURL))
	if clientPackageAvailable(pkg) {
		fmt.Fprintf(b, `<div class=client-invite-actions><a class="button primary" href="%s" download>Download Linux package</a><form class=client-done-form method=get action="/devices"><button class=button type=submit>Back to Device list</button></form></div>`, esc(pkg.URL))
	} else {
		b.WriteString(`<div class=client-invite-actions><form class=client-done-form method=get action="/devices"><button class=button type=submit>Back to Device list</button></form></div><p class="small warn">The Linux package is not currently available from this control plane.</p>`)
		if packageError != "" {
			fmt.Fprintf(b, `<p class="tiny dim">%s</p>`, esc(packageError))
		}
	}
	b.WriteString(`</section></div><section class="card client-setup"><div class=client-setup-head><div><div class=label>Windows Portable preview</div><h2>Start the client, then import the QR code</h2></div><p class=small>Portable Mixed and Portable TUN join this existing Device without an extra command or component selection. Installed will use the same flow after its MSI, desktop UI and restricted Service IPC are delivered.</p></div></section><section class="card client-setup" aria-labelledby=client-setup-title><div class=client-setup-head><div><div class=label>Linux server</div><h2 id=client-setup-title>Command-line setup</h2></div><p class=small>The QR, join file and protocol link carry the same one-time code.</p></div>`)
	if deviceListContains(invite.Responsibilities, "forward") {
		b.WriteString(`<div class=client-setup-prepare><div><span class=client-step>1</span><div><b>Configure the server declaration before joining</b><span class="small dim">This declares how other Devices may reach this server. It is not a route or exit selection.</span></div></div><code class=command-block>sudo install -d -m 0755 /etc/loom
sudoedit /etc/loom/device.yaml</code><code class=command-block>server:
  public_endpoint: edge.example.net
  inbound_port: 61698
  direction: bidirectional</code><p class="small dim">Use this Device's real public DNS name or public IP and the UDP port exposed by the deployment. These declared facts are verified by the existing signed topology observations after apply; country, city and provider are optional.</p></div>`)
	}
	if pkg.InstallerURL != "" {
		fmt.Fprintf(b, `<div class=client-setup-prepare><div><span class=client-step>1</span><div><b>Install the public generic package</b><span class="small dim">No join code or Device configuration is embedded in this URL.</span></div></div><code class=command-block>curl -fsSL '%s' | sudo sh
sudo /usr/local/bin/loom client enroll -stdin</code></div>`, esc(pkg.InstallerURL))
	}
	if clientPackageAvailable(pkg) {
		fmt.Fprintf(b, `<div class=client-setup-prepare><div><span class=client-step>⇩</span><div><b>Manual or offline package install</b><span class="small dim">Run these commands in the directory containing both downloads.</span></div></div><code class=command-block>printf '%%s  %%s\n' '%s' '%s' | sha256sum -c -
tar -xzf loom-client-linux-amd64.tar.gz
cd loom-client-linux-amd64</code></div>
<div class=client-setup-methods><section class=client-setup-method aria-labelledby=invite-file-method><div class=client-method-title><span class=client-step>2A</span><div><h3 id=invite-file-method>Join file</h3><span class="badge ok">Recommended</span></div></div><p class="small dim">Use this after downloading <code>client.loom-invite</code>.</p><code class=command-block>sudo ./install.sh --invite-file ../client.loom-invite</code></section>
<section class=client-setup-method aria-labelledby=invite-uri-method><div class=client-method-title><span class=client-step>2B</span><div><h3 id=invite-uri-method>Join link via stdin</h3><span class="small dim">For a Linux host where you copied the link.</span></div></div><code class=command-block>sudo ./install.sh --no-enroll
sudo /usr/local/bin/loom client enroll -stdin</code><p class="small">Paste the complete URI shown above, press <kbd>Enter</kbd>, then <kbd>Ctrl-D</kbd>. Stdin keeps the secret out of shell history.</p></section></div>`, esc(pkg.SHA256), esc(pkg.Filename))
	} else {
		b.WriteString(`<div class="callout warnline client-setup-blocked"><b>Linux package unavailable</b><br><span class=small>Publish a validated Linux client package before attempting these installation commands. The join code remains usable until the expiry shown above.</span></div>`)
	}
	b.WriteString(`<div class=client-setup-boundary><b>The first successful join consumes the code.</b><span>Before it is used, an operator can generate a fresh QR from the Device details. After joining, deleting the local identity requires Rejoin Device there to revoke the old access and create a replacement. An interrupted join must finish or be resolved before replacement. Reconnects, restarts and configuration updates keep the existing identity.</span></div></section>`)
}

func deviceEnrollmentProfiles(d Deps) ([]DeviceEnrollmentProfileView, error) {
	control := deviceControl(d)
	if control == nil {
		return nil, fmt.Errorf("profile preview is unavailable")
	}
	if control.EnrollmentProfiles != nil {
		profiles, err := control.EnrollmentProfiles()
		if err != nil {
			return nil, err
		}
		if len(profiles) == 0 {
			return nil, fmt.Errorf("no join profile is available")
		}
		return profiles, nil
	}
	if control.EnrollmentProfile == nil {
		return nil, fmt.Errorf("profile preview is unavailable")
	}
	profile, err := control.EnrollmentProfile()
	profile.Default = true
	return []DeviceEnrollmentProfileView{profile}, err
}

func deviceEnrollmentProfile(d Deps) (DeviceEnrollmentProfileView, error) {
	profiles, err := deviceEnrollmentProfiles(d)
	return selectedEnrollmentProfile(profiles, ""), err
}

func selectedEnrollmentProfile(profiles []DeviceEnrollmentProfileView, requested string) DeviceEnrollmentProfileView {
	for _, profile := range profiles {
		if requested != "" && profile.Version == requested {
			return profile
		}
	}
	for _, profile := range profiles {
		if profile.Default {
			return profile
		}
	}
	if len(profiles) > 0 {
		return profiles[0]
	}
	return DeviceEnrollmentProfileView{}
}

func enrollmentProfileControl(profiles []DeviceEnrollmentProfileView, selected string) string {
	if len(profiles) <= 1 {
		return `<input type=hidden name=profile_version value="` + esc(selected) + `">`
	}
	var b strings.Builder
	b.WriteString(`<div class=field><label for=device-profile>Device purpose</label><select id=device-profile name=profile_version required data-device-profile-control>`)
	for _, profile := range profiles {
		selectedAttr := ""
		if profile.Version == selected {
			selectedAttr = " selected"
		}
		fmt.Fprintf(&b, `<option value="%s" data-responsibilities="%s" data-grants="%s"%s>%s · %s</option>`,
			esc(profile.Version), esc(deviceList(profile.Responsibilities)), esc(deviceList(profile.DestinationGrants)), selectedAttr,
			esc(profile.Version), esc(deviceList(profile.Responsibilities)))
	}
	b.WriteString(`</select><span class=field-hint>This pins an immutable responsibility/grant expansion; it is not a platform choice.</span></div>`)
	return b.String()
}

func deviceListContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func enrollmentProfileError(err error) string {
	if err == nil {
		return ""
	}
	return `<div class="callout warnline"><b>Profile unavailable</b><br><span class=small>` + esc(err.Error()) + `</span></div>`
}

func writeLinuxDelivery(b *strings.Builder, pkg LinuxClientPackageView, packageError string) {
	b.WriteString(`<aside class=linux-delivery><section class="card linux-package"><div class=linux-package-head><div><div class=label>Linux server</div><h2>Client distribution</h2><span class="small dim">Loom, pinned sing-box and systemd installation</span></div>`)
	if clientPackageAvailable(pkg) {
		downloadURL := pkg.URL
		if pkg.PublicURL != "" {
			downloadURL = pkg.PublicURL
		}
		fmt.Fprintf(b, `<a class="button primary sp" href="%s" download>Download</a></div><dl class=linux-package-meta><dt>File<dd class=mono>%s<dt>Version<dd>%s<dt>Target<dd class=mono>%s<dt>SHA-256<dd class=mono>%s</dl>`, esc(downloadURL), esc(pkg.Filename), esc(orDash(pkg.Version)), esc(orDash(pkg.Arch)), esc(pkg.SHA256))
		if pkg.InstallerURL != "" {
			fmt.Fprintf(b, `<div><div class=label>One-line public install</div><code class=command-block>curl -fsSL '%s' | sudo sh</code><span class="tiny dim">The generic installer contains no join code. Join afterward with the QR, file or URI.</span></div>`, esc(pkg.InstallerURL))
		}
	} else {
		b.WriteString(`</div><div class="callout warnline"><b>Package unavailable</b><br><span class=small>No validated Linux artifact is published by this control node.</span></div>`)
		if packageError != "" {
			fmt.Fprintf(b, `<span class="tiny dim">%s</span>`, esc(packageError))
		}
	}
	b.WriteString(`</section><details class="card linux-install" open><summary>Install and join</summary><ol><li>Download the package and join file on the target Linux server.</li><li>Verify the package before extracting it.`)
	if clientPackageAvailable(pkg) && pkg.SHA256 != "" {
		fmt.Fprintf(b, `<code class=command-block>printf '%%s  %%s\n' '%s' '%s' | sha256sum -c -</code>`, esc(pkg.SHA256), esc(pkg.Filename))
	} else {
		b.WriteString(`<span class="small dim">The checksum appears here only when a package is available.</span>`)
	}
	b.WriteString(`</li><li>Extract, then install with the downloaded join file.<code class=command-block>tar -xzf loom-client-linux-amd64.tar.gz
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
		return "info", "Joined · status unverified"
	case "managed":
		return "info", "SSOT managed"
	case "provisioning":
		return "warn", "Provisioning"
	case "pending":
		return "warn", "Waiting to join"
	case "invite_expired":
		return "bad", "Join code expired"
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

func clientTableTime(value string) string {
	if strings.TrimSpace(value) == "" {
		return "—"
	}
	at, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return esc(value)
	}
	at = at.UTC()
	return fmt.Sprintf(`<time class="client-time mono" datetime="%s">%s<br>%s</time>`,
		at.Format(time.RFC3339), at.Format("2006/01/02"), at.Format("15:04:05"))
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
	control := deviceControl(d)
	if control == nil || control.LinuxPackage == nil {
		return LinuxClientPackageView{}, "Linux client package capability is not configured."
	}
	pkg, err := control.LinuxPackage()
	if err != nil {
		return LinuxClientPackageView{}, err.Error()
	}
	if !clientPackageAvailable(pkg) {
		return LinuxClientPackageView{}, "Linux client package metadata is incomplete."
	}
	return pkg, ""
}
