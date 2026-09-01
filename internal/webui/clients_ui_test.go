package webui

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func clientUIDeps() Deps {
	d := misakaDeps()
	d.Control.Clients = &ClientControlDeps{
		List: func() (ClientInventory, error) {
			return ClientInventory{
				Clients: []ClientView{
					{ID: "client-linux01", Name: "Build server", Platform: "linux", Status: "provisioning", CreatedAt: "2026-08-31T09:00:00Z", EnrolledAt: "2026-08-31T09:02:00Z"},
					{ID: "client-phone01", Name: "Phone", Status: "pending", CreatedAt: "2026-08-31T10:00:00Z"},
				},
				ActiveInvites: 1,
			}, nil
		},
		CreateInvite: func(ClientInviteInput) (ClientInviteView, error) { return ClientInviteView{}, nil },
		LinuxPackage: func() (LinuxClientPackageView, error) {
			return LinuxClientPackageView{
				Filename: "loom-client-linux-amd64.tar.gz",
				URL:      "/clients/download/linux-amd64",
				SHA256:   "0123456789abcdef",
				Version:  "v1.0.0",
				Arch:     "linux/amd64",
			}, nil
		},
	}
	return d
}

func TestClientsPageSeparatesRegistrationFromRuntimeHealth(t *testing.T) {
	d := clientUIDeps()
	body := pageClients(d, clientPageState{}, true)
	for _, want := range []string{
		`href="/clients?new=1"`,
		`Build server`, `client-linux01`, `Provisioning`,
		`Phone`, `Pending claim`, `Not reported`,
		`data: not reported · config: not issued`,
		`Registration state is not tunnel health or proof of traffic.`,
		`1 unconsumed invitations`,
		`href="/clients/download/linux-amd64"`,
		`loom-client-linux-amd64.tar.gz`,
		`sudo ./install.sh --invite-file ../client.loom-invite`,
		`127.0.0.1:1080`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Clients page missing %q", want)
		}
	}
	if strings.Contains(body, `class="metric ok">1`) {
		t.Fatal("a claimed but still-provisioning client was presented as ready or online")
	}
}

func TestClientsPageMergesOnlyTrustedCurrentNodeRuntime(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	d := clientUIDeps()
	d.Now = func() time.Time { return now }
	d.Control.Clients.List = func() (ClientInventory, error) {
		return ClientInventory{Clients: []ClientView{
			{ID: "direct", Name: "Direct", Status: "ready"},
			{ID: "signed", Name: "Signed", Status: "ready"},
			{ID: "unsigned", Name: "Unsigned", Status: "online", LastSeenAt: "2026-08-31T11:58:00Z"},
			{ID: "stale", Name: "Stale", Status: "ready"},
			{ID: "broken", Name: "Broken", Status: "ready"},
			{ID: "silent", Name: "Silent", Status: "online"},
			{ID: "revoked", Name: "Revoked", Status: "revoked"},
		}}, nil
	}
	d.Snapshot = func() View {
		return View{Nodes: []NodeView{
			{ID: "direct", Declared: true, Reached: true, Health: "healthy", Source: "直连 /status", ObservedAt: now.Add(-5 * time.Second).Format(time.RFC3339), Applied: "snapshot-direct-0123456789"},
			{ID: "signed", Declared: true, Health: "healthy", Source: "签名健康转述", ObservedAt: now.Add(-20 * time.Second).Format(time.RFC3339), AgeSec: 20, Applied: "snapshot-signed-0123456789"},
			{ID: "unsigned", Declared: true, Health: "healthy", Source: "未签名转述", ObservedAt: now.Add(-10 * time.Second).Format(time.RFC3339), Applied: "untrusted"},
			{ID: "stale", Declared: true, Health: "healthy", Source: "签名转述", ObservedAt: now.Add(-10 * time.Minute).Format(time.RFC3339), AgeSec: 600, Applied: "snapshot-stale"},
			{ID: "broken", Declared: true, Reached: true, Health: "problem", Source: "直连 /status", ObservedAt: now.Add(-8 * time.Second).Format(time.RFC3339), Applied: "snapshot-broken"},
			{ID: "silent", Declared: true, Health: "unknown", Source: "中控 SSOT · 尚无观测"},
			{ID: "revoked", Declared: true, Reached: true, Health: "healthy", Source: "直连 /status", ObservedAt: now.Format(time.RFC3339), Applied: "snapshot-revoked"},
		}}
	}

	inventory, err := d.Control.Clients.List()
	if err != nil {
		t.Fatal(err)
	}
	merged := mergeClientRuntime(inventory, d.Snapshot(), now)
	if inventory.Clients[2].Status != "online" || inventory.Clients[2].LastSeenAt == "" {
		t.Fatalf("页面合并修改了 registry 原始切片:%+v", inventory.Clients[2])
	}
	byID := make(map[string]ClientView, len(merged.Clients))
	for _, client := range merged.Clients {
		byID[client.ID] = client
	}
	for _, id := range []string{"direct", "signed"} {
		if byID[id].Status != "online" || byID[id].DataPlaneStatus != "online" || byID[id].LastSeenAt == "" || !strings.HasPrefix(byID[id].ConfigState, "applied snapshot-") {
			t.Errorf("%s runtime merge = %+v", id, byID[id])
		}
	}
	if got := byID["unsigned"]; got.Status == "online" || got.DataPlaneStatus != "untrusted observation" || got.LastSeenAt != "" || got.ConfigState != "not reported" {
		t.Errorf("unsigned runtime was trusted: %+v", got)
	}
	if got := byID["stale"]; got.Status != "stale" || got.DataPlaneStatus != "stale" || got.LastSeenAt == "" {
		t.Errorf("stale runtime = %+v", got)
	}
	if got := byID["broken"]; got.Status != "problem" || got.DataPlaneStatus != "problem" {
		t.Errorf("problem runtime = %+v", got)
	}
	if got := byID["silent"]; got.Status == "online" || got.DataPlaneStatus != "not observed" || got.LastSeenAt != "" {
		t.Errorf("silent runtime = %+v", got)
	}
	if got := byID["revoked"]; got.Status != "revoked" {
		t.Errorf("revoked registry state was overwritten: %+v", got)
	}

	body := pageClients(d, clientPageState{}, true)
	for _, want := range []string{"Online", "Stale", "Problem", "untrusted observation", "not observed", "config: applied snapshot-dir"} {
		if !strings.Contains(body, want) {
			t.Errorf("Clients runtime page missing %q", want)
		}
	}
}

func TestClientInvitationShowsRealQRResourceAndLinuxLink(t *testing.T) {
	d := clientUIDeps()
	invite := ClientInviteView{
		InviteID: "invite-123", ClientID: "client-linux01", ClientName: "Build server",
		InviteURI: "loom://enroll#opaque-short-lived-payload",
		ExpiresAt: "2026-08-31T10:15:00Z",
	}
	body := pageClients(d, clientPageState{Invite: &invite}, true)
	for _, want := range []string{
		`src="/api/control/client-invites/invite-123/qr.png"`,
		`href="/api/control/client-invites/invite-123/download"`,
		`alt="Enrollment QR code for client-linux01"`,
		`value="loom://enroll#opaque-short-lived-payload"`,
		`Invitation ready`,
		`short-lived, single-use secret`,
		`sudo ./install.sh --invite-file ../client.loom-invite`,
		`sudo ./install.sh --no-enroll`,
		`sudo /usr/local/bin/loom client enroll -stdin`,
		`press <kbd>Enter</kbd>, then <kbd>Ctrl-D</kbd>`,
		`method=get action="/clients"`,
		`Back to client list`,
		`normal reconnects, restarts and configuration updates do not register the device again`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Invitation result missing %q", want)
		}
	}
	if strings.Contains(body, "EnrollmentURL") {
		t.Fatal("internal claim endpoint label leaked into the enrollment result")
	}
	if strings.Count(body, invite.InviteURI) != 1 {
		t.Fatalf("invitation URI must appear only in the readonly input; count=%d", strings.Count(body, invite.InviteURI))
	}
	if strings.Contains(body, `loom client enroll -invite `) || strings.Contains(body, `printf 'loom://`) {
		t.Fatal("invitation URI was encouraged in shell arguments or command history")
	}
}

func TestAddClientDoesNotAskForPlatformOrRoute(t *testing.T) {
	d := clientUIDeps()
	body := pageClients(d, clientPageState{Create: true}, true)
	for _, want := range []string{
		`action="/clients/create"`, `name=name`, `Display name`,
		`The client reports its supported platform`,
		`Do not enter a platform, exit node or route`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Add client page missing %q", want)
		}
	}
	for _, forbidden := range []string{`name=platform`, `name=exit`, `name=route`} {
		if strings.Contains(body, forbidden) {
			t.Errorf("Add client form exposes forbidden field %q", forbidden)
		}
	}
}

func TestClientsPageDoesNotAdvertiseMissingPackage(t *testing.T) {
	d := clientUIDeps()
	d.Control.Clients.LinuxPackage = func() (LinuxClientPackageView, error) {
		return LinuxClientPackageView{}, errors.New("artifact not published")
	}
	body := pageClients(d, clientPageState{}, true)
	for _, want := range []string{"Package unavailable", "artifact not published"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing-package state omits %q", want)
		}
	}
	if strings.Contains(body, `href="/clients/download/linux-amd64"`) {
		t.Fatal("missing package still advertised a download URL")
	}
}

func TestInvitationDoesNotPresentUnrunnableLinuxCommandsWithoutPackage(t *testing.T) {
	d := clientUIDeps()
	d.Control.Clients.LinuxPackage = func() (LinuxClientPackageView, error) {
		return LinuxClientPackageView{}, errors.New("artifact not published")
	}
	invite := ClientInviteView{
		InviteID: "invite-blocked", ClientID: "client-blocked", ClientName: "Blocked client",
		InviteURI: "loom://enroll#blocked", ExpiresAt: "2026-08-31T10:15:00Z",
	}
	body := pageClients(d, clientPageState{Invite: &invite}, true)
	for _, want := range []string{"Linux package unavailable", "artifact not published", "Back to client list"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing-package invitation state omits %q", want)
		}
	}
	for _, forbidden := range []string{"sudo ./install.sh", `href="/clients/download/linux-amd64"`} {
		if strings.Contains(body, forbidden) {
			t.Errorf("missing-package invitation presents unrunnable action %q", forbidden)
		}
	}
}

func TestClientsNavigationIsControlOnly(t *testing.T) {
	control := shell(clientUIDeps(), "Clients", "", false)
	if !strings.Contains(control, `data-key=clients class=active href="/clients">Clients</a>`) {
		t.Fatal("control navigation is missing the active Clients entry")
	}
	local := clientUIDeps()
	local.Control = nil
	if body := shell(local, "总览", "", false); strings.Contains(body, `href="/clients"`) {
		t.Fatal("local-node navigation exposes control-only client inventory")
	}
}

func TestClientEnrollmentUIAndInvitationArtifacts(t *testing.T) {
	d := clientUIDeps()
	createdInvites := 0
	d.Control.Clients.CreateInvite = func(input ClientInviteInput) (ClientInviteView, error) {
		createdInvites++
		return ClientInviteView{
			InviteID: "invite-ui", ClientID: "client-ui", ClientName: input.Name,
			InviteURI: "loom://enroll#real-short-lived-payload", ExpiresAt: "2026-08-31T10:15:00Z",
		}, nil
	}
	d.Control.Clients.InviteArtifact = func(inviteID string) (ClientInviteArtifact, error) {
		if inviteID != "invite-ui" {
			return ClientInviteArtifact{}, errors.New("not found")
		}
		return ClientInviteArtifact{
			ClientID: "client-ui", ClientName: "Build server",
			InviteURI: "loom://enroll#real-short-lived-payload", ExpiresAt: "2026-08-31T10:15:00Z",
		}, nil
	}

	created := misakaRequest(t, d, http.MethodPost, "/clients/create", url.Values{"name": {"Build server"}}, true)
	if created.Code != http.StatusSeeOther {
		t.Fatalf("POST /clients/create = %d; body=%s", created.Code, created.Body.String())
	}
	if got := created.Header().Get("Location"); got != "/clients/invites/invite-ui" {
		t.Fatalf("POST /clients/create location = %q, want invitation result GET", got)
	}
	if got := created.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("POST /clients/create Cache-Control = %q, want no-store", got)
	}
	if strings.Contains(created.Body.String(), "real-short-lived-payload") {
		t.Fatal("create redirect leaked the bearer invitation in its response body")
	}
	unauthenticatedCreate := misakaRequest(t, d, http.MethodPost, "/clients/create", url.Values{"name": {"Other"}}, false)
	if unauthenticatedCreate.Code != http.StatusSeeOther || unauthenticatedCreate.Header().Get("Location") != loginURL("/clients?new=1") || createdInvites != 1 {
		t.Fatalf("unauthenticated create = %d location=%q calls=%d", unauthenticatedCreate.Code, unauthenticatedCreate.Header().Get("Location"), createdInvites)
	}
	unauthenticatedResult := misakaRequest(t, d, http.MethodGet, created.Header().Get("Location"), nil, false)
	if unauthenticatedResult.Code != http.StatusSeeOther || unauthenticatedResult.Header().Get("Location") != loginURL(created.Header().Get("Location")) {
		t.Fatalf("unauthenticated result = %d location=%q", unauthenticatedResult.Code, unauthenticatedResult.Header().Get("Location"))
	}

	result := misakaRequest(t, d, http.MethodGet, created.Header().Get("Location"), nil, true)
	if result.Code != http.StatusOK {
		t.Fatalf("GET invitation result = %d; body=%s", result.Code, result.Body.String())
	}
	if got := result.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("GET invitation result Cache-Control = %q, want no-store", got)
	}
	for _, want := range []string{"Build server", `/api/control/client-invites/invite-ui/qr.png`, `loom://enroll#real-short-lived-payload`} {
		if !strings.Contains(result.Body.String(), want) {
			t.Errorf("created invitation page missing %q", want)
		}
	}
	for _, want := range []string{`method=get action="/clients"`, `Back to client list`, `loom client enroll -stdin`, `Ctrl-D`} {
		if !strings.Contains(result.Body.String(), want) {
			t.Errorf("invitation result missing return/setup control %q", want)
		}
	}
	refreshed := misakaRequest(t, d, http.MethodGet, created.Header().Get("Location"), nil, true)
	if refreshed.Code != http.StatusOK || createdInvites != 1 {
		t.Fatalf("refresh result=%d create calls=%d; result refresh must not create another invitation", refreshed.Code, createdInvites)
	}
	list := misakaRequest(t, d, http.MethodGet, "/clients", nil, true)
	if list.Code != http.StatusOK || list.Header().Get("Cache-Control") != "no-store" ||
		strings.Contains(list.Body.String(), "real-short-lived-payload") {
		t.Fatalf("Done target /clients = %d headers=%v; list must be no-store and contain no invitation secret", list.Code, list.Header())
	}

	qr := misakaRequest(t, d, http.MethodGet, "/api/control/client-invites/invite-ui/qr.png", nil, true)
	if qr.Code != http.StatusOK || qr.Header().Get("Content-Type") != "image/png" || !strings.HasPrefix(qr.Body.String(), "\x89PNG\r\n\x1a\n") {
		t.Fatalf("QR resource is not a PNG: status=%d content-type=%q prefix=%q", qr.Code, qr.Header().Get("Content-Type"), qr.Body.Bytes()[:min(len(qr.Body.Bytes()), 8)])
	}
	download := misakaRequest(t, d, http.MethodGet, "/api/control/client-invites/invite-ui/download", nil, true)
	if download.Code != http.StatusOK || strings.TrimSpace(download.Body.String()) != "loom://enroll#real-short-lived-payload" ||
		!strings.Contains(download.Header().Get("Content-Disposition"), "client.loom-invite") {
		t.Fatalf("invitation download = %d headers=%v body=%q", download.Code, download.Header(), download.Body.String())
	}
	unauthorized := misakaRequest(t, d, http.MethodGet, "/api/control/client-invites/invite-ui/download", nil, false)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized invitation download = %d, want 401", unauthorized.Code)
	}
}
