package webui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDeviceJoinRecoveryRequiresOperatorPOSTAndExplicitIdentityLoss(t *testing.T) {
	d := clientUIDeps()
	called := ""
	d.Control.Clients.RenewInvite = func(id string) (ClientInviteView, error) {
		called = "renew:" + id
		return ClientInviteView{InviteID: "demo-invite"}, nil
	}
	d.Control.Clients.ReplaceDevice = func(id string) (ClientInviteView, error) {
		called = "replace:" + id
		return ClientInviteView{InviteID: "demo-invite"}, nil
	}
	for _, path := range []string{"/devices/renew-invite", "/devices/replace"} {
		response := misakaRequest(t, d, http.MethodGet, path, nil, true)
		if response.Code != http.StatusMethodNotAllowed || called != "" {
			t.Fatal("GET performed Device recovery")
		}
		response = misakaRequest(t, d, http.MethodPost, path, url.Values{"id": {"demo-client"}, "identity_deleted": {"yes"}}, false)
		if response.Code != http.StatusSeeOther || called != "" {
			t.Fatal("anonymous request performed Device recovery")
		}
	}
	response := misakaRequest(t, d, http.MethodPost, "/devices/replace", url.Values{"id": {"demo-client"}}, true)
	if response.Code != http.StatusBadRequest || called != "" {
		t.Fatal("replacement skipped confirmation of deleted identity")
	}
	response = misakaRequest(t, d, http.MethodPost, "/devices/replace?identity_deleted=yes", url.Values{"id": {"demo-client"}}, true)
	if response.Code != http.StatusBadRequest || called != "" {
		t.Fatal("query string supplied destructive confirmation")
	}
	for _, action := range []string{"renew-invite", "replace"} {
		response = misakaRequest(t, d, http.MethodPost, "/devices/"+action, url.Values{"id": {"demo-client"}, "identity_deleted": {"yes"}}, true)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/devices/invites/demo-invite" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("recovery response status=%d headers=%v", response.Code, response.Header())
		}
		if !strings.HasSuffix(called, ":demo-client") {
			t.Fatalf("action=%s", called)
		}
	}
}

func TestJoinedAccessOnlyDeviceRemovalRequiresAuthenticatedConfirmedPost(t *testing.T) {
	d := clientUIDeps()
	d.Control.Clients.List = func() (ClientInventory, error) {
		return ClientInventory{Clients: []ClientView{{
			ID: "demo-joined", Name: "Demo joined", Platform: "windows-desktop",
			Status: "ready", IdentitySource: "enrollment", Membership: "active",
			KeyFingerprint: strings.Repeat("A", 96), Responsibilities: []string{"use_loom"},
		}}}, nil
	}
	removed := ""
	d.Control.Clients.DeleteDevice = func(id string) error {
		removed = id
		return nil
	}

	detail := misakaRequest(t, d, http.MethodGet, "/devices/demo-joined", nil, true)
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), `action="/devices/delete"`) ||
		!strings.Contains(detail.Body.String(), `name=confirm value=yes required`) ||
		!strings.Contains(style, `.kv dd.mono{overflow-wrap:anywhere;word-break:break-word}`) {
		t.Fatalf("joined access Device lacks safe removal or overflow handling: status=%d", detail.Code)
	}
	publicDetail := misakaRequest(t, d, http.MethodGet, "/devices/demo-joined", nil, false)
	if !strings.Contains(publicDetail.Body.String(), `Sign in to remove`) || strings.Contains(publicDetail.Body.String(), `action="/devices/delete"`) {
		t.Fatal("unauthenticated detail exposed a removal form")
	}
	if response := misakaRequest(t, d, http.MethodGet, "/devices/delete", nil, true); response.Code != http.StatusMethodNotAllowed || removed != "" {
		t.Fatal("GET performed Device removal")
	}
	if response := misakaRequest(t, d, http.MethodPost, "/devices/delete", url.Values{"id": {"demo-joined"}, "confirm": {"yes"}}, false); response.Code != http.StatusSeeOther || removed != "" {
		t.Fatal("anonymous request performed Device removal")
	}
	for _, values := range []url.Values{
		{"id": {"demo-joined"}},
		{"id": {"demo-joined"}, "confirm": {"no"}},
	} {
		if response := misakaRequest(t, d, http.MethodPost, "/devices/delete?confirm=yes", values, true); response.Code != http.StatusBadRequest || removed != "" {
			t.Fatal("Device removal accepted missing or query-string confirmation")
		}
	}
	response := misakaRequest(t, d, http.MethodPost, "/devices/delete", url.Values{"id": {"demo-joined"}, "confirm": {"yes"}}, true)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/devices" || removed != "demo-joined" {
		t.Fatalf("confirmed removal status=%d location=%q removed=%q", response.Code, response.Header().Get("Location"), removed)
	}
}

func TestReplacedDevicesAreArchivedAndPointToTheirReplacement(t *testing.T) {
	d := clientUIDeps()
	packageLoads := 0
	d.Control.Clients.LinuxPackage = func() (LinuxClientPackageView, error) {
		packageLoads++
		return LinuxClientPackageView{
			Filename: "loom-client-linux-amd64.tar.gz", URL: "/devices/download/linux-amd64",
			SHA256: "0123456789abcdef", Version: "v1.0.0", Arch: "linux/amd64",
		}, nil
	}
	d.Control.Clients.List = func() (ClientInventory, error) {
		return ClientInventory{Clients: []ClientView{
			{ID: "demo-old", Name: "Demo workstation", Status: "revoked", ReplacedBy: "demo-new"},
			{ID: "demo-new", Name: "Demo workstation", Status: "pending", Replaces: "demo-old"},
			{ID: "demo-joined", Name: "Demo joined", Status: "ready", IdentitySource: "enrollment", Responsibilities: []string{"use_loom"}},
		}}, nil
	}
	d.Control.Clients.RenewInvite = func(string) (ClientInviteView, error) { return ClientInviteView{}, nil }
	d.Control.Clients.ReplaceDevice = func(string) (ClientInviteView, error) { return ClientInviteView{}, nil }
	current := misakaRequest(t, d, http.MethodGet, "/devices", nil, true).Body.String()
	if strings.Contains(current, `href="/devices/demo-old"`) || !strings.Contains(current, `Archived devices (1)`) || !strings.Contains(current, `href="/devices/demo-new"`) {
		t.Fatal("current inventory did not separate archived identity")
	}
	archived := misakaRequest(t, d, http.MethodGet, "/devices?archived=1", nil, true).Body.String()
	if !strings.Contains(archived, `href="/devices/demo-old"`) || strings.Contains(archived, `href="/devices/demo-new"`) {
		t.Fatal("archive inventory contains current identities")
	}
	if packageLoads != 1 || strings.Contains(archived, "Client distribution") {
		t.Fatalf("archive inventory performed unrelated Linux package work: loads=%d", packageLoads)
	}
	old := misakaRequest(t, d, http.MethodGet, "/devices/demo-old", nil, true).Body.String()
	if !strings.Contains(old, `href="/devices/demo-new"`) || strings.Contains(old, `action="/devices/replace"`) {
		t.Fatal("archived identity did not point to replacement or remained replaceable")
	}
	pending := misakaRequest(t, d, http.MethodGet, "/devices/demo-new", nil, true).Body.String()
	if !strings.Contains(pending, `action="/devices/renew-invite"`) || strings.Contains(pending, `action="/devices/replace"`) {
		t.Fatal("pending identity has wrong recovery action")
	}
	joined := misakaRequest(t, d, http.MethodGet, "/devices/demo-joined", nil, true).Body.String()
	if !strings.Contains(joined, `action="/devices/replace"`) || !strings.Contains(joined, `name=identity_deleted value=yes required`) {
		t.Fatal("joined access Device lacks explicit replacement flow")
	}
}

func TestUnauthenticatedDeviceCreationDoesNotLoadLinuxPackage(t *testing.T) {
	d := clientUIDeps()
	packageLoads := 0
	d.Control.Clients.LinuxPackage = func() (LinuxClientPackageView, error) {
		packageLoads++
		return LinuxClientPackageView{}, nil
	}
	body := pageDevices(d, clientPageState{Create: true}, false)
	if packageLoads != 0 || !strings.Contains(body, "Operator session required") {
		t.Fatalf("unauthenticated creation loaded Linux package: loads=%d", packageLoads)
	}
}

func TestRevokedDevicePurgeRequiresAuthenticatedConfirmedPost(t *testing.T) {
	d := clientUIDeps()
	d.Control.Clients.List = func() (ClientInventory, error) {
		return ClientInventory{Clients: []ClientView{{
			ID: "demo-old", Name: "Demo workstation", Status: "revoked", Membership: "revoked",
			DataPlaneStatus: "not applicable", ConfigState: "not applicable", ReplacedBy: "demo-new",
		}}}, nil
	}
	purged := ""
	d.Control.Clients.PurgeRevoked = func(id string) error {
		purged = id
		return nil
	}

	detail := misakaRequest(t, d, http.MethodGet, "/devices/demo-old", nil, true)
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), `class="card notice device-archive-notice"`) ||
		!strings.Contains(detail.Body.String(), `action="/devices/purge-revoked"`) ||
		!strings.Contains(detail.Body.String(), `data: not applicable · config: not applicable`) ||
		!strings.Contains(style, `.device-archive-notice{margin-bottom:14px}`) {
		t.Fatal("revoked Device detail lacks purge action, closed runtime semantics, or card spacing")
	}
	publicDetail := misakaRequest(t, d, http.MethodGet, "/devices/demo-old", nil, false)
	if !strings.Contains(publicDetail.Body.String(), `Sign in to delete`) || strings.Contains(publicDetail.Body.String(), `action="/devices/purge-revoked"`) {
		t.Fatal("unauthenticated detail exposed archived record purge")
	}
	if response := misakaRequest(t, d, http.MethodGet, "/devices/purge-revoked", nil, true); response.Code != http.StatusMethodNotAllowed || purged != "" {
		t.Fatal("GET purged an archived Device")
	}
	if response := misakaRequest(t, d, http.MethodPost, "/devices/purge-revoked", url.Values{"id": {"demo-old"}, "confirm": {"yes"}}, false); response.Code != http.StatusSeeOther || purged != "" {
		t.Fatal("anonymous request purged an archived Device")
	}
	if response := misakaRequest(t, d, http.MethodPost, "/devices/purge-revoked?confirm=yes", url.Values{"id": {"demo-old"}}, true); response.Code != http.StatusBadRequest || purged != "" {
		t.Fatal("archived Device purge accepted query-string confirmation")
	}
	response := misakaRequest(t, d, http.MethodPost, "/devices/purge-revoked", url.Values{"id": {"demo-old"}, "confirm": {"yes"}}, true)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/devices?archived=1" || purged != "demo-old" {
		t.Fatalf("confirmed purge status=%d location=%q purged=%q", response.Code, response.Header().Get("Location"), purged)
	}
}
