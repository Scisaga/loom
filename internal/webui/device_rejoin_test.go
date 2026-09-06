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

func TestReplacedDevicesAreArchivedAndPointToTheirReplacement(t *testing.T) {
	d := clientUIDeps()
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
