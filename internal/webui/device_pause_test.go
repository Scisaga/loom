package webui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDevicePauseAndResumeRequireAuthenticatedPOST(t *testing.T) {
	d := clientUIDeps()
	calls := 0
	paused := false
	d.Control.Clients.SetDevicePaused = func(id string, value bool) error {
		if id != "demo-device" {
			t.Fatalf("unexpected Device %q", id)
		}
		calls++
		paused = value
		return nil
	}
	for _, action := range []string{"pause", "resume"} {
		path := "/devices/" + action
		before := calls
		if got := misakaRequest(t, d, http.MethodGet, path, nil, true); got.Code != http.StatusMethodNotAllowed {
			t.Fatal("GET accepted pause/resume")
		}
		misakaRequest(t, d, http.MethodPost, path, url.Values{"id": {"demo-device"}}, false)
		if got := misakaRequest(t, d, http.MethodPost, path+"?id=demo-device", nil, true); got.Code != http.StatusBadRequest {
			t.Fatal("query parameters performed a write")
		}
		if calls != before {
			t.Fatal("unauthorized request changed device state")
		}
		got := misakaRequest(t, d, http.MethodPost, path, url.Values{"id": {"demo-device"}}, true)
		if got.Code != http.StatusSeeOther || got.Header().Get("Location") != "/devices" || paused != (action == "pause") || calls != before+1 {
			t.Fatalf("%s did not return to the inventory after updating desired state", action)
		}
	}
}

func TestDeviceListOffersPauseOnlyForPureAccessMembers(t *testing.T) {
	d := clientUIDeps()
	d.Control.Clients.SetDevicePaused = func(string, bool) error { return nil }
	d.Control.Clients.List = func() (ClientInventory, error) {
		return ClientInventory{Clients: []ClientView{
			{ID: "demo-active", Status: "ready", Membership: "active", Responsibilities: []string{"use_loom"}},
			{ID: "demo-paused", Status: "stale", Membership: "paused", Responsibilities: []string{"use_loom"}},
			{ID: "demo-combined", Status: "ready", Membership: "active", Responsibilities: []string{"use_loom", "forward"}},
			{ID: "demo-control", Status: "ready", Membership: "active", Responsibilities: []string{"use_loom", "control"}},
			{ID: "demo-pending", Status: "pending", Membership: "identity only", Responsibilities: []string{"use_loom"}},
			{ID: "demo-retired", Status: "ready", Membership: "decommissioned", Responsibilities: []string{"use_loom"}},
		}}, nil
	}
	body := pageDevices(d, clientPageState{}, true)
	for _, want := range []string{`action="/devices/pause"`, `aria-label="Pause demo-active"`, `aria-label="Resume demo-paused"`, `action="/devices/resume"`} {
		if !strings.Contains(body, want) {
			t.Errorf("device list missing %s", want)
		}
	}
	if strings.Count(body, `class=device-pause-action`) != 2 {
		t.Fatal("pause/resume exposed for a non-access-only or inactive identity")
	}
	body = pageDevices(d, clientPageState{}, false)
	if strings.Contains(body, `action="/devices/pause"`) || strings.Contains(body, `action="/devices/resume"`) {
		t.Fatal("anonymous list exposed write forms")
	}
}
