package webui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestLoginPreservesSafeRequestedPage(t *testing.T) {
	d := misakaDeps()
	target := "/services?service=intl-api"
	login := misakaRequest(t, d, http.MethodGet, loginURL(target), nil, false)
	if login.Code != http.StatusOK || login.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET login = %d headers=%v", login.Code, login.Header())
	}
	for _, want := range []string{`name=next value="/services?service=intl-api"`, `return to <code>/services?service=intl-api</code>`} {
		if !strings.Contains(login.Body.String(), want) {
			t.Errorf("login page did not preserve destination %q", want)
		}
	}

	failed := misakaRequest(t, d, http.MethodPost, "/login", url.Values{
		"password": {"wrong"}, "next": {target},
	}, false)
	if failed.Code != http.StatusOK || !strings.Contains(failed.Body.String(), `name=next value="/services?service=intl-api"`) {
		t.Fatalf("failed login lost destination: status=%d body=%s", failed.Code, failed.Body.String())
	}

	success := misakaRequest(t, d, http.MethodPost, "/login", url.Values{
		"password": {d.Operator}, "next": {target},
	}, false)
	if success.Code != http.StatusSeeOther || success.Header().Get("Location") != target {
		t.Fatalf("successful login = %d location %q, want %q", success.Code, success.Header().Get("Location"), target)
	}
	if len(success.Result().Cookies()) == 0 || success.Result().Cookies()[0].Name != cookieName {
		t.Fatal("successful login did not set the operator session cookie")
	}
}

func TestLoginReturnTargetRejectsExternalAndWriteRoutes(t *testing.T) {
	for _, target := range []string{
		"", "https://evil.example/", "//evil.example/", `/\\evil.example`, `/%5c%5cevil.example`,
		"/devices/create", "/clients/create", "/services/save", "/services/delete", "/nodes/add", "/nodes/add/commit", "/devices?legacy=ssh",
		"/login", "/logout", "/act/publish", "/unknown", "/nodes/..", "/clients/invites/../clients",
	} {
		if got := safeLoginReturnTo(target); got != "/" {
			t.Errorf("safeLoginReturnTo(%q) = %q, want overview fallback", target, got)
		}
	}
	for _, target := range []string{
		"/", "/devices?new=1", "/devices/invites/invite-1", "/devices/download/linux-amd64", "/devices/demo-d",
		"/clients?new=1", "/clients/invites/invite-1", "/clients/download/linux-amd64",
		"/nodes", "/nodes/demo-d", "/topology?entry=demo-d%3Asvc%3Aintl-api",
		"/services?service=intl-api", "/routing?entry=demo-d%3Asvc%3Aintl-api", "/deployments", "/events", "/settings",
	} {
		if got := safeLoginReturnTo(target); got != target {
			t.Errorf("safeLoginReturnTo(%q) = %q", target, got)
		}
	}
}

func TestEveryNavigationPageSignsInBackToItsPage(t *testing.T) {
	d := misakaDeps()
	cases := map[string]string{
		"总览":            "/",
		"Devices":       "/devices",
		"Topology":      "/topology",
		"Services":      "/services",
		"Live paths":    "/routing",
		"Deployments":   "/deployments",
		"事件":            "/events",
		"改 SSOT":        "/settings",
		"Node · demo-e": "/nodes/demo-e",
	}
	for title, target := range cases {
		t.Run(title, func(t *testing.T) {
			body := shell(d, title, "", false)
			if !strings.Contains(body, `href="`+loginURL(target)+`">Operator sign in</a>`) {
				t.Fatalf("%s sign-in link does not return to %s", title, target)
			}
		})
	}
}
