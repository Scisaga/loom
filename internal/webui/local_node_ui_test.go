package webui

import (
	"net/http"
	"strings"
	"testing"
)

func primaryNavFragment(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, `<nav class=nav`)
	if start < 0 {
		t.Fatal("page has no primary navigation")
	}
	end := strings.Index(body[start:], `</nav>`)
	if end < 0 {
		t.Fatal("primary navigation is not closed")
	}
	return body[start : start+end+len(`</nav>`)]
}

func TestLocalNodeUIUsesDiagnosticNavigationAndHeadings(t *testing.T) {
	d := deps("", nil)
	h := Handler(d)

	for _, path := range []string{"/", "/nodes/n1", "/topology", "/routing"} {
		response := get(t, h, path, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s = %d; body=%s", path, response.Code, response.Body.String())
		}
		body := response.Body.String()
		nav := primaryNavFragment(t, body)
		for _, want := range []string{
			`href="/">Local overview</a>`,
			`href="/nodes/n1">This node</a>`,
			`href="/topology">Topology</a>`,
			`href="/routing">Live paths</a>`,
		} {
			if !strings.Contains(nav, want) {
				t.Errorf("GET %s local navigation is missing %q: %s", path, want, nav)
			}
		}
		for _, forbidden := range []string{
			`href="/services"`, `href="/deployments"`, `href="/events"`,
			`href="/settings"`, `href="/nodes/add"`, `>Nodes</a>`,
		} {
			if strings.Contains(nav, forbidden) {
				t.Errorf("GET %s local navigation exposes control entry %q: %s", path, forbidden, nav)
			}
		}
		if strings.Contains(body, "n1 control plane") || strings.Contains(body, "n1 control-plane") {
			t.Errorf("GET %s describes a regular node as the control plane", path)
		}
	}

	overview := get(t, h, "/", nil).Body.String()
	for _, want := range []string{
		`<title>Local overview · LOOM</title>`,
		`<div class=eyebrow>LOCAL NODE / STATUS</div>`,
		`direct local status with newest trusted network observations`,
		`n1 · Local node`,
	} {
		if !strings.Contains(overview, want) {
			t.Errorf("local overview is missing %q", want)
		}
	}
	for _, forbidden := range []string{`href="/deployments"`, `href="/events"`} {
		if strings.Contains(overview, forbidden) {
			t.Errorf("local overview exposes control-only shortcut %q", forbidden)
		}
	}

	nodes := get(t, h, "/nodes", nil).Body.String()
	for _, forbidden := range []string{
		`href="/nodes/add"`, "Control bootstrap identity", "Open enrollment workflow",
	} {
		if strings.Contains(nodes, forbidden) {
			t.Errorf("read-only fleet inventory exposes enrollment capability %q", forbidden)
		}
	}
}

func TestControlNodeKeepsFullControlNavigation(t *testing.T) {
	d := deps("", nil)
	d.Control = &ControlDeps{}
	body := get(t, Handler(d), "/", nil).Body.String()
	nav := primaryNavFragment(t, body)
	for _, want := range []string{
		`href="/">Overview</a>`, `href="/nodes">Nodes</a>`,
		`href="/topology">Topology</a>`, `href="/services">Services</a>`,
		`data-label="Network"`, `data-label="Traffic"`, `data-label="Operations"`, `data-label="Advanced"`,
		`href="/routing">Live paths</a>`, `href="/deployments">Deployments</a>`,
		`href="/events">Events</a>`, `href="/settings">SSOT</a>`,
	} {
		if !strings.Contains(nav, want) {
			t.Errorf("control navigation is missing %q: %s", want, nav)
		}
	}
	for _, want := range []string{"Network overview", "n1 control plane", `href="/deployments"`, `href="/events"`} {
		if !strings.Contains(body, want) {
			t.Errorf("control overview lost %q", want)
		}
	}
}
