package webui

import (
	"encoding/csv"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func misakaDeps() Deps {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	view := View{
		Self:         "demo-d",
		Applied:      "snapshot-0123456789abcdef",
		ObservedAt:   now.Add(-12 * time.Second).Format(time.RFC3339),
		IntentSource: "current SSOT",
		Nodes: []NodeView{
			{
				ID: "demo-d", Name: "Jiangmen", City: "Jiangmen", Provider: "edge",
				Declared: true,
				Health:   "healthy", Self: true, Reached: true, Applied: "snapshot-0123456789abcdef",
				ObservedAt: now.Add(-12 * time.Second).Format(time.RFC3339), Source: "direct /status",
				Direction: "bidirectional", EgressCapable: true,
				Tunnels: []TunnelView{{
					Interface: "wg-loom-demo-e", CarrierPresent: true, State: "active", AgeSec: 9,
					RxBytes: 1536, TxBytes: 2 * 1024 * 1024, CounterPresent: true, OK: true,
				}},
			},
			{
				ID: "demo-e", Name: "Region D", Health: "healthy", Reached: true,
				Declared: true,
				Applied:  "snapshot-0123456789abcdef", ObservedAt: now.Add(-18 * time.Second).Format(time.RFC3339),
				Source: "demo-d relay", Direction: "bidirectional", EgressCapable: true,
			},
		},
		Links: []LinkView{{
			From: "demo-d", To: "demo-e", Kind: "tunnel", State: "active", MS: 42,
			ObservedAt: now.Add(-12 * time.Second).Format(time.RFC3339), Source: "demo-d",
		}},
		Routes: []RouteView{{
			Node: "demo-d", Declaration: "intl-api", Selector: "svc:intl-api",
			ScopeKind: ScopeService, ScopeID: "intl-api", PolicyID: "best-egress",
			Candidate: "demo-e", Chain: []string{"demo-d", "demo-e"},
			ObservedAt: now.Add(-12 * time.Second).Format(time.RFC3339), Source: "agent/demo-d",
		}},
		Candidates: []CandidatePathView{{
			Node: "demo-d", Declaration: "intl-api", ScopeKind: ScopeService,
			ScopeID: "intl-api", PolicyID: "best-egress", Chain: []string{"demo-d", "demo-e"},
			State: "selected", ObservedAt: now.Add(-12 * time.Second).Format(time.RFC3339), Source: "agent/demo-d",
		}},
		Services: []ServiceView{{
			ID: "intl-api", Name: "International APIs", PolicyID: "best-egress",
			Addresses: []string{"api.example.net", ".example.org"},
			Hosts:     []HostRuleView{{Host: "api.example.net", Match: "exact"}, {Host: ".example.org", Match: "suffix"}},
		}},
		Policies: []PolicyView{{
			ID: "best-egress", Name: "Best egress", Objective: "latency", MaxHops: 2,
			AllowedServers: []string{"demo-e"}, RankingPeriod: "1m", TuningPeriod: "5m",
			Window: "10m", MinSamples: 3, Fallback: "direct",
		}},
		Ingresses: []IngressView{{
			Node: "demo-d", Kind: "mixed", Listen: "127.0.0.1:1080", Mode: "host-based",
			ScopeKind: ScopeServices, PolicyID: "best-egress", Port: 1080, Services: true,
		}},
		Publisher: &PublisherView{
			PID: 42, IntervalSeconds: 30, Commit: "abcdef0123456789", Binary: "fedcba9876543210",
			StartedAt: now.Add(-time.Hour).Format(time.RFC3339), UpdatedAt: now.Add(-5 * time.Second).Format(time.RFC3339),
			LastSuccess: now.Add(-20 * time.Second).Format(time.RFC3339), LastSnapshot: "snapshot-0123456789abcdef",
			Healthy: true,
		},
	}
	events := []EventView{
		{
			TS: "2026-08-28T11:59:00Z", Node: "demo-d", Kind: "tunnel", Subject: "wg-loom-demo-e",
			From: "active", To: "failed", Level: "problem", Ongoing: true, Lasted: "1m",
			Detail: "needle, with a \"quoted\" peer",
		},
		{
			TS: "2026-08-28T11:58:00Z", Node: "demo-e", Kind: "publisher", Subject: "snapshot",
			From: "old", To: "new", Level: "info", Detail: "must-not-match",
		},
		{
			TS: "2026-08-28T11:57:00Z", Node: "demo-d", Kind: "tunnel", Subject: "wg-other",
			From: "failed", To: "active", Level: "ok", Detail: "needle but wrong level",
		},
	}
	return Deps{
		Node: "demo-d", Now: func() time.Time { return now }, Operator: "operator-secret",
		Snapshot: func() View { return view },
		Events: func(limit int) []EventView {
			if limit > len(events) {
				limit = len(events)
			}
			return append([]EventView(nil), events[:limit]...)
		},
		Control: &ControlDeps{
			SSOTPath: "/etc/loom/ssot.yaml",
			Read:     func() (string, error) { return "schema: 1\n", nil },
			Revision: func() (string, error) { return "revision-7", nil },
			Validate: func(string) (string, error) { return "", nil },
			Save:     func(string) error { return nil },
			Distributed: func() (string, error) {
				return "snapshot-0123456789abcdef", nil
			},
		},
	}
}

func TestDeclaredCountersExcludeRetainedUndeclaredObservation(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	view := View{
		Self: "current-a", Applied: "snapshot-new", ObservedAt: now.Format(time.RFC3339), IntentSource: "current SSOT",
		Nodes: []NodeView{
			{ID: "current-a", Declared: true, Self: true, Health: "healthy", Applied: "snapshot-new", ObservedAt: now.Format(time.RFC3339)},
			{ID: "current-b", Declared: true, Health: "unknown", Applied: "snapshot-new", ObservedAt: now.Format(time.RFC3339)},
			{ID: "removed", Health: "problem", Applied: "snapshot-old", ObservedAt: now.Format(time.RFC3339), Source: "signed retained observation"},
		},
	}
	d := Deps{Node: "current-a", Now: func() time.Time { return now }, Snapshot: func() View { return view }}

	nodes := pageNodes(d, false, "")
	for _, want := range []string{
		`<div class=label>Declared</div><div class=metric>2 <small>nodes</small>`,
		`<div class="metric ok">1 <small>trusted</small>`,
		`<div class="metric ok">0 <small>problems</small>`,
		`Undeclared observed`,
		`Not in current SSOT · observation retained`,
	} {
		if !strings.Contains(nodes, want) {
			t.Errorf("Nodes page missing declaration-aware output %q", want)
		}
	}

	overview := pageOverview(d, false)
	for _, want := range []string{
		`<b>1 <small>/ 2 正常</small></b>`,
		`快照 snapshot-new · 全网一致`,
		`Undeclared observed`,
	} {
		if !strings.Contains(overview, want) {
			t.Errorf("Overview missing declaration-aware output %q", want)
		}
	}
	if strings.Contains(overview, "配置仍在同步") {
		t.Fatal("removed runtime node polluted the current declared snapshot verdict")
	}
	if topology := topologySVG(view); !strings.Contains(topology, "undeclared observed") ||
		!strings.Contains(topology, `class="node problem undeclared"`) {
		t.Fatalf("topology did not retain and label the undeclared observation: %s", topology)
	}
}

func TestDirectRouteOverlayHighlightsItsLocalEgressNode(t *testing.T) {
	d := misakaDeps()
	view := d.Snapshot()
	view.Nodes[0].Roles = []string{"control", "access", "server", "egress"}
	direct := RouteView{Node: "demo-d", Chain: nil}

	topology := topologySVG(view, direct)
	if !strings.Contains(topology, `class=route-ring`) ||
		!strings.Contains(topology, `class="node selected"`) ||
		!strings.Contains(topology, `class=route-local-exit`) ||
		!strings.Contains(topology, `width=82 height=19`) ||
		!strings.Contains(topology, `font-size=8 font-weight=700`) ||
		!strings.Contains(topology, `>LOCAL EXIT</text>`) {
		t.Fatalf("direct route did not highlight demo-d as its local egress: %s", topology)
	}
	if strings.Contains(topology, `class="route route-direct"`) || strings.Contains(topology, `<line class=route`) || strings.Contains(topology, `class="topology-edge edge-route"`) {
		t.Fatalf("direct route invented a node-to-node path: %s", topology)
	}
	if !strings.Contains(topology, "control + access + server + egress") {
		t.Fatalf("topology hid the hybrid node's egress role: %s", topology)
	}
}

func misakaRequest(t *testing.T, d Deps, method, target string, form url.Values, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, target, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if authenticated {
		r.AddCookie(&http.Cookie{Name: cookieName, Value: mintToken(d)})
	}
	w := httptest.NewRecorder()
	Handler(d).ServeHTTP(w, r)
	return w
}

func misakaHasNamedControl(body, name string) bool {
	pattern := `(?i)<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']?` + regexp.QuoteMeta(name) + `(?:["'\s>])`
	return regexp.MustCompile(pattern).MatchString(body)
}

func misakaNamedControlValue(t *testing.T, body, name string) string {
	t.Helper()
	pattern := `(?i)<input\b[^>]*\bname\s*=\s*["']?` + regexp.QuoteMeta(name) + `["']?[^>]*\bvalue\s*=\s*"([^"]*)"`
	match := regexp.MustCompile(pattern).FindStringSubmatch(body)
	if len(match) != 2 || match[1] == "" {
		t.Fatalf("page is missing a non-empty %q input", name)
	}
	return match[1]
}

func TestMisakaRoutesAndNavigationContract(t *testing.T) {
	d := misakaDeps()
	for _, target := range []string{
		"/devices", "/nodes", "/nodes/demo-d", "/topology", "/services", "/routing",
		"/deployments", "/events", "/settings",
	} {
		t.Run(strings.TrimPrefix(target, "/"), func(t *testing.T) {
			w := misakaRequest(t, d, http.MethodGet, target, nil, target == "/settings")
			if w.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200; body=%s", target, w.Code, w.Body.String())
			}
		})
	}

	for _, target := range []string{"/nodes/not-declared", "/nodes/demo-d/nested", "/not-a-real-page"} {
		if w := misakaRequest(t, d, http.MethodGet, target, nil, false); w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", target, w.Code)
		}
	}

	body := misakaRequest(t, d, http.MethodGet, "/devices", nil, false).Body.String()
	for _, want := range []string{
		`<header class=header>`, `<nav class=nav`, `<span>LOOM</span>`,
		`<link rel=icon href="/favicon.svg?v=9" type="image/svg+xml">`,
		`href="/"`, `href="/devices"`, `href="/topology"`, `href="/services"`,
		`href="/routing"`, `href="/deployments"`, `href="/events"`, `href="/settings"`,
		`--font-mono:"SFMono-Regular"`, `font-weight:400;font-synthesis:none`, `.navgroup{display:contents}`,
		`.nav a.active:after{transform:scaleX(1)}`, `@keyframes loom-page-in`,
		`@media(prefers-reduced-motion:reduce)`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("horizontal LOOM navigation is missing %q", want)
		}
	}
	if strings.Contains(body, "translateY(") {
		t.Error("page entry animation must not shift content during refresh")
	}
	for _, forbidden := range []string{
		"avatar", "profile-photo", "<img", "<script", "</script", `href="http`, `src="http`, "@import",
		`"Intel One Mono"`,
	} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(forbidden)) {
			t.Errorf("self-contained navigation contains forbidden %q", forbidden)
		}
	}
	if csp := misakaRequest(t, d, http.MethodGet, "/devices", nil, false).Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "img-src 'self' data:") {
		t.Fatalf("CSP no longer enforces self-contained pages: %q", csp)
	}
}

func TestMisakaServiceWritesAreAuthenticatedStructuredTransactions(t *testing.T) {
	d := misakaDeps()
	var upserts []struct {
		input    ServiceInput
		revision string
	}
	var deletes [][2]string
	d.Control.Services = &ServiceControlDeps{
		Upsert: func(input ServiceInput, revision string) error {
			upserts = append(upserts, struct {
				input    ServiceInput
				revision string
			}{input, revision})
			return nil
		},
		Delete: func(id, revision string) error {
			deletes = append(deletes, [2]string{id, revision})
			return nil
		},
	}
	form := url.Values{
		"id":          {" new-api "},
		"name":        {" New API "},
		"declaration": {" best-egress "},
		"revision":    {"revision-form-3"},
		"addresses":   {"api.example.com\n.example.net, cdn.example.org\r\n"},
	}

	if w := misakaRequest(t, d, http.MethodPost, "/services/save", form, false); w.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated save = %d, want redirect", w.Code)
	}
	if len(upserts) != 0 {
		t.Fatal("unauthenticated Service save called the structured callback")
	}
	if w := misakaRequest(t, d, http.MethodGet, "/services", nil, true); w.Code != http.StatusOK {
		t.Fatalf("GET /services = %d", w.Code)
	}
	if w := misakaRequest(t, d, http.MethodGet, "/services/save", nil, true); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /services/save = %d, want 405", w.Code)
	}
	if len(upserts) != 0 || len(deletes) != 0 {
		t.Fatal("a Service GET performed a write")
	}

	w := misakaRequest(t, d, http.MethodPost, "/services/save", form, true)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("authenticated save = %d, want 303; body=%s", w.Code, w.Body.String())
	}
	if len(upserts) != 1 {
		t.Fatalf("Upsert calls = %d, want 1", len(upserts))
	}
	want := ServiceInput{
		ID: "new-api", Name: "New API", Declaration: "best-egress",
		Addresses: []string{"api.example.com", ".example.net", "cdn.example.org"},
	}
	if !reflect.DeepEqual(upserts[0].input, want) || upserts[0].revision != "revision-form-3" {
		t.Fatalf("structured upsert = %#v @ %q, want %#v @ revision-form-3", upserts[0].input, upserts[0].revision, want)
	}

	deleteForm := url.Values{"id": {"intl-api"}, "revision": {"revision-delete-4"}}
	if w := misakaRequest(t, d, http.MethodPost, "/services/delete", deleteForm, false); w.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated delete = %d, want redirect", w.Code)
	}
	if len(deletes) != 0 {
		t.Fatal("unauthenticated Service delete called the callback")
	}
	if w := misakaRequest(t, d, http.MethodPost, "/services/delete", deleteForm, true); w.Code != http.StatusSeeOther {
		t.Fatalf("authenticated delete = %d, want 303", w.Code)
	}
	if !reflect.DeepEqual(deletes, [][2]string{{"intl-api", "revision-delete-4"}}) {
		t.Fatalf("Delete calls = %#v", deletes)
	}
}

func TestMisakaServiceWriteFailuresEchoSubmittedInput(t *testing.T) {
	d := misakaDeps()
	d.Control.Services = &ServiceControlDeps{
		Upsert: func(ServiceInput, string) error { return errors.New("service validation failed") },
		Delete: func(string, string) error { return errors.New("service revision conflict") },
	}

	saveForm := url.Values{
		"id":          {"intl-api"},
		"name":        {"Operator draft"},
		"declaration": {"not-yet-valid-policy"},
		"revision":    {"stale-save-revision"},
		"addresses":   {"draft.example.net\n.draft.example.org"},
	}
	save := misakaRequest(t, d, http.MethodPost, "/services/save", saveForm, true)
	if save.Code != http.StatusOK {
		t.Fatalf("failed save = %d, want 200; body=%s", save.Code, save.Body.String())
	}
	for _, want := range []string{
		"service validation failed",
		`value="intl-api" readonly`,
		`value="Operator draft"`,
		`<option value="not-yet-valid-policy" selected>`,
		"draft.example.net\n.draft.example.org",
		"Submitted values · not saved",
	} {
		if !strings.Contains(save.Body.String(), want) {
			t.Errorf("failed save did not echo submitted value %q", want)
		}
	}
	deleteForm := url.Values{
		"id":          {"intl-api"},
		"name":        {"Delete review copy"},
		"declaration": {"delete-policy-copy"},
		"revision":    {"stale-delete-revision"},
		"addresses":   {"delete.example.net\n.delete.example.org"},
	}
	deleted := misakaRequest(t, d, http.MethodPost, "/services/delete", deleteForm, true)
	if deleted.Code != http.StatusOK {
		t.Fatalf("failed delete = %d, want 200; body=%s", deleted.Code, deleted.Body.String())
	}
	for _, want := range []string{
		"service revision conflict",
		`value="Delete review copy"`,
		`<option value="delete-policy-copy" selected>`,
		"delete.example.net\n.delete.example.org",
		"Submitted values · not saved",
	} {
		if !strings.Contains(deleted.Body.String(), want) {
			t.Errorf("failed delete did not echo submitted value %q", want)
		}
	}
}

func TestMisakaServiceDeleteFormCarriesDisplayedDefinition(t *testing.T) {
	d := misakaDeps()
	d.Control.Services = &ServiceControlDeps{
		Upsert: func(ServiceInput, string) error { return nil },
		Delete: func(string, string) error { return nil },
	}
	body := misakaRequest(t, d, http.MethodGet, "/services?service=intl-api", nil, true).Body.String()
	for _, want := range []string{
		`action="/services/delete"`,
		`name=name value="International APIs"`,
		`name=declaration value="best-egress"`,
		"<textarea hidden name=addresses>api.example.net\n.example.org</textarea>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("delete form is missing displayed ServiceInput field %q", want)
		}
	}
}

func TestMisakaRawSSOTPrefersRevisionGuardAndShowsConflict(t *testing.T) {
	d := misakaDeps()
	legacyCalls, guardedCalls := 0, 0
	d.Control.Save = func(string) error {
		legacyCalls++
		return nil
	}
	d.Control.SaveIfRevision = func(content, revision string) error {
		guardedCalls++
		if content != "schema: 2\n" || revision != "stale-revision" {
			t.Fatalf("SaveIfRevision(%q, %q)", content, revision)
		}
		return errors.New("revision conflict: the SSOT changed after this form was opened")
	}
	w := misakaRequest(t, d, http.MethodPost, "/settings", url.Values{
		"action": {"save"}, "content": {"schema: 2\n"}, "revision": {"stale-revision"},
	}, true)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /settings = %d; body=%s", w.Code, w.Body.String())
	}
	if guardedCalls != 1 || legacyCalls != 0 {
		t.Fatalf("guarded calls=%d legacy calls=%d; revision-safe save must have priority", guardedCalls, legacyCalls)
	}
	for _, want := range []string{"revision conflict", "SSOT changed after this form was opened", "schema: 2"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("conflict page does not preserve/display %q", want)
		}
	}
}

func TestMisakaEventsFilterAndCSVEncoding(t *testing.T) {
	d := misakaDeps()
	query := "?node=demo-d&kind=tunnel&level=problem&q=needle"
	page := misakaRequest(t, d, http.MethodGet, "/events"+query, nil, false)
	if page.Code != http.StatusOK {
		t.Fatalf("filtered Events page = %d", page.Code)
	}
	if !strings.Contains(page.Body.String(), "wg-loom-demo-e") || strings.Contains(page.Body.String(), "must-not-match") || strings.Contains(page.Body.String(), "wg-other") {
		t.Fatalf("Events page filter was not applied:\n%s", page.Body.String())
	}

	exported := misakaRequest(t, d, http.MethodGet, "/events.csv"+query, nil, false)
	if exported.Code != http.StatusOK {
		t.Fatalf("filtered Events CSV = %d", exported.Code)
	}
	if got := exported.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/csv") {
		t.Fatalf("CSV content type = %q", got)
	}
	raw := exported.Body.String()
	if !strings.Contains(raw, `"needle, with a ""quoted"" peer"`) {
		t.Fatalf("CSV writer did not escape comma and quotes: %q", raw)
	}
	records, err := csv.NewReader(strings.NewReader(raw)).ReadAll()
	if err != nil {
		t.Fatalf("export is not valid CSV: %v\n%s", err, raw)
	}
	if len(records) != 2 {
		t.Fatalf("CSV records = %d, want header + one filtered event: %#v", len(records), records)
	}
	if records[1][1] != "demo-d" || records[1][2] != "tunnel" || records[1][6] != "problem" || records[1][9] != `needle, with a "quoted" peer` {
		t.Fatalf("filtered CSV row = %#v", records[1])
	}
}

func TestMisakaTunnelCountersStayInTrafficViewsWithoutInventedHistory(t *testing.T) {
	d := misakaDeps()
	detail := misakaRequest(t, d, http.MethodGet, "/nodes/demo-d", nil, false)
	if detail.Code != http.StatusOK {
		t.Fatalf("node detail = %d", detail.Code)
	}
	for _, want := range []string{
		"WG RX total", "WG TX total", "1.50 KiB", "2.00 MiB",
		"current cumulative counters · history not retained", "Direct-self /status counter evidence.",
		"direct non-WireGuard, service/sing-box and Hysteria2 traffic are excluded",
		"Bars compare current counters; they are not time buckets.",
	} {
		if !strings.Contains(detail.Body.String(), want) {
			t.Errorf("node detail is missing counter/history boundary %q", want)
		}
	}

	overview := misakaRequest(t, d, http.MethodGet, "/", nil, false).Body.String()
	for _, want := range []string{
		"Current cumulative counters by local interface", "Direct self /status only", "not a time series",
	} {
		if !strings.Contains(overview, want) {
			t.Errorf("Overview is missing its direct-self aggregate boundary %q", want)
		}
	}

	for _, target := range []string{"/nodes", "/topology", "/services", "/routing", "/deployments", "/events"} {
		body := misakaRequest(t, d, http.MethodGet, target, nil, false).Body.String()
		if strings.Contains(body, "1.50 KiB") || strings.Contains(body, "2.00 MiB") {
			t.Errorf("%s exposes per-node raw tunnel counters outside Overview/Node detail", target)
		}
	}
}
