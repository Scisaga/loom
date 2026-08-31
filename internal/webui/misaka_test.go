package webui

import (
	"context"
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

const misakaPrivateSentinel = "-----BEGIN PRIVATE KEY-----MUST-NEVER-LEAVE-CONTROL"

func misakaDeps() Deps {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	view := View{
		Self:         "jm24",
		Applied:      "snapshot-0123456789abcdef",
		ObservedAt:   now.Add(-12 * time.Second).Format(time.RFC3339),
		IntentSource: "current SSOT",
		Nodes: []NodeView{
			{
				ID: "jm24", Name: "Jiangmen", City: "Jiangmen", Provider: "edge",
				Declared: true,
				Health:   "healthy", Self: true, Reached: true, Applied: "snapshot-0123456789abcdef",
				ObservedAt: now.Add(-12 * time.Second).Format(time.RFC3339), Source: "direct /status",
				Direction: "bidirectional", EgressCapable: true,
				Tunnels: []TunnelView{{
					Interface: "wg-loom-sg02", CarrierPresent: true, State: "active", AgeSec: 9,
					RxBytes: 1536, TxBytes: 2 * 1024 * 1024, CounterPresent: true, OK: true,
				}},
			},
			{
				ID: "sg02", Name: "Singapore", Health: "healthy", Reached: true,
				Declared: true,
				Applied:  "snapshot-0123456789abcdef", ObservedAt: now.Add(-18 * time.Second).Format(time.RFC3339),
				Source: "jm24 relay", Direction: "bidirectional", EgressCapable: true,
			},
		},
		Links: []LinkView{{
			From: "jm24", To: "sg02", Kind: "tunnel", State: "active", MS: 42,
			ObservedAt: now.Add(-12 * time.Second).Format(time.RFC3339), Source: "jm24",
		}},
		Routes: []RouteView{{
			Node: "jm24", Declaration: "intl-api", Selector: "svc:intl-api",
			ScopeKind: ScopeService, ScopeID: "intl-api", PolicyID: "best-egress",
			Candidate: "sg02", Chain: []string{"jm24", "sg02"},
			ObservedAt: now.Add(-12 * time.Second).Format(time.RFC3339), Source: "agent/jm24",
		}},
		Candidates: []CandidatePathView{{
			Node: "jm24", Declaration: "intl-api", ScopeKind: ScopeService,
			ScopeID: "intl-api", PolicyID: "best-egress", Chain: []string{"jm24", "sg02"},
			State: "selected", ObservedAt: now.Add(-12 * time.Second).Format(time.RFC3339), Source: "agent/jm24",
		}},
		Services: []ServiceView{{
			ID: "intl-api", Name: "International APIs", PolicyID: "best-egress",
			Addresses: []string{"api.example.net", ".example.org"},
			Hosts:     []HostRuleView{{Host: "api.example.net", Match: "exact"}, {Host: ".example.org", Match: "suffix"}},
		}},
		Policies: []PolicyView{{
			ID: "best-egress", Name: "Best egress", Objective: "latency", MaxHops: 2,
			AllowedServers: []string{"sg02"}, RankingPeriod: "1m", TuningPeriod: "5m",
			Window: "10m", MinSamples: 3, Fallback: "direct",
		}},
		Ingresses: []IngressView{{
			Node: "jm24", Kind: "mixed", Listen: "127.0.0.1:1080", Mode: "host-based",
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
			TS: "2026-08-28T11:59:00Z", Node: "jm24", Kind: "tunnel", Subject: "wg-loom-sg02",
			From: "active", To: "failed", Level: "problem", Ongoing: true, Lasted: "1m",
			Detail: "needle, with a \"quoted\" peer",
		},
		{
			TS: "2026-08-28T11:58:00Z", Node: "sg02", Kind: "publisher", Subject: "snapshot",
			From: "old", To: "new", Level: "info", Detail: "must-not-match",
		},
		{
			TS: "2026-08-28T11:57:00Z", Node: "jm24", Kind: "tunnel", Subject: "wg-other",
			From: "failed", To: "active", Level: "ok", Detail: "needle but wrong level",
		},
	}
	return Deps{
		Node: "jm24", Now: func() time.Time { return now }, Operator: "operator-secret",
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
			BootstrapIdentity: &BootstrapIdentityDeps{
				Status: func() (BootstrapIdentityView, error) {
					return BootstrapIdentityView{
						Ready: true, PublicKey: "ssh-ed25519 AAAAC3Nza loom-control-bootstrap",
						Fingerprint: "SHA256:public-fingerprint", PublicPath: "/etc/loom/control-bootstrap.pub",
					}, nil
				},
				Ensure: func() (BootstrapIdentityView, error) {
					return BootstrapIdentityView{Ready: true, PublicKey: "ssh-ed25519 AAAAC3Nza loom-control-bootstrap"}, nil
				},
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
	direct := RouteView{Node: "jm24", Chain: nil}

	topology := topologySVG(view, direct)
	if !strings.Contains(topology, `class=route-ring`) ||
		!strings.Contains(topology, `class="node selected"`) ||
		!strings.Contains(topology, `class=route-local-exit`) ||
		!strings.Contains(topology, `width=82 height=19`) ||
		!strings.Contains(topology, `font-size=8 font-weight=700`) ||
		!strings.Contains(topology, `>LOCAL EXIT</text>`) {
		t.Fatalf("direct route did not highlight jm24 as its local egress: %s", topology)
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

func misakaEnrollmentDeps() (*NodeEnrollmentDeps, *[]EnrollmentConnection, *[]EnrollmentReviewInput, *[]EnrollmentCommitInput) {
	scans := []EnrollmentConnection{}
	reviews := []EnrollmentReviewInput{}
	commits := []EnrollmentCommitInput{}
	deps := &NodeEnrollmentDeps{
		Scan: func(_ context.Context, connection EnrollmentConnection) (EnrollmentHostKey, error) {
			scans = append(scans, connection)
			return EnrollmentHostKey{
				Algorithm: "ssh-ed25519", PublicKey: "AAAAC3NzaC1lZDI1NTE5AAAAIhost-key",
				Fingerprint: "SHA256:W1f2Qe-test-host-key",
			}, nil
		},
		Review: func(_ context.Context, input EnrollmentReviewInput) (EnrollmentReview, error) {
			reviews = append(reviews, input)
			country := strings.ToUpper(strings.TrimSpace(input.Country))
			city := strings.TrimSpace(input.City)
			geoEvidence := "Country and city were supplied by the operator; GeoIP was not queried again."
			geoSuggested := false
			if input.DisableGeoIP {
				geoEvidence = "GeoIP suggestion was disabled for this declaration review."
			} else if country == "" || city == "" {
				if country == "" {
					country = "HK"
				}
				if city == "" {
					city = "Hong Kong"
				}
				geoSuggested = true
				geoEvidence = "GeoIP suggestion from ipwho.is for public endpoint address 203.0.113.42; approximate and not trusted endpoint or location evidence."
			}
			resolved := input.RequestedDirection
			evidence := "operator-selected after trusted preflight"
			if resolved == "" || resolved == "automatic" {
				resolved = "reverse_only"
				evidence = "automatic is conservative because UDP ingress is not independently verified"
			}
			return EnrollmentReview{
				Connection: input.Connection, HostKey: input.HostKey,
				NodeID: "hk01", ObservedHostname: "HK01", PublicEndpoint: "203.0.113.42",
				Country: country, City: city, DisableGeoIP: input.DisableGeoIP,
				GeoIPSuggested: geoSuggested, GeoIPEvidence: geoEvidence,
				EndpointEvidence: "global SSH target resolved by control; WireGuard UDP unverified",
				System:           "Ubuntu 24.04 · x86_64", Privilege: "bootstrap permitted",
				KernelWireGuard: true, WGCommand: true,
				RequestedDirection: input.RequestedDirection, ResolvedDirection: resolved,
				DirectionEvidence: evidence, Revision: "revision-enroll-9",
				EgressEnabled: true, FixedPolicyID: "hk01-fixed", FixedPolicyName: "固定Hong Kong出口",
				Tunnels: []EnrollmentTunnel{{
					From: "hk01", To: "sg02", FromAddress: "10.99.0.7/32", ToAddress: "10.99.0.8/32",
					Initiator: "sg02", Acceptor: "hk01", ListenPort: 61775,
				}},
			}, nil
		},
		Commit: func(_ context.Context, input EnrollmentCommitInput) (string, error) {
			commits = append(commits, input)
			return "hk01", nil
		},
	}
	return deps, &scans, &reviews, &commits
}

func TestMisakaRoutesAndNavigationContract(t *testing.T) {
	d := misakaDeps()
	for _, target := range []string{
		"/nodes", "/nodes/jm24", "/topology", "/services", "/routing",
		"/deployments", "/events", "/settings",
	} {
		t.Run(strings.TrimPrefix(target, "/"), func(t *testing.T) {
			w := misakaRequest(t, d, http.MethodGet, target, nil, target == "/settings")
			if w.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200; body=%s", target, w.Code, w.Body.String())
			}
		})
	}

	for _, target := range []string{"/nodes/not-declared", "/nodes/jm24/nested", "/not-a-real-page"} {
		if w := misakaRequest(t, d, http.MethodGet, target, nil, false); w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", target, w.Code)
		}
	}

	body := misakaRequest(t, d, http.MethodGet, "/nodes", nil, false).Body.String()
	for _, want := range []string{
		`<header class=header>`, `<nav class=nav`, `<span>LOOM</span>`,
		`<link rel=icon href="/favicon.svg?v=9" type="image/svg+xml">`,
		`href="/"`, `href="/nodes"`, `href="/topology"`, `href="/services"`,
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
	if csp := misakaRequest(t, d, http.MethodGet, "/nodes", nil, false).Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "img-src 'self' data:") {
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

func TestMisakaBootstrapIdentityRequiresAuthenticationAndNeverLeaksPrivateKey(t *testing.T) {
	d := misakaDeps()
	ensureCalls := 0
	d.Control.BootstrapIdentity.Ensure = func() (BootstrapIdentityView, error) {
		ensureCalls++
		return BootstrapIdentityView{Ready: true, PublicKey: "ssh-ed25519 PUBLIC-ONLY"}, nil
	}

	if w := misakaRequest(t, d, http.MethodPost, "/nodes/bootstrap-key/generate", nil, false); w.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated generate = %d, want redirect", w.Code)
	}
	if ensureCalls != 0 {
		t.Fatal("unauthenticated generate created/read a key")
	}
	if w := misakaRequest(t, d, http.MethodGet, "/nodes/bootstrap-key.pub", nil, false); w.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated download = %d, want redirect", w.Code)
	}

	generated := misakaRequest(t, d, http.MethodPost, "/nodes/bootstrap-key/generate", nil, true)
	if generated.Code != http.StatusSeeOther || ensureCalls != 1 {
		t.Fatalf("authenticated generate status=%d calls=%d", generated.Code, ensureCalls)
	}
	pub := misakaRequest(t, d, http.MethodGet, "/nodes/bootstrap-key.pub", nil, true)
	if pub.Code != http.StatusOK {
		t.Fatalf("authenticated public-key download = %d; body=%s", pub.Code, pub.Body.String())
	}
	if got := pub.Header().Get("Content-Disposition"); !strings.Contains(got, "attachment") || !strings.Contains(got, ".pub") {
		t.Fatalf("public key is not an attachment: %q", got)
	}
	if !strings.Contains(pub.Body.String(), "ssh-ed25519 AAAAC3Nza loom-control-bootstrap") {
		t.Fatalf("download does not contain the public key: %q", pub.Body.String())
	}
	for _, response := range []*httptest.ResponseRecorder{
		misakaRequest(t, d, http.MethodGet, "/nodes", nil, true), generated, pub,
	} {
		if strings.Contains(response.Body.String(), misakaPrivateSentinel) || strings.Contains(response.Body.String(), "BEGIN PRIVATE KEY") {
			t.Fatal("bootstrap endpoint exposed private key material")
		}
	}
}

func TestMisakaNodeEnrollmentStartsWithOnlySSHCoordinates(t *testing.T) {
	d := misakaDeps()
	d.Control.Enrollment, _, _, _ = misakaEnrollmentDeps()

	w := misakaRequest(t, d, http.MethodGet, "/nodes/add", nil, true)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /nodes/add = %d; body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		"Host or IP address", "SSH user", "Port", `action="/nodes/add/scan"`,
		"Initial input", "SSH host or IP, user and port only",
		"Country and city are suggested from the public endpoint IP",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("initial enrollment page is missing %q", want)
		}
	}
	for _, name := range []string{"host", "user", "port"} {
		if !misakaHasNamedControl(body, name) {
			t.Errorf("initial enrollment page is missing the %q SSH coordinate", name)
		}
	}
	for _, forbidden := range []string{
		"node", "node_id", "nodeid", "public_endpoint", "endpoint", "egress", "direction",
		"country", "city",
	} {
		if misakaHasNamedControl(body, forbidden) {
			t.Errorf("initial enrollment page lets the operator submit inferred field %q", forbidden)
		}
	}
	if strings.Contains(strings.ToLower(body), "generate key &amp; add") || strings.Contains(strings.ToLower(body), "generate key & add") {
		t.Fatal("enrollment still presents the misleading per-node key-generation action")
	}
}

func TestEnrollmentLocationInputIsOptionalNormalizedAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name, input, want, wantErr string
	}{
		{name: "omitted"},
		{name: "unicode and surrounding space", input: "  香港  ", want: "香港"},
		{name: "too long", input: strings.Repeat("a", 257), wantErr: "exceeds 256 bytes"},
		{name: "control character", input: "Hong\nKong", wantErr: "control character"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{Form: url.Values{"city": {tc.input}}}
			got, err := parseEnrollmentCity(r)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("parseEnrollmentCity error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("parseEnrollmentCity = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		input, want, wantErr string
	}{
		{input: "  hk ", want: "HK"},
		{input: "", want: ""},
		{input: "HKG", wantErr: "two-letter ISO"},
		{input: "H1", wantErr: "two-letter ISO"},
	} {
		r := &http.Request{Form: url.Values{"country": {tc.input}}}
		got, err := parseEnrollmentCountry(r)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("parseEnrollmentCountry(%q) error = %v, want %q", tc.input, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("parseEnrollmentCountry(%q) = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
}

func TestMisakaNodeEnrollmentPOSTsRequireAuthentication(t *testing.T) {
	d := misakaDeps()
	enrollment, scans, reviews, commits := misakaEnrollmentDeps()
	d.Control.Enrollment = enrollment
	forms := map[string]url.Values{
		"/nodes/add/scan": {
			"host": {"203.0.113.42"}, "user": {"loom-bootstrap"}, "port": {"22"},
		},
		"/nodes/add/review": {
			"host": {"203.0.113.42"}, "user": {"loom-bootstrap"}, "port": {"22"},
			"host_key_algorithm": {"ssh-ed25519"}, "host_key_public": {"AAAAtest"},
			"host_key_fingerprint": {"SHA256:test"}, "confirm_host_key": {"yes"},
		},
		"/nodes/add/commit": {
			"host": {"203.0.113.42"}, "user": {"loom-bootstrap"}, "port": {"22"},
			"host_key_algorithm": {"ssh-ed25519"}, "host_key_public": {"AAAAtest"},
			"host_key_fingerprint": {"SHA256:test"}, "direction": {"automatic"},
			"reviewed_direction": {"automatic"},
			"expected_node":      {"hk01"}, "expected_endpoint": {"203.0.113.42"},
			"revision": {"revision-enroll-9"}, "action": {"commit"},
		},
	}
	for target, form := range forms {
		t.Run(strings.TrimPrefix(target, "/nodes/add/"), func(t *testing.T) {
			w := misakaRequest(t, d, http.MethodPost, target, form, false)
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
				t.Fatalf("unauthenticated POST %s = %d location %q, want 303 /login", target, w.Code, w.Header().Get("Location"))
			}
		})
	}
	if len(*scans) != 0 || len(*reviews) != 0 || len(*commits) != 0 {
		t.Fatalf("unauthenticated enrollment reached callbacks: scans=%d reviews=%d commits=%d", len(*scans), len(*reviews), len(*commits))
	}

	for _, target := range []string{"/nodes/add/scan", "/nodes/add/review", "/nodes/add/commit"} {
		if w := misakaRequest(t, d, http.MethodGet, target, nil, true); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", target, w.Code)
		}
	}
}

func TestMisakaNodeEnrollmentTrustReviewPreviewAndCommitContract(t *testing.T) {
	d := misakaDeps()
	enrollment, scans, reviews, commits := misakaEnrollmentDeps()
	d.Control.Enrollment = enrollment
	connectionForm := url.Values{
		"host": {"203.0.113.42"}, "user": {"loom-bootstrap"}, "port": {"2222"},
	}

	scanned := misakaRequest(t, d, http.MethodPost, "/nodes/add/scan", connectionForm, true)
	if scanned.Code != http.StatusOK {
		t.Fatalf("scan = %d; body=%s", scanned.Code, scanned.Body.String())
	}
	if want := []EnrollmentConnection{{Host: "203.0.113.42", User: "loom-bootstrap", Port: 2222}}; !reflect.DeepEqual(*scans, want) {
		t.Fatalf("Scan inputs = %#v, want %#v", *scans, want)
	}
	for _, want := range []string{
		"Confirm SSH host identity", "Operator decision", "SHA256:W1f2Qe-test-host-key",
		"I independently confirmed this host fingerprint", "Do not send the public endpoint IP",
		"Trust key &amp; run preflight",
	} {
		if !strings.Contains(scanned.Body.String(), want) {
			t.Errorf("host-key confirmation is missing %q", want)
		}
	}
	if len(*reviews) != 0 {
		t.Fatal("scanning a key ran trusted preflight before operator confirmation")
	}

	confirmedForm := connectionForm
	confirmedForm.Set("host_key_algorithm", "ssh-ed25519")
	confirmedForm.Set("host_key_public", "AAAAC3NzaC1lZDI1NTE5AAAAIhost-key")
	confirmedForm.Set("host_key_fingerprint", "SHA256:W1f2Qe-test-host-key")
	withoutConfirmation := misakaRequest(t, d, http.MethodPost, "/nodes/add/review", confirmedForm, true)
	if withoutConfirmation.Code != http.StatusOK {
		t.Fatalf("unconfirmed review = %d", withoutConfirmation.Code)
	}
	if len(*reviews) != 0 {
		t.Fatal("Review callback ran without the explicit host-key confirmation checkbox")
	}
	if body := withoutConfirmation.Body.String(); !strings.Contains(body, "confirm the SSH host fingerprint before preflight") || !strings.Contains(body, "Confirm SSH host identity") {
		t.Fatalf("missing confirmation did not fail closed on the confirmation step:\n%s", body)
	}

	confirmedForm.Set("confirm_host_key", "yes")
	reviewed := misakaRequest(t, d, http.MethodPost, "/nodes/add/review", confirmedForm, true)
	if reviewed.Code != http.StatusOK {
		t.Fatalf("confirmed review = %d; body=%s", reviewed.Code, reviewed.Body.String())
	}
	wantReviewInput := EnrollmentReviewInput{
		Connection: EnrollmentConnection{Host: "203.0.113.42", User: "loom-bootstrap", Port: 2222},
		HostKey: EnrollmentHostKey{
			Algorithm: "ssh-ed25519", PublicKey: "AAAAC3NzaC1lZDI1NTE5AAAAIhost-key",
			Fingerprint: "SHA256:W1f2Qe-test-host-key",
		},
		RequestedDirection: "automatic",
	}
	if len(*reviews) != 1 || !reflect.DeepEqual((*reviews)[0], wantReviewInput) {
		t.Fatalf("confirmed Review inputs = %#v, want %#v", *reviews, wantReviewInput)
	}
	reviewBody := reviewed.Body.String()
	if regexp.MustCompile(`%![A-Za-z]\(`).MatchString(reviewBody) {
		t.Fatalf("review page contains a fmt placeholder failure:\n%s", reviewBody)
	}
	for _, want := range []string{
		"Trusted remote observation", "hk01", "derived from remote hostname",
		"Public endpoint candidate", "203.0.113.42",
		"global SSH target resolved by control; WireGuard UDP unverified",
		"Country / city", "Hong Kong", "HK", `name=country`, `name=city`,
		"GeoIP is an editable suggestion, not proof", "ipwho.is", `name=disable_geoip`,
		"Egress", "Enabled", `select name=direction`, "Automatic · conservative",
		"reverse_only", "10.99.0.7/32", "10.99.0.8/32", "sg02", "61775/udp",
		"Fixed exit policy added automatically", "hk01-fixed", "lowest latency (P50)",
		"Reviewed direction is locked for commit", `name=direction value="automatic"`,
		`name=reviewed_direction value="automatic"`, `name=review_token value="`,
		`name=expected_node value="hk01"`, `name=expected_endpoint value="203.0.113.42"`,
		`name=revision value="revision-enroll-9"`, "Not committed",
		"Prepare WG identity &amp; save SSOT declaration", "This is declaration bootstrap, not Agent installation",
		"It does not install or start the Loom Agent", "or claim the node is online",
	} {
		if !strings.Contains(reviewBody, want) {
			t.Errorf("review page is missing trusted/guarded value %q", want)
		}
	}
	if strings.Contains(strings.ToLower(reviewBody), "generate key &amp; add") || strings.Contains(strings.ToLower(reviewBody), "generate key & add") {
		t.Fatal("review action still conflates remote WG identity preparation with creating the shared control key")
	}
	if strings.Contains(reviewBody, "Add hk01 to network") {
		t.Fatal("review action overclaims that declaration bootstrap makes the remote node operational")
	}
	commitForms := regexp.MustCompile(`(?s)<form\b[^>]*action="/nodes/add/commit"[^>]*>.*?</form>`).FindAllString(reviewBody, -1)
	if len(commitForms) != 2 {
		t.Fatalf("review page has %d direction/commit forms, want two isolated forms", len(commitForms))
	}
	if !strings.Contains(commitForms[0], `<select name=direction>`) || !strings.Contains(commitForms[0], `name=action value=preview`) || strings.Contains(commitForms[0], `value=commit`) {
		t.Fatalf("first form is not preview-only:\n%s", commitForms[0])
	}
	if strings.Contains(commitForms[1], `<select name=direction>`) || !strings.Contains(commitForms[1], `name=reviewed_direction value="automatic"`) || !strings.Contains(commitForms[1], `name=action value=commit`) {
		t.Fatalf("second form is not bound to the reviewed direction:\n%s", commitForms[1])
	}

	transactionForm := url.Values{
		"host": {"203.0.113.42"}, "user": {"loom-bootstrap"}, "port": {"2222"},
		"host_key_algorithm": {"ssh-ed25519"}, "host_key_public": {"AAAAC3NzaC1lZDI1NTE5AAAAIhost-key"},
		"host_key_fingerprint": {"SHA256:W1f2Qe-test-host-key"},
		"expected_node":        {"hk01"}, "expected_endpoint": {"203.0.113.42"},
		"revision": {"revision-enroll-9"},
	}
	transactionForm.Set("action", "preview")
	transactionForm.Set("direction", "bidirectional")
	transactionForm.Set("country", "HK")
	transactionForm.Set("city", "Hong Kong")
	previewed := misakaRequest(t, d, http.MethodPost, "/nodes/add/commit", transactionForm, true)
	if previewed.Code != http.StatusOK {
		t.Fatalf("direction preview = %d; body=%s", previewed.Code, previewed.Body.String())
	}
	if len(*reviews) != 2 || (*reviews)[1].RequestedDirection != "bidirectional" || (*reviews)[1].Country != "HK" || (*reviews)[1].City != "Hong Kong" {
		t.Fatalf("preview did not recompute through Review: %#v", *reviews)
	}
	if len(*commits) != 0 {
		t.Fatal("preview committed the network plan")
	}
	if body := previewed.Body.String(); !strings.Contains(body, `name=direction value="bidirectional"`) || !strings.Contains(body, `name=reviewed_direction value="bidirectional"`) || !strings.Contains(body, `name=country value="HK"`) || !strings.Contains(body, `name=city value="Hong Kong"`) {
		t.Fatalf("recomputed page did not bind commit to reviewed bidirectional plan:\n%s", body)
	}

	transactionForm.Set("action", "commit")
	transactionForm.Set("direction", "bidirectional")
	transactionForm.Set("reviewed_direction", "bidirectional")
	transactionForm.Set("review_token", misakaNamedControlValue(t, previewed.Body.String(), "review_token"))
	committed := misakaRequest(t, d, http.MethodPost, "/nodes/add/commit", transactionForm, true)
	if committed.Code != http.StatusSeeOther || committed.Header().Get("Location") != "/nodes?added=hk01" {
		t.Fatalf("commit = %d location %q, want 303 /nodes?added=hk01; body=%s", committed.Code, committed.Header().Get("Location"), committed.Body.String())
	}
	wantCommit := EnrollmentCommitInput{
		EnrollmentReviewInput: EnrollmentReviewInput{
			Connection: EnrollmentConnection{Host: "203.0.113.42", User: "loom-bootstrap", Port: 2222},
			HostKey: EnrollmentHostKey{
				Algorithm: "ssh-ed25519", PublicKey: "AAAAC3NzaC1lZDI1NTE5AAAAIhost-key",
				Fingerprint: "SHA256:W1f2Qe-test-host-key",
			},
			Country: "HK", City: "Hong Kong", RequestedDirection: "bidirectional",
		},
		ExpectedNodeID: "hk01", ExpectedEndpoint: "203.0.113.42", ExpectedRevision: "revision-enroll-9",
	}
	if len(*commits) != 1 || !reflect.DeepEqual((*commits)[0], wantCommit) {
		t.Fatalf("Commit inputs = %#v, want %#v", *commits, wantCommit)
	}
	nodes := misakaRequest(t, d, http.MethodGet, "/nodes?added=hk01", nil, true)
	for _, want := range []string{
		"hk01 declaration was saved to SSOT; its remote WireGuard identity was prepared.",
		"does not install or start the Loom Agent", "does not prove the node is online",
		"unknown / joining",
	} {
		if !strings.Contains(nodes.Body.String(), want) {
			t.Errorf("post-commit Nodes page is missing scope boundary %q", want)
		}
	}
}

func TestMisakaNodeEnrollmentCanDisableGeoIPBeforeFirstLookup(t *testing.T) {
	d := misakaDeps()
	enrollment, _, reviews, _ := misakaEnrollmentDeps()
	d.Control.Enrollment = enrollment
	form := url.Values{
		"host": {"203.0.113.42"}, "user": {"loom-bootstrap"}, "port": {"22"},
		"host_key_algorithm": {"ssh-ed25519"}, "host_key_public": {"AAAAC3Nza-test"},
		"host_key_fingerprint": {"SHA256:test"}, "confirm_host_key": {"yes"},
		"disable_geoip": {"yes"},
	}
	w := misakaRequest(t, d, http.MethodPost, "/nodes/add/review", form, true)
	if w.Code != http.StatusOK || len(*reviews) != 1 || !(*reviews)[0].DisableGeoIP {
		t.Fatalf("GeoIP opt-out did not reach first review: status=%d reviews=%#v", w.Code, *reviews)
	}
	body := w.Body.String()
	if !strings.Contains(body, "GeoIP suggestion was disabled") || !strings.Contains(body, `name=disable_geoip value="yes"`) {
		t.Fatalf("GeoIP opt-out was not preserved in review:\n%s", body)
	}
}

func TestMisakaNodeEnrollmentRejectsUnreviewedDirectionCommit(t *testing.T) {
	for _, tc := range []struct {
		name, direction, reviewed, want string
	}{
		{name: "one field changed", direction: "direct_only", reviewed: "automatic", want: "direction changed after review"},
		{name: "both client fields changed", direction: "direct_only", reviewed: "direct_only", want: "review binding is invalid"},
		{name: "missing binding", direction: "direct_only", reviewed: "", want: "reviewed direction is missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := misakaDeps()
			enrollment, _, reviews, commits := misakaEnrollmentDeps()
			d.Control.Enrollment = enrollment
			reviewedInput := EnrollmentCommitInput{
				EnrollmentReviewInput: EnrollmentReviewInput{
					Connection: EnrollmentConnection{Host: "203.0.113.42", User: "loom-bootstrap", Port: 2222},
					HostKey: EnrollmentHostKey{
						Algorithm: "ssh-ed25519", PublicKey: "AAAAC3NzaC1lZDI1NTE5AAAAIhost-key",
						Fingerprint: "SHA256:W1f2Qe-test-host-key",
					},
					RequestedDirection: "automatic",
				},
				ExpectedNodeID: "hk01", ExpectedEndpoint: "203.0.113.42", ExpectedRevision: "revision-enroll-9",
			}
			form := url.Values{
				"host": {"203.0.113.42"}, "user": {"loom-bootstrap"}, "port": {"2222"},
				"host_key_algorithm": {"ssh-ed25519"}, "host_key_public": {"AAAAC3NzaC1lZDI1NTE5AAAAIhost-key"},
				"host_key_fingerprint": {"SHA256:W1f2Qe-test-host-key"},
				"direction":            {tc.direction}, "reviewed_direction": {tc.reviewed},
				"review_token":  {mintEnrollmentReviewToken(d, reviewedInput)},
				"expected_node": {"hk01"}, "expected_endpoint": {"203.0.113.42"},
				"revision": {"revision-enroll-9"}, "action": {"commit"},
			}
			w := misakaRequest(t, d, http.MethodPost, "/nodes/add/commit", form, true)
			if w.Code != http.StatusOK || w.Header().Get("Location") != "" {
				t.Fatalf("unreviewed commit status=%d location=%q; body=%s", w.Code, w.Header().Get("Location"), w.Body.String())
			}
			if len(*commits) != 0 {
				t.Fatalf("unreviewed direction reached Commit: %#v", *commits)
			}
			if len(*reviews) != 1 || (*reviews)[0].RequestedDirection != tc.direction {
				t.Fatalf("failure page did not recompute the requested direction for explicit review: %#v", *reviews)
			}
			body := w.Body.String()
			for _, want := range []string{tc.want, "Enrollment stopped without changing SSOT", "Not committed"} {
				if !strings.Contains(body, want) {
					t.Errorf("unreviewed direction response is missing %q", want)
				}
			}
		})
	}
}

func TestMisakaEnrollmentReviewTokenBindsEveryCommitBoundary(t *testing.T) {
	d := misakaDeps()
	base := EnrollmentCommitInput{
		EnrollmentReviewInput: EnrollmentReviewInput{
			Connection: EnrollmentConnection{Host: "203.0.113.42", User: "loom-bootstrap", Port: 2222},
			HostKey: EnrollmentHostKey{
				Algorithm: "ssh-ed25519", PublicKey: "AAAAC3NzaC1lZDI1NTE5AAAAIhost-key",
				Fingerprint: "SHA256:W1f2Qe-test-host-key",
			},
			RequestedDirection: "automatic",
		},
		ExpectedNodeID: "hk01", ExpectedEndpoint: "203.0.113.42", ExpectedRevision: "revision-enroll-9",
	}
	token := mintEnrollmentReviewToken(d, base)
	if token == "" || !validEnrollmentReviewToken(d, base, token) {
		t.Fatal("fresh review token does not verify against its reviewed input")
	}
	mutations := []struct {
		name   string
		mutate func(*EnrollmentCommitInput)
	}{
		{"host", func(v *EnrollmentCommitInput) { v.Connection.Host = "203.0.113.43" }},
		{"user", func(v *EnrollmentCommitInput) { v.Connection.User = "root" }},
		{"port", func(v *EnrollmentCommitInput) { v.Connection.Port = 22 }},
		{"host key algorithm", func(v *EnrollmentCommitInput) { v.HostKey.Algorithm = "ssh-rsa" }},
		{"host public key", func(v *EnrollmentCommitInput) { v.HostKey.PublicKey += "tampered" }},
		{"host fingerprint", func(v *EnrollmentCommitInput) { v.HostKey.Fingerprint += "tampered" }},
		{"country", func(v *EnrollmentCommitInput) { v.Country = "SG" }},
		{"city", func(v *EnrollmentCommitInput) { v.City = "Singapore" }},
		{"geoip opt-out", func(v *EnrollmentCommitInput) { v.DisableGeoIP = true }},
		{"direction", func(v *EnrollmentCommitInput) { v.RequestedDirection = "direct_only" }},
		{"node id", func(v *EnrollmentCommitInput) { v.ExpectedNodeID = "hk02" }},
		{"endpoint", func(v *EnrollmentCommitInput) { v.ExpectedEndpoint = "203.0.113.43" }},
		{"revision", func(v *EnrollmentCommitInput) { v.ExpectedRevision = "revision-enroll-10" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := base
			mutation.mutate(&changed)
			if validEnrollmentReviewToken(d, changed, token) {
				t.Fatal("review token accepted a changed commit boundary")
			}
		})
	}
	changedOperator := d
	changedOperator.Operator = "different-operator-secret"
	if validEnrollmentReviewToken(changedOperator, base, token) {
		t.Fatal("review token survived an operator-key change")
	}
}

func TestMisakaNodeEnrollmentBackendFailureDoesNotClaimMutation(t *testing.T) {
	d := misakaDeps()
	enrollment, _, _, commits := misakaEnrollmentDeps()
	enrollment.Commit = func(_ context.Context, input EnrollmentCommitInput) (string, error) {
		*commits = append(*commits, input)
		return "", errors.New("revision conflict: SSOT changed during trusted preflight")
	}
	d.Control.Enrollment = enrollment
	form := url.Values{
		"host": {"203.0.113.42"}, "user": {"loom-bootstrap"}, "port": {"2222"},
		"host_key_algorithm": {"ssh-ed25519"}, "host_key_public": {"AAAAC3NzaC1lZDI1NTE5AAAAIhost-key"},
		"host_key_fingerprint": {"SHA256:W1f2Qe-test-host-key"}, "direction": {"automatic"},
		"reviewed_direction": {"automatic"},
		"expected_node":      {"hk01"}, "expected_endpoint": {"203.0.113.42"},
		"revision": {"stale-revision"}, "action": {"commit"},
	}
	form.Set("review_token", mintEnrollmentReviewToken(d, EnrollmentCommitInput{
		EnrollmentReviewInput: EnrollmentReviewInput{
			Connection: EnrollmentConnection{Host: "203.0.113.42", User: "loom-bootstrap", Port: 2222},
			HostKey: EnrollmentHostKey{
				Algorithm: "ssh-ed25519", PublicKey: "AAAAC3NzaC1lZDI1NTE5AAAAIhost-key",
				Fingerprint: "SHA256:W1f2Qe-test-host-key",
			},
			RequestedDirection: "automatic",
		},
		ExpectedNodeID: "hk01", ExpectedEndpoint: "203.0.113.42", ExpectedRevision: "stale-revision",
	}))
	w := misakaRequest(t, d, http.MethodPost, "/nodes/add/commit", form, true)
	if w.Code != http.StatusOK || len(*commits) != 1 {
		t.Fatalf("failed commit status=%d calls=%d; body=%s", w.Code, len(*commits), w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		"Enrollment stopped without changing SSOT", "revision conflict", "Not committed",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("failed enrollment response is missing %q", want)
		}
	}
	for _, forbidden := range []string{"Enrollment complete", "SSOT saved", "Node added", "added successfully"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(forbidden)) {
			t.Errorf("failed enrollment response falsely claims mutation with %q", forbidden)
		}
	}
	if location := w.Header().Get("Location"); location != "" {
		t.Fatalf("failed enrollment redirected as success to %q", location)
	}
}

func TestMisakaEventsFilterAndCSVEncoding(t *testing.T) {
	d := misakaDeps()
	query := "?node=jm24&kind=tunnel&level=problem&q=needle"
	page := misakaRequest(t, d, http.MethodGet, "/events"+query, nil, false)
	if page.Code != http.StatusOK {
		t.Fatalf("filtered Events page = %d", page.Code)
	}
	if !strings.Contains(page.Body.String(), "wg-loom-sg02") || strings.Contains(page.Body.String(), "must-not-match") || strings.Contains(page.Body.String(), "wg-other") {
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
	if records[1][1] != "jm24" || records[1][2] != "tunnel" || records[1][6] != "problem" || records[1][9] != `needle, with a "quoted" peer` {
		t.Fatalf("filtered CSV row = %#v", records[1])
	}
}

func TestMisakaTunnelCountersStayInTrafficViewsWithoutInventedHistory(t *testing.T) {
	d := misakaDeps()
	detail := misakaRequest(t, d, http.MethodGet, "/nodes/jm24", nil, false)
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
