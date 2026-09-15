package webui

import (
	"io"

	"net/http/httptest"
	"net/url"

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
		Node: "demo-d", Now: func() time.Time { return now },
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
	d.Admin = authenticated
	w := httptest.NewRecorder()
	Handler(d).ServeHTTP(w, r)
	return w
}
