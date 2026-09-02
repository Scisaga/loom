package report

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"loom/internal/model"
	"loom/internal/webui"
)

func TestEnrichControlViewPreservesSSOTContractAndRouteScope(t *testing.T) {
	s := &model.SSOT{
		Nodes: []model.Node{
			{
				ID: "demo-d", Name: "Control", Country: "CN", City: "Nanjing", Provider: "Example",
				PublicEndpoint: "control.example", Drain: true,
				Server: &model.ServerRole{
					Direction: model.Bidirectional, InboundPort: 443,
					InboundProtocol: model.Trojan, EgressCapable: true,
				},
				Access: &model.AccessRole{
					Platform: model.LinuxServer, Credentials: []string{"c-best", "c-fixed"},
					MixedPorts: []model.MixedPort{
						{Port: 1080, Declaration: "fixed"},
						{Port: 1083, Services: true},
					},
				},
			},
			{
				ID: "desk01", PublicEndpoint: "desk.example", SSHPort: 2222,
				Access: &model.AccessRole{
					Platform: model.Desktop, Credentials: []string{"c-best"}, DefaultDeclaration: "best",
				},
			},
		},
		Services: []model.Service{{
			ID: "intl-api", Name: "International APIs",
			Addresses: []string{"api.example", ".example.net"}, Declaration: "best",
		}},
		Declarations: []model.AccessDeclaration{
			{
				ID: "best", Name: "Best egress", AddressAxis: model.FromRequest,
				EgressAxis: model.EgressAny, Matcher: "host", ProbeURL: "https://probe.example/",
				ProbeBudget: 7, Objective: model.Latency,
				Constraints:    []model.Constraint{{Kind: model.Region, Expr: "country != CN"}},
				AllowedServers: []string{"demo-e", "demo-a"}, MaxHops: 2,
				RankingPeriod: "10m", TuningPeriod: "30s", SwitchThreshold: 0.15,
				TopN: 3, Window: "1h", MinSamples: 6, StaleAfter: "20m",
				Fallback: model.LastKnownGood,
			},
			{ID: "fixed", AddressAxis: model.FromRequest, EgressAxis: "pinned:demo-e"},
		},
		Credentials: []model.Credential{
			{ID: "c-best", Declaration: "best"},
			{ID: "c-fixed", Declaration: "fixed"},
		},
	}
	v := webui.View{
		Self:  "demo-d",
		Nodes: []webui.NodeView{{ID: "demo-d", Health: "healthy", Source: "直连 /status"}},
		Routes: []webui.RouteView{
			{Node: "demo-d", Declaration: "intl-api", Selector: "svc:intl-api", ScopeKind: webui.ScopeService, ScopeID: "intl-api"},
			{Node: "demo-d", Declaration: "fixed", Selector: "decl:fixed", ScopeKind: webui.ScopePolicy, ScopeID: "fixed"},
		},
		Candidates: []webui.CandidatePathView{
			{Node: "demo-d", Declaration: "intl-api"},
			{Node: "demo-d", Declaration: "fixed"},
		},
	}

	enrichControlView(&v, s, "demo-d")

	if len(v.Nodes) != 2 {
		t.Fatalf("SSOT-only node was not retained as unknown: %+v", v.Nodes)
	}
	desk := nodeByID(t, v.Nodes, "desk01")
	if desk.Health != "unknown" {
		t.Fatalf("SSOT-only node was not retained as unknown: %+v", desk)
	}
	jm := nodeByID(t, v.Nodes, "demo-d")
	if jm.Name != "Control" || jm.Country != "CN" || jm.City != "Nanjing" || jm.Provider != "Example" ||
		jm.PublicEndpoint != "control.example" || jm.SSHPort != 22 || !jm.Drain ||
		jm.InboundPort != 443 || jm.InboundProtocol != "trojan" || !jm.IngressKnown || !jm.PublicDialable ||
		!jm.EgressCapable || jm.Direction != "bidirectional" ||
		!slices.Equal(jm.Roles, []string{"control", "access", "server", "egress"}) {
		t.Fatalf("node SSOT metadata was lost or misderived: %+v", jm)
	}
	if jm.Health != "healthy" || jm.Source != "直连 /status" {
		t.Fatalf("desired metadata overwrote observed state: %+v", jm)
	}
	if got := nodeByID(t, v.Nodes, "desk01"); got.SSHPort != 2222 || !got.IngressKnown || !slices.Equal(got.Roles, []string{"access"}) {
		t.Fatalf("access-only node metadata wrong: %+v", got)
	}

	if len(v.Services) != 1 || v.Services[0].PolicyID != "best" ||
		!slices.Equal(v.Services[0].Addresses, []string{"api.example", ".example.net"}) ||
		len(v.Services[0].Hosts) != 2 || v.Services[0].Hosts[1].Match != "suffix" {
		t.Fatalf("service form fields were not preserved: %+v", v.Services)
	}
	best := policyByID(t, v.Policies, "best")
	if best.ProbeBudget != 7 || best.Objective != "latency" || best.SwitchThreshold != 0.15 ||
		best.Fallback != "last_known_good" || !slices.Equal(best.AllowedServers, []string{"demo-e", "demo-a"}) ||
		len(best.Constraints) != 1 || best.Constraints[0].Kind != "region" ||
		!best.AvailabilityKnown || !best.Available {
		t.Fatalf("policy form fields were not preserved: %+v", best)
	}

	if got := ingressBy(t, v.Ingresses, "desk01", "tun", 0); got.PolicyID != "best" ||
		got.Declaration != "best" || !got.Default || !got.Services ||
		got.ScopeKind != webui.ScopeServices || got.Mode != "services" {
		t.Fatalf("TUN 没有同时表达 Service 路由和显式设备默认策略: %+v", got)
	}
	if got := ingressBy(t, v.Ingresses, "demo-d", "mixed", 1083); !got.Services ||
		got.ScopeKind != webui.ScopeServices || got.Listen != "127.0.0.1:1083" {
		t.Fatalf("service-aware mixed ingress wrong: %+v", got)
	}
	if got := ingressBy(t, v.Ingresses, "demo-d", "mixed", 1080); got.PolicyID != "fixed" ||
		got.Declaration != "fixed" || got.ScopeKind != webui.ScopePolicy {
		t.Fatalf("policy mixed ingress wrong: %+v", got)
	}

	for _, route := range v.Routes {
		want := "best"
		if route.ScopeKind == webui.ScopePolicy {
			want = "fixed"
		}
		if route.PolicyID != want {
			t.Fatalf("route policy resolution wrong: %+v", route)
		}
	}
	intl := candidateBy(t, v.Candidates, "demo-d", "intl-api")
	if intl.ScopeKind != webui.ScopeService || intl.PolicyID != "best" || intl.State != "selected" {
		t.Fatalf("current-SSOT service candidate scope wrong: %+v", intl)
	}
	fixed := candidateBy(t, v.Candidates, "demo-d", "fixed")
	if fixed.ScopeKind != webui.ScopePolicy || fixed.PolicyID != "fixed" || fixed.State != "selected" {
		t.Fatalf("runtime-only policy selection was lost: %+v", fixed)
	}
	if got := candidateBy(t, v.Candidates, "desk01", "best"); got.ScopeKind != webui.ScopePolicy {
		t.Fatalf("current-SSOT TUN policy candidate scope wrong: %+v", got)
	}
}

func TestLegacyRouteScopeRefusesServicePolicyIDCollision(t *testing.T) {
	s := &model.SSOT{
		Nodes: []model.Node{{ID: "access", Access: &model.AccessRole{
			Platform: model.LinuxServer, Credentials: []string{"for-service", "for-policy"},
			MixedPorts: []model.MixedPort{{Port: 1080, Declaration: "same"}},
		}}},
		Services:     []model.Service{{ID: "same", Declaration: "service-policy"}},
		Declarations: []model.AccessDeclaration{{ID: "same"}, {ID: "service-policy"}},
		Credentials: []model.Credential{
			{ID: "for-service", Declaration: "service-policy"},
			{ID: "for-policy", Declaration: "same"},
		},
	}
	kind, id := legacyRouteScope(s, &s.Nodes[0], "same")
	if kind != "" || id != "" {
		t.Fatalf("colliding legacy id was guessed as %s/%s", kind, id)
	}
}

func TestIngressViewShowsManagedMixedDeviceDefault(t *testing.T) {
	s := &model.SSOT{
		Nodes: []model.Node{
			{ID: "server", Access: &model.AccessRole{
				Platform: model.LinuxServer, Credentials: []string{"c-de"},
				DefaultDeclaration: "de-fixed",
				MixedPorts:         []model.MixedPort{{Port: 1080, Services: true}},
			}},
			{ID: "phone", Access: &model.AccessRole{
				Platform: model.Android, Credentials: []string{"c-auto"},
			}},
		},
		Credentials: []model.Credential{
			{ID: "c-de", Declaration: "de-fixed"},
			{ID: "c-auto", Declaration: "automatic"},
		},
	}

	views := ingressViews(s)
	got := ingressBy(t, views, "server", "mixed", 1080)
	if !got.Services || !got.Default || got.PolicyID != "de-fixed" ||
		got.ScopeKind != webui.ScopeServices || got.Mode != "services" {
		t.Fatalf("managed mixed 没有展示共用的设备默认策略: %+v", got)
	}
	phone := ingressBy(t, views, "phone", "tun", 0)
	if phone.Default || phone.PolicyID != "" {
		t.Fatalf("单凭据 TUN 不应被隐式推导出设备默认策略: %+v", phone)
	}
}

func TestEnrichControlViewRebuildsIntentFromCurrentSSOT(t *testing.T) {
	s := &model.SSOT{
		Nodes:   []model.Node{{ID: "a"}, {ID: "b"}},
		Tunnels: []model.Tunnel{{From: "a", To: "b"}},
	}
	v := webui.View{
		Nodes: []webui.NodeView{{ID: "a", Edges: []webui.EdgeView{{
			To: "b", MS: 12, Samples: 3, ObservedAt: "2026-08-28T12:00:00Z",
		}}}},
		Links:      []webui.LinkView{{From: "old", To: "intent", Kind: "tunnel"}},
		Candidates: []webui.CandidatePathView{{Node: "old", Declaration: "intent"}},
	}

	enrichControlView(&v, s, "a")
	if len(v.Links) != 1 || v.Links[0].From != "a" || v.Links[0].To != "b" ||
		v.Links[0].State != "active" || v.Links[0].MS != 12 {
		t.Fatalf("desired SSOT edge and observed overlay were not rebuilt together: %+v", v.Links)
	}
	if len(v.Candidates) != 0 {
		t.Fatalf("stale applied-config candidate survived current SSOT enrichment: %+v", v.Candidates)
	}
}

func TestEnrichControlViewKeepsCurrentSSOTDirectHy2Metrics(t *testing.T) {
	const snapshot, revision, observedAt = "snapshot-current", "ssot-current", "2026-08-31T20:00:00Z"
	s := &model.SSOT{Nodes: []model.Node{
		{ID: "demo-b", PublicEndpoint: "gz.example", Server: &model.ServerRole{
			Direction: model.Bidirectional, InboundPort: 61698,
		}},
		{ID: "demo-c", PublicEndpoint: "hz.example", Server: &model.ServerRole{
			Direction: model.Bidirectional, InboundPort: 61698,
		}},
		{ID: "demo-d", Server: &model.ServerRole{Direction: model.Bidirectional},
			Access: &model.AccessRole{Platform: model.LinuxServer}},
	}}
	v := webui.View{Publisher: &webui.PublisherView{LastSnapshot: snapshot, LastSSOT: revision}, Nodes: []webui.NodeView{
		{ID: "demo-b", Applied: snapshot, VerifiedLinkMetrics: []webui.VerifiedLinkMetricView{{
			PeerNode: "demo-c", Transport: "hysteria2", Carrier: "public",
			ObservedAt: observedAt, RTTMS: 32, P50MS: 30, P95MS: 34, Samples: 3,
		}}},
		{ID: "demo-c", Applied: snapshot},
		{ID: "demo-d", Applied: snapshot, VerifiedLinkMetrics: []webui.VerifiedLinkMetricView{
			{PeerNode: "demo-b", Transport: "hysteria2", Carrier: "public", ObservedAt: observedAt, RTTMS: 43, Samples: 2},
			{PeerNode: "demo-c", Transport: "hysteria2", Carrier: "public", ObservedAt: observedAt, RTTMS: 34, Samples: 2},
		}},
	}}

	enrichControlView(&v, s, "demo-d")
	gateCurrentSSOTDirectEvidence(&v, revision)
	got := map[string]webui.LinkView{}
	for _, link := range v.Links {
		if link.Kind == "direct-hy2" {
			got[link.ObservedFrom+"→"+link.ObservedTo] = link
		}
	}
	if len(got) != 3 || got["demo-b→demo-c"].MS != 32 ||
		got["demo-d→demo-b"].MS != 43 || got["demo-d→demo-c"].MS != 34 {
		t.Fatalf("current SSOT projection dropped direct Hy2 inventory or metrics: %+v", v.Links)
	}
}

func TestCurrentSSOTDirectEvidenceRequiresCurrentPublishedSnapshot(t *testing.T) {
	const snapshot, revision = "snapshot-current", "ssot-current"
	base := func() webui.View {
		return webui.View{
			Publisher: &webui.PublisherView{LastSnapshot: snapshot, LastSSOT: revision},
			Nodes: []webui.NodeView{
				{ID: "source", Applied: snapshot},
				{ID: "target", Applied: snapshot, Declared: true, PublicDialable: true},
			},
			Links: []webui.LinkView{{
				From: "source", To: "target", Kind: "direct-hy2", State: "active",
				ObservedFrom: "source", ObservedTo: "target", ObservedAt: "2026-08-31T20:00:00Z", Samples: 3,
			}},
		}
	}
	for name, mutate := range map[string]func(*webui.View, *string){
		"current":                    func(*webui.View, *string) {},
		"SSOT changed after publish": func(_ *webui.View, rev *string) { *rev = "new-ssot" },
		"source still old":           func(v *webui.View, _ *string) { v.Nodes[0].Applied = "old" },
		"target still old":           func(v *webui.View, _ *string) { v.Nodes[1].Applied = "old" },
		"unknown state":              func(v *webui.View, _ *string) { v.Links[0].State = "future-state" },
		"inconsistent active state":  func(v *webui.View, _ *string) { v.Links[0].Failures = 1 },
		"invalid timestamp":          func(v *webui.View, _ *string) { v.Links[0].ObservedAt = "not-a-time" },
	} {
		t.Run(name, func(t *testing.T) {
			v, currentRevision := base(), revision
			mutate(&v, &currentRevision)
			gateCurrentSSOTDirectEvidence(&v, currentRevision)
			if name == "current" && v.Links[0].State != "active" {
				t.Fatalf("current topology evidence was unexpectedly downgraded: %+v", v.Links[0])
			}
			if name != "current" && (v.Links[0].State != "unknown" || v.Links[0].Samples != 0 || v.Links[0].ObservedAt != "") {
				t.Fatalf("mismatched topology evidence survived current-snapshot gate: %+v", v.Links[0])
			}
		})
	}
}

func TestEnrichControlViewKeepsRemovedRuntimeNodeButMarksItUndeclared(t *testing.T) {
	s := &model.SSOT{Nodes: []model.Node{{ID: "current"}}}
	v := webui.View{Nodes: []webui.NodeView{
		{ID: "current", Declared: true, Health: "healthy", Source: "直连 /status"},
		{
			ID: "removed", Declared: true, Name: "Old declaration", PublicEndpoint: "old.example",
			Roles: []string{"server"}, Direction: "bidirectional", EgressCapable: true,
			InboundPort: 61698, InboundProtocol: "hysteria2", IngressKnown: true, PublicDialable: true,
			Health: "healthy", Applied: "old-snapshot",
			ObservedAt: "2026-08-28T12:00:00Z", Source: "签名转述",
		},
	}}

	enrichControlView(&v, s, "current")

	current := nodeByID(t, v.Nodes, "current")
	if !current.Declared {
		t.Fatalf("current SSOT node was not marked declared: %+v", current)
	}
	removed := nodeByID(t, v.Nodes, "removed")
	if removed.Declared {
		t.Fatalf("removed runtime node retained stale declaration membership: %+v", removed)
	}
	if removed.Health != "healthy" || removed.Applied != "old-snapshot" || removed.Source != "签名转述" {
		t.Fatalf("removed runtime node lost diagnostic evidence: %+v", removed)
	}
	if removed.Name != "" || removed.PublicEndpoint != "" || len(removed.Roles) != 0 ||
		removed.Direction != "" || removed.InboundPort != 0 || removed.InboundProtocol != "" || removed.IngressKnown ||
		removed.PublicDialable || removed.EgressCapable {
		t.Fatalf("removed runtime node retained stale desired metadata: %+v", removed)
	}
}

func TestRouteScopeComesFromSelectorNotLegacyDeclaration(t *testing.T) {
	if kind, id, policy := routeScope("svc:intl-api"); kind != webui.ScopeService || id != "intl-api" || policy != "" {
		t.Fatalf("service selector scope = %q/%q/%q", kind, id, policy)
	}
	if kind, id, policy := routeScope("decl:best"); kind != webui.ScopePolicy || id != "best" || policy != "best" {
		t.Fatalf("policy selector scope = %q/%q/%q", kind, id, policy)
	}
	if kind, id, policy := routeScope("best"); kind != "" || id != "" || policy != "" {
		t.Fatalf("unknown selector was guessed = %q/%q/%q", kind, id, policy)
	}
}

func TestEnrichRouteScopeDoesNotGuessUnknownAgentSelector(t *testing.T) {
	s := &model.SSOT{
		Nodes: []model.Node{{ID: "access", Access: &model.AccessRole{
			Platform: model.LinuxServer, Credentials: []string{"c"},
		}}},
		Services:    []model.Service{{ID: "svc", Declaration: "p"}},
		Credentials: []model.Credential{{ID: "c", Declaration: "p"}},
	}
	v := webui.View{Routes: []webui.RouteView{{
		Node: "access", Declaration: "svc", Selector: "opaque-selector",
	}}}
	enrichRouteScopes(&v, s)
	if got := v.Routes[0]; got.ScopeKind != "" || got.ScopeID != "" || got.PolicyID != "" {
		t.Fatalf("unknown runtime selector was guessed from legacy declaration: %+v", got)
	}
	if len(v.Warnings) != 1 || !strings.Contains(v.Warnings[0], "Agent selector") {
		t.Fatalf("unknown selector was not made visible: %+v", v.Warnings)
	}
}

func TestControlDepsEnrichReadsValidatedSSOT(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssot.yaml")
	if err := os.WriteFile(path, []byte(validControlSSOT), 0o644); err != nil {
		t.Fatal(err)
	}
	v := webui.View{Self: "acc"}
	if err := controlDeps(&Control{SSOTPath: path}).Enrich(&v); err != nil {
		t.Fatalf("valid SSOT enrichment failed: %v", err)
	}
	if len(v.Nodes) != 3 || len(v.Policies) != 1 || len(v.Ingresses) != 1 {
		t.Fatalf("validated SSOT was not exposed: nodes=%d policies=%d ingresses=%d", len(v.Nodes), len(v.Policies), len(v.Ingresses))
	}

	if err := os.WriteFile(path, []byte("nodes: ["), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := controlDeps(&Control{SSOTPath: path}).Enrich(&v); err == nil || !strings.Contains(err.Error(), "解析 SSOT") {
		t.Fatalf("invalid SSOT enrichment error = %v", err)
	}
}

func nodeByID(t *testing.T, nodes []webui.NodeView, id string) webui.NodeView {
	t.Helper()
	for _, node := range nodes {
		if node.ID == id {
			return node
		}
	}
	t.Fatalf("node %q not found", id)
	return webui.NodeView{}
}

func policyByID(t *testing.T, policies []webui.PolicyView, id string) webui.PolicyView {
	t.Helper()
	for _, policy := range policies {
		if policy.ID == id {
			return policy
		}
	}
	t.Fatalf("policy %q not found", id)
	return webui.PolicyView{}
}

func ingressBy(t *testing.T, ingresses []webui.IngressView, node, kind string, port int) webui.IngressView {
	t.Helper()
	for _, ingress := range ingresses {
		if ingress.Node == node && ingress.Kind == kind && ingress.Port == port {
			return ingress
		}
	}
	t.Fatalf("ingress %s/%s/%d not found", node, kind, port)
	return webui.IngressView{}
}

func candidateBy(t *testing.T, candidates []webui.CandidatePathView, node, declaration string) webui.CandidatePathView {
	t.Helper()
	for _, candidate := range candidates {
		if candidate.Node == node && candidate.Declaration == declaration {
			return candidate
		}
	}
	t.Fatalf("candidate %s/%s not found in %+v", node, declaration, candidates)
	return webui.CandidatePathView{}
}
