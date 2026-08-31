package webui

import (
	"strings"
	"testing"
)

func TestServicesPageExplainsRoutingFlowAndSeparatesWorkspacePanels(t *testing.T) {
	d := misakaDeps()
	d.Control.Services = &ServiceControlDeps{
		Upsert: func(ServiceInput, string) error { return nil },
		Delete: func(string, string) error { return nil },
	}

	body := pageServices(d, "intl-api", false, "", false, nil, true)
	for _, want := range []string{
		`class=services-summary`,
		`class=services-flow`,
		`<b>Host</b><span aria-hidden=true>→</span> Service <span aria-hidden=true>→</span> Policy <span aria-hidden=true>→</span> live path`,
		`class=services-workspace`,
		`class="card service-catalog"`,
		`class="card service-editor"`,
		`class=service-host-rules`,
		`class=service-form-actions`,
		`Operator-facing label used across the control center`,
		`Fixed exit pins the final node; relay selection still minimizes latency, with threshold-based anti-flap`,
		`class=service-danger`,
		`class="card services-policy-library"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Services workspace is missing %q", want)
		}
	}
	for _, want := range []string{
		`.service-primary-fields{display:grid;grid-template-columns:minmax(170px,.72fr) minmax(210px,1fr) minmax(230px,1.08fr);gap:12px;align-items:start}`,
		`.service-primary-fields .field{grid-template-rows:auto 40px minmax(14px,auto);align-content:start}`,
		`.service-primary-fields input,.service-primary-fields select,.service-primary-fields .readonly-value{width:100%;height:40px;min-height:40px}`,
	} {
		if !strings.Contains(style, want) {
			t.Errorf("Services primary controls are missing alignment rule %q", want)
		}
	}

	// The routing model should be introduced before the controls that edit it.
	flowAt := strings.Index(body, `class=services-flow`)
	workspaceAt := strings.Index(body, `class=services-workspace`)
	if flowAt < 0 || workspaceAt < 0 || flowAt > workspaceAt {
		t.Errorf("routing flow must precede the editor workspace: flow=%d workspace=%d", flowAt, workspaceAt)
	}
	// Destructive action belongs in its own low-emphasis region rather than the
	// primary save/discard toolbar.
	actionsAt := strings.Index(body, `class=service-form-actions`)
	dangerAt := strings.Index(body, `class=service-danger`)
	if actionsAt < 0 || dangerAt < 0 || actionsAt > dangerAt {
		t.Errorf("danger action must follow normal form actions: actions=%d danger=%d", actionsAt, dangerAt)
	}
	if strings.Contains(body, `<b>Ingress</b>`) {
		t.Error("routing flow still presents ingress as part of the Service rule model")
	}
}

func TestPolicyOptionsExposeAutomaticOrPinnedEgress(t *testing.T) {
	options := policyOptions([]PolicyView{
		{ID: "best-egress", Name: "最优出口", EgressAxis: "any", Objective: "latency"},
		{ID: "de-fixed", Name: "固定德国出口", EgressAxis: "pinned:ber01", Objective: "stability"},
		{ID: "sv-fixed", Name: "固定硅谷出口", EgressAxis: "pinned:sv01", Objective: "stability"},
	}, "sv-fixed")
	for _, want := range []string{
		`最优出口 · automatic egress · lowest latency (P50)`,
		`固定德国出口 · fixed ber01 · tail stability (P95)`,
		`<option value="sv-fixed" selected>固定硅谷出口 · fixed sv01 · tail stability (P95)</option>`,
	} {
		if !strings.Contains(options, want) {
			t.Errorf("policy options do not expose routing semantics %q: %s", want, options)
		}
	}
}

func TestPolicyOptionsDisablePoliciesNotAuthorizedOnControlAccessNode(t *testing.T) {
	options := policyOptions([]PolicyView{{
		ID: "new-edge-fixed", Name: "固定新出口", EgressAxis: "pinned:new-edge",
		Objective: "latency", AvailabilityKnown: true,
	}}, "")
	if !strings.Contains(options, `<option value="new-edge-fixed" disabled>固定新出口 · fixed new-edge · lowest latency (P50) · credentials pending</option>`) {
		t.Fatalf("unprovisioned policy remained selectable: %s", options)
	}
}

func TestServicesPageOmitsTrafficIngressInventoryButKeepsPolicyLibrary(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	v.Ingresses = []IngressView{
		{Node: "jm24", Kind: "mixed", Listen: "127.0.0.1:1080", Mode: "policy", ScopeKind: ScopePolicy, ScopeID: "sg-fixed", PolicyID: "sg-fixed"},
		{Node: "jm24", Kind: "mixed", Listen: "127.0.0.1:1081", Mode: "policy", ScopeKind: ScopePolicy, ScopeID: "de-fixed", PolicyID: "de-fixed"},
		{Node: "jm24", Kind: "mixed", Listen: "127.0.0.1:1082", Mode: "policy", ScopeKind: ScopePolicy, ScopeID: "best-egress", PolicyID: "best-egress"},
		{Node: "jm24", Kind: "mixed", Listen: "127.0.0.1:1083", Mode: "host-based", ScopeKind: ScopeServices, PolicyID: "best-egress", Services: true},
	}
	d.Snapshot = func() View { return v }

	body := pageServices(d, "intl-api", false, "", false, nil, false)
	for _, unwanted := range []string{
		`<div class=label>Configured ingress</div>`,
		`class=services-ingress`,
		`class=ingress-grid`,
		`class=ingress-card`,
		`<h2>Traffic ingress</h2>`,
	} {
		if strings.Contains(body, unwanted) {
			t.Errorf("Services page still contains traffic ingress inventory %q", unwanted)
		}
	}
	for _, want := range []string{
		`<div class=label>Access policies</div>`,
		`class="card services-policy-library"`,
		`<b class=mono>best-egress</b>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Services page dropped policy context %q", want)
		}
	}
}

func TestNodeDetailPromotesManagedIngressAndFoldsLegacyPolicyPorts(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	v.Ingresses = []IngressView{
		{Node: "jm24", Kind: "mixed", Listen: "127.0.0.1:1080", Mode: "policy", ScopeKind: ScopePolicy, ScopeID: "sg-fixed", PolicyID: "sg-fixed"},
		{Node: "jm24", Kind: "mixed", Listen: "127.0.0.1:1081", Mode: "policy", ScopeKind: ScopePolicy, ScopeID: "de-fixed", PolicyID: "de-fixed"},
		{Node: "jm24", Kind: "mixed", Listen: "127.0.0.1:1082", Mode: "policy", ScopeKind: ScopePolicy, ScopeID: "best-egress", PolicyID: "best-egress"},
		{Node: "jm24", Kind: "mixed", Listen: "127.0.0.1:1083", Mode: "host-based", ScopeKind: ScopeServices, PolicyID: "best-egress", Services: true},
		{Node: "sg02", Kind: "mixed", Listen: "127.0.0.1:2080", Mode: "policy", ScopeKind: ScopePolicy, ScopeID: "remote-only", PolicyID: "remote-only"},
	}
	d.Snapshot = func() View { return v }

	body, found := pageNodeDetail(d, "jm24", false)
	if !found {
		t.Fatal("access node detail was not rendered")
	}
	for _, want := range []string{
		`<h2>Application entry points</h2>`,
		`SSOT configuration · not runtime listener health`,
		`Recommended / Managed`,
		`Automatic entry point`,
		`Host → Service → Policy → live path`,
		`class=node-ingress-legacy`,
		`Legacy / Advanced`,
		`3 configured`,
		`127.0.0.1:1080`,
		`127.0.0.1:1081`,
		`127.0.0.1:1082`,
		`127.0.0.1:1083`,
		`policy · sg-fixed`,
		`best-egress`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("node ingress presentation is missing %q", want)
		}
	}
	if strings.Contains(body, `127.0.0.1:2080`) {
		t.Error("node detail included ingress belonging to another node")
	}
	managedAt := strings.Index(body, `127.0.0.1:1083`)
	legacyAt := strings.Index(body, `<details class=node-ingress-legacy>`)
	legacyPortAt := strings.Index(body, `127.0.0.1:1080`)
	if managedAt < 0 || legacyAt < 0 || legacyPortAt < 0 || managedAt > legacyAt || legacyAt > legacyPortAt {
		t.Errorf("managed ingress must remain visible before folded legacy ports: managed=%d details=%d legacy-port=%d", managedAt, legacyAt, legacyPortAt)
	}
	if strings.Contains(body, `<details class=node-ingress-legacy open`) {
		t.Error("legacy / advanced ingress must be collapsed by default")
	}
}

func TestNodeDetailShowsTUNAsPrimaryCaptureNotLegacyPort(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	v.Nodes = append(v.Nodes, NodeView{
		ID: "phone", Name: "Android phone", Declared: true, Health: "unknown",
	})
	v.Ingresses = []IngressView{{
		Node: "phone", Platform: "android", Kind: "tun", Mode: "default_policy",
		ScopeKind: ScopePolicy, ScopeID: "best-egress", PolicyID: "best-egress", Default: true,
	}}
	d.Snapshot = func() View { return v }

	body, found := pageNodeDetail(d, "phone", false)
	if !found {
		t.Fatal("Android access node detail was not rendered")
	}
	for _, want := range []string{
		`<h2>Application entry points</h2>`,
		`Primary capture`,
		`<h3>System TUN</h3>`,
		`Current configuration uses one default policy · central Service matching not enabled`,
		`default_policy`,
		`best-egress`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("TUN presentation is missing %q", want)
		}
	}
	for _, unwanted := range []string{
		`<details class=node-ingress-legacy>`,
		`No Recommended / Managed automatic entry point`,
	} {
		if strings.Contains(body, unwanted) {
			t.Errorf("TUN was misclassified as a legacy fixed-policy port: %q", unwanted)
		}
	}
}
