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
		`Host <span aria-hidden=true>→</span> Service <span aria-hidden=true>→</span> Policy <span aria-hidden=true>→</span> live path`,
		`class=services-workspace`,
		`class="card service-catalog"`,
		`class="card service-editor"`,
		`class=service-host-rules`,
		`class=service-form-actions`,
		`class=service-danger`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Services workspace is missing %q", want)
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
}

func TestServicesPageDistinguishesServiceMatchingFromFixedPolicyIngress(t *testing.T) {
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
	for _, want := range []string{
		`<div class=label>Configured ingress</div>`,
		`4 <small>/ 4 valid</small>`,
		`class=ingress-grid`,
		`class=ingress-card`,
		`Service matching`,
		`Fixed policy`,
		`Loopback only`,
		`Local applications on jm24 only`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("ingress presentation is missing %q", want)
		}
	}
	if strings.Contains(body, `<div class=label>Service-aware ingress</div>`) {
		t.Error("summary still describes every ingress as service-aware")
	}
	if got := strings.Count(body, `<article class=ingress-card>`); got != len(v.Ingresses) {
		t.Errorf("ingress cards = %d, want %d", got, len(v.Ingresses))
	}
}
