package clientruntime

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"loom/internal/agent"
	"loom/internal/clientcore"
)

func pathPlanFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	files := validWindowsBundle("demo-windows", "warn")
	hydrate := func(s string) []byte {
		return []byte(strings.NewReplacer("${secret:api/win01}", "demo-api", "${secret:vault:cred/win01}", "demo-secret").Replace(s))
	}
	var sb singBoxConfig
	if err := json.Unmarshal(hydrate(files["sing-box/config.json"]), &sb); err != nil {
		t.Fatal(err)
	}
	cfg, err := agent.Load(hydrate(files["agent/config.json"]))
	if err != nil {
		t.Fatal(err)
	}
	// §5.6：故意用不可解析、与链无关的 opaque tag 验证没有名称排序选路。
	candidates := []agent.Cand{
		{Tag: "opaque:a@slow", Chain: []string{"demo-prefix-a", "demo-exit"}, ProbeUser: "demo-slow"},
		{Tag: "opaque:z@fast", Chain: []string{"demo-prefix-b", "demo-exit"}, ProbeUser: "demo-fast"},
		{Tag: "opaque:other", Chain: []string{"demo-other"}, ProbeUser: "demo-other"},
		{Tag: "opaque:direct", ProbeUser: "demo-direct"},
	}
	proxy := sb.Outbounds[1]
	sb.Outbounds = append(sb.Outbounds[:1], sb.Outbounds[2:]...)
	sb.Inbounds[0].Users = nil
	sb.Route.Rules = sb.Route.Rules[1:]
	for _, c := range candidates {
		o := proxy
		o.Tag = c.Tag
		if len(c.Chain) == 0 {
			o = singBoxOutbound{Type: "direct", Tag: c.Tag}
		}
		sb.Outbounds = append(sb.Outbounds, o)
		sb.Inbounds[0].Users = append(sb.Inbounds[0].Users, singBoxUser{Username: c.ProbeUser, Password: cfg.ProbeSecret})
		sb.Route.Rules = append([]singBoxRule{{Inbound: []string{"probe-in"}, AuthUser: []string{c.ProbeUser}, Outbound: c.Tag}}, sb.Route.Rules...)
	}
	sb.Outbounds[1].Outbounds = nil
	for _, c := range candidates {
		sb.Outbounds[1].Outbounds = append(sb.Outbounds[1].Outbounds, c.Tag)
	}
	sb.Outbounds[1].Default = candidates[0].Tag
	cfg.Declarations[0].Candidates = candidates
	body, _ := json.Marshal(sb)
	plan, _ := json.Marshal(cfg)
	return body, plan
}

func TestWindowsPreferenceFiltersExplicitChains(t *testing.T) {
	body, planBody := pathPlanFixture(t)
	p, err := validateWindowsAgentPair(body, planBody, "demo-windows")
	if err != nil {
		t.Fatal(err)
	}
	if !p.DirectAvailable() || len(p.Policy().Exits) != 2 {
		t.Fatalf("policy=%+v", p.Policy())
	}
	for _, mode := range []clientcore.Mode{clientcore.Auto, clientcore.FixedExit, clientcore.Direct} {
		pref := clientcore.Preference{Schema: 1, Mode: mode}
		if mode == clientcore.FixedExit {
			pref.Exit = "demo-exit"
		}
		derived, cfg, err := p.Derive(body, pref)
		if err != nil {
			t.Fatal(err)
		}
		var sb singBoxConfig
		_ = json.Unmarshal(derived, &sb)
		want := 4
		if mode == clientcore.FixedExit {
			want = 2
		}
		if mode == clientcore.Direct {
			want = 1
		}
		if len(sb.Outbounds[1].Outbounds) != want || !slices.Contains(sb.Outbounds[1].Outbounds, sb.Outbounds[1].Default) {
			t.Fatal("selector escaped preference")
		}
		if mode == clientcore.Direct {
			if cfg != nil {
				t.Fatal("Direct started Agent")
			}
			continue
		}
		if len(cfg.Declarations[0].Candidates) != want {
			t.Fatal("Agent/selector set mismatch")
		}
		if mode == clientcore.FixedExit {
			for _, c := range cfg.Declarations[0].Candidates {
				if c.Chain[len(c.Chain)-1] != pref.Exit {
					t.Fatal("wrong last hop")
				}
			}
		}
	}
	if _, _, err := p.Derive(body, clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-unauthorized"}); err == nil {
		t.Fatal("accepted empty candidate set")
	}
	if len(p.config.Declarations[0].Candidates) != 4 {
		t.Fatal("preference mutated signed plan")
	}
}

func TestWindowsAgentPairRejectsInvalidPlans(t *testing.T) {
	body, planBody := pathPlanFixture(t)
	tests := map[string]func(*agent.Config){
		"node":                func(c *agent.Config) { c.Node = "demo-another" },
		"schema":              func(c *agent.Config) { c.Schema = 0 },
		"api":                 func(c *agent.Config) { c.API = "192.0.2.1:443" },
		"api secret":          func(c *agent.Config) { c.APISecret = "wrong" },
		"probe secret":        func(c *agent.Config) { c.ProbeSecret = "wrong" },
		"selector":            func(c *agent.Config) { c.Declarations[0].Selector = "missing" },
		"candidate":           func(c *agent.Config) { c.Declarations[0].Candidates[0].Tag = "missing" },
		"probe user":          func(c *agent.Config) { c.Declarations[0].Candidates[0].ProbeUser = "missing" },
		"empty":               func(c *agent.Config) { c.Declarations[0].Candidates = nil },
		"target":              func(c *agent.Config) { c.Declarations[0].Targets = []string{"file:///demo"} },
		"window":              func(c *agent.Config) { c.Declarations[0].MinSamples = 1000 },
		"stale":               func(c *agent.Config) { c.Declarations[0].StaleAfter = "1ms" },
		"threshold":           func(c *agent.Config) { c.Declarations[0].SwitchThreshold = -1 },
		"budget":              func(c *agent.Config) { c.Declarations[0].ProbeBudget = 1 },
		"remote samples":      func(c *agent.Config) { c.SelfReport = "127.0.0.1:1234"; c.AttestationCA = "demo-ca" },
		"duplicate service":   func(c *agent.Config) { c.Declarations = append(c.Declarations, c.Declarations[0]) },
		"duplicate candidate": func(c *agent.Config) { c.Declarations[0].Candidates[1] = c.Declarations[0].Candidates[0] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			var cfg agent.Config
			_ = json.Unmarshal(planBody, &cfg)
			mutate(&cfg)
			b, _ := json.Marshal(cfg)
			if _, err := validateWindowsAgentPair(body, b, "demo-windows"); err == nil {
				t.Fatal("accepted invalid plan")
			}
		})
	}
	for _, extra := range []string{` {}`, ` ` + string(planBody)} {
		if _, err := validateWindowsAgentPair(body, append(append([]byte(nil), planBody...), extra...), ""); err == nil {
			t.Fatal("accepted trailing plan")
		}
	}
	// 规则把同一 probe user 指向另一条路径必须在执行之前拒绝。
	bad := strings.Replace(string(body), `"outbound":"opaque:a@slow"`, `"outbound":"opaque:z@fast"`, 1)
	if _, err := validateWindowsAgentPair([]byte(bad), planBody, ""); err == nil {
		t.Fatal("accepted misdirected probe")
	}
}

func TestWindowsFixedExitRequiresCandidatesForEveryService(t *testing.T) {
	body, planBody := pathPlanFixture(t)
	var sb singBoxConfig
	_ = json.Unmarshal(body, &sb)
	var cfg agent.Config
	_ = json.Unmarshal(planBody, &cfg)
	second := cfg.Declarations[0]
	second.ID = "demo-second-service"
	second.Selector = "opaque:second-selector"
	second.Candidates = []agent.Cand{{Tag: "opaque:second-path", Chain: []string{"demo-other"}, ProbeUser: "demo-second-probe"}}
	cfg.Declarations = append(cfg.Declarations, second)
	proxy := sb.Outbounds[3]
	proxy.Tag = "opaque:second-path"
	sb.Outbounds = append(sb.Outbounds, proxy, singBoxOutbound{Type: "selector", Tag: second.Selector, Default: proxy.Tag, Outbounds: []string{proxy.Tag}})
	sb.Inbounds[0].Users = append(sb.Inbounds[0].Users, singBoxUser{Username: "demo-second-probe", Password: cfg.ProbeSecret})
	sb.Route.Rules = append([]singBoxRule{{Inbound: []string{"probe-in"}, AuthUser: []string{"demo-second-probe"}, Outbound: proxy.Tag}}, sb.Route.Rules...)
	body, _ = json.Marshal(sb)
	planBody, _ = json.Marshal(cfg)
	plan, err := validateWindowsAgentPair(body, planBody, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := plan.Derive(body, clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-exit"}); err == nil {
		t.Fatal("first Service's exit authorization leaked into second Service")
	}
	_, auto, err := plan.Derive(body, clientcore.Preference{Schema: 1, Mode: clientcore.Auto})
	if err != nil {
		t.Fatal(err)
	}
	if len(auto.Declarations) != 2 || len(auto.Declarations[0].Candidates) != 4 || len(auto.Declarations[1].Candidates) != 1 {
		t.Fatal("Auto lost Service candidates")
	}
}
