package control

import (
	"encoding/json"
	"testing"
)

func TestCandidateDiagnosticSharesServiceAndDenyExclusions(t *testing.T) {
	p := hy2ProjectionFixture(t)
	p.NetworkIntent.Policies[0].AllowDirect = new(true)
	denyService := Service{ID: "demo-denied-service", Name: "Demo denied", Kind: "internet", Matchers: []ServiceMatcher{{Kind: "dns_suffix", Value: "private.example"}}}
	denyPolicy := p.NetworkIntent.Policies[0]
	denyPolicy.ID = "demo-deny"
	denyPolicy.Name = "Demo deny"
	denyPolicy.ServiceID = denyService.ID
	denyPolicy.Action = "deny"
	p.NetworkIntent.Services = append(p.NetworkIntent.Services, denyService)
	p.NetworkIntent.Policies = append([]NetworkPolicy{denyPolicy}, p.NetworkIntent.Policies...)
	p.DeviceAuthorizations[0].PolicyIDs = append([]string{denyPolicy.ID}, p.DeviceAuthorizations[0].PolicyIDs...)
	view, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(view.RuntimeProfile.Config), &document); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range view.Routes {
		blocked, allowed := false, false
		for _, rule := range document.Route.Rules {
			children, ok := rule["rules"].([]any)
			if !ok || len(children) != 2 {
				continue
			}
			scope, _ := children[0].(map[string]any)
			users, _ := scope["auth_user"].([]any)
			inbound, _ := scope["inbound"].([]any)
			if len(users) != 1 || users[0] != candidate.ID || len(inbound) != 1 || inbound[0] != LinkProbeInbound {
				continue
			}
			matcher, _ := children[1].(map[string]any)
			if rule["outbound"] == "reject" {
				parts, _ := matcher["rules"].([]any)
				if len(parts) != 1 {
					continue
				}
				part, _ := parts[0].(map[string]any)
				domains, _ := part["domain_suffix"].([]any)
				if len(domains) == 1 && domains[0] == "private.example" {
					blocked = true
				}
			}
			if rule["outbound"] == candidate.ID {
				if !blocked {
					t.Fatal("candidate permission precedes deny exclusion")
				}
				allowed = true
			}
		}
		if !blocked || !allowed {
			t.Fatal("local candidate credential bypassed Service denial", candidate.ID)
		}
	}
}
