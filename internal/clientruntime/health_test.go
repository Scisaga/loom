package clientruntime

import (
	"encoding/json"
	"strings"
	"testing"
)

func healthConfig(t *testing.T, profile WindowsRuntimeProfile, domains, suffixes []string) []byte {
	t.Helper()
	source := strings.NewReplacer("${secret:vault:cred/win01}", "fixture-password", "${secret:api/win01}", "fixture-api").Replace(validWindowsConfig("warn"))
	var config singBoxConfig
	if err := json.Unmarshal([]byte(source), &config); err != nil {
		t.Fatal(err)
	}
	config.Outbounds = append(config.Outbounds, singBoxOutbound{Type: "selector", Tag: "svc:demo-service", Outbounds: []string{"cand:auto:edge"}, Default: "cand:auto:edge"})
	config.Route.Rules = append([]singBoxRule{{Inbound: []string{"tun-in", "in-1080"}, Domain: domains, DomainSuffix: suffixes, Outbound: "svc:demo-service"}}, config.Route.Rules...)
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := DeriveWindowsRuntimeConfig(body, profile, WindowsInstalledCAPath)
	if err != nil {
		t.Fatal(err)
	}
	return derived
}

// §16.1：没有业务目标也能检查本机状态；不再派生需要主动访问的地址。
func TestWindowsHealthPlanDoesNotRequireBusinessTargets(t *testing.T) {
	for _, profile := range []WindowsRuntimeProfile{WindowsInstalledProfile, WindowsPortableMixedProfile, WindowsPortableTUNProfile} {
		for _, domains := range [][]string{nil, {"demo.example"}} {
			body := healthConfig(t, profile, domains, nil)
			plan, err := BuildWindowsHealthPlan(body, profile, WindowsInstalledCAPath)
			if err != nil || plan.profile != profile {
				t.Fatalf("plan=%+v err=%v", plan, err)
			}
		}
	}
}
