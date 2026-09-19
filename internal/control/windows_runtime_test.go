package control

import (
	"strings"
	"testing"

	"loom/internal/clientmodel"
)

func TestWindowsEnrollmentRequiresStrictCompleteRuntimeProfile(t *testing.T) {
	routes := []RouteCandidate{
		{ID: "one-hop", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "internet"},
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-relay", "demo-exit"}, Scope: "internet"},
	}
	raw := `{"inbounds":[{"type":"tun","tag":"tun-in","auto_route":true}],"outbounds":[{"type":"hysteria2","tag":"one-hop"},{"type":"hysteria2","tag":"relay"},{"type":"selector","tag":"internet","outbounds":["one-hop","relay"]}],"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-secret"}}}`
	canonical, err := clientmodel.CanonicalizeRuntimeConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	base := EnrollmentIntent{DeviceID: "demo-windows", Name: "Demo Windows", Platform: "windows",
		Roles: []string{"access"}, Routes: routes}
	if err := base.Validate(); err == nil {
		t.Fatal("Windows enrollment accepted a missing runtime profile")
	}
	base.Runtime = &RuntimeProfile{Kind: "sing_box", Config: canonical}
	if err := base.Validate(); err != nil {
		t.Fatalf("canonical Windows runtime rejected: %v", err)
	}
	nonCanonical := base
	nonCanonical.Runtime = &RuntimeProfile{Kind: "sing_box", Config: raw + "\n"}
	if err := nonCanonical.Validate(); err == nil {
		t.Fatal("Windows enrollment accepted non-canonical runtime JSON")
	}
	unauthorized := strings.Replace(raw, `"one-hop","relay"`, `"one-hop","relay","extra"`, 1)
	unauthorizedConfig, err := clientmodel.CanonicalizeRuntimeConfig([]byte(unauthorized))
	if err != nil {
		t.Fatal(err)
	}
	base.Runtime = &RuntimeProfile{Kind: "sing_box", Config: unauthorizedConfig}
	if err := base.Validate(); err == nil {
		t.Fatal("Windows enrollment accepted an unauthorized selector member")
	}
}
