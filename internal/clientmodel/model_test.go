package clientmodel

import (
	"reflect"
	"testing"
	"time"
)

func TestSelectAvailabilityGenerationAndSameExitFallback(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	routes := []RouteCandidate{
		{ID: "direct", FinalExit: "direct", Scope: "service"},
		{ID: "one-hop", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "service"},
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}, Scope: "service"},
	}
	observations := []Observation{
		{CandidateID: "one-hop", NetworkGeneration: "network-a", Scope: "business", Result: "unavailable", Action: "https",
			ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)},
		{CandidateID: "relay", NetworkGeneration: "old-network", Scope: "business", Result: "unavailable", Action: "https",
			ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)},
	}
	selected, err := Select(routes, observations, Preference{Schema: 1, Mode: ModeFixed, Exit: "demo-exit"},
		"one-hop", "network-a", now)
	if err != nil || selected.CandidateID != "relay" {
		t.Fatalf("same-exit fallback = %+v, %v", selected, err)
	}
	selected, err = Select(routes, observations, Preference{Schema: 1, Mode: ModeDirect}, "", "network-a", now)
	if err != nil || selected.CandidateID != "direct" {
		t.Fatalf("direct = %+v, %v", selected, err)
	}
}

func TestRuntimeProfileRequiresExactRouteMapping(t *testing.T) {
	raw := `{"inbounds":[{"type":"tun","tag":"tun-in","auto_route":true}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"service","outbounds":["direct","relay"]},{"type":"hysteria2","tag":"relay"}],"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-secret"}}}`
	config, err := CanonicalizeRuntimeConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	routes := []RouteCandidate{{ID: "direct", FinalExit: "direct", Scope: "service"},
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}, Scope: "service"}}
	if err := (RuntimeProfile{Kind: "sing_box", Config: config}).Validate(routes); err != nil {
		t.Fatal(err)
	}
	bad := raw[:len(raw)-2] + `,"extra"]}}`
	if canonical, err := CanonicalizeRuntimeConfig([]byte(bad)); err == nil &&
		(RuntimeProfile{Kind: "sing_box", Config: canonical}).Validate(routes) == nil {
		t.Fatal("unauthorized selector member accepted")
	}
}

func TestRuntimeCandidatesArePureStableProjection(t *testing.T) {
	raw := `{"inbounds":[{"type":"tun","tag":"tun-in","auto_route":true}],"outbounds":[{"type":"selector","tag":"service","outbounds":["relay","direct"]},{"type":"hysteria2","tag":"relay"},{"type":"direct","tag":"direct"}],"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-secret"}}}`
	config, err := CanonicalizeRuntimeConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	profile := RuntimeProfile{Kind: "sing_box", Config: config}
	routes := []RouteCandidate{
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}, Scope: "service"},
		{ID: "direct", FinalExit: "direct", Scope: "service"},
	}
	want := []RuntimeCandidate{
		{ID: "direct", FinalExit: "direct", Scope: "service", Transport: "direct"},
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}, Scope: "service", Transport: "hysteria2"},
	}
	first, err := ProjectRuntimeCandidates(routes, profile)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ProjectRuntimeCandidates([]RouteCandidate{routes[1], routes[0]}, profile)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, want) || !reflect.DeepEqual(second, want) {
		t.Fatalf("runtime projection is not stable:\nfirst=%+v\nsecond=%+v", first, second)
	}
}
