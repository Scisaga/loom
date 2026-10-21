package clientmodel

import (
	"encoding/json"
	"loom/internal/control"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLocalNetworkSelectedPolicyRetainsGateway(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	routes := []RouteCandidate{
		{ID: "demo-one-hop", FinalExit: "demo-gateway", Chain: []string{"demo-gateway"}, Scope: "local_network:demo-lan", PolicyID: "demo-policy"},
		{ID: "demo-relay", FinalExit: "demo-gateway", Chain: []string{"demo-entry", "demo-gateway"}, Scope: "local_network:demo-lan", PolicyID: "demo-policy"},
	}
	failed := Observation{CandidateID: routes[0].ID, NetworkGeneration: "demo-network-generation", Scope: "local_network:demo-lan", Result: "unavailable", Action: "https_request", ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)}
	preference := Preference{Schema: 3, Services: []ServicePreference{{ServiceID: "demo-lan", PolicyID: "demo-policy"}}}
	selection, err := Select(routes, []Observation{failed}, nil, preference, routes[0].ID, failed.NetworkGeneration, now, "")
	if err != nil || selection.CandidateID != "demo-relay" {
		t.Fatal("LAN selected policy lost its alternate gateway path", err)
	}
	routes[0].FinalExit, routes[0].Chain = "direct", nil
	if _, err := Select(routes, nil, nil, Preference{Schema: 3, Services: []ServicePreference{{ServiceID: "demo-lan", PolicyID: "demo-policy"}, {ServiceID: "demo-service", PolicyID: "demo-policy"}}}, "", failed.NetworkGeneration, now, ""); err == nil {
		t.Fatal("LAN candidate escaped through Direct")
	}
}

func TestSelectAvailabilityGenerationAndSameExitFallback(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	routes := []RouteCandidate{
		{ID: "direct", FinalExit: "direct", Scope: "service:demo-service", PolicyID: "demo-direct-policy"},
		{ID: "one-hop", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "service:demo-service", PolicyID: "demo-policy"},
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}, Scope: "service:demo-service", PolicyID: "demo-policy"},
	}
	observations := []Observation{
		{CandidateID: "one-hop", NetworkGeneration: "network-a", Scope: "service:demo-service", Result: "unavailable", Action: "https",
			ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)},
		{CandidateID: "relay", NetworkGeneration: "old-network", Scope: "service:demo-service", Result: "unavailable", Action: "https",
			ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)},
	}
	selected, err := Select(routes, observations, nil, Preference{Schema: 3, Services: []ServicePreference{{ServiceID: "demo-lan", PolicyID: "demo-policy"}, {ServiceID: "demo-service", PolicyID: "demo-policy"}}},
		"one-hop", "network-a", now, "")
	if err != nil || selected.CandidateID != "relay" {
		t.Fatalf("same-exit fallback = %+v, %v", selected, err)
	}
	selected, err = Select(routes, observations, nil, Preference{Schema: 3, Services: []ServicePreference{{ServiceID: "demo-lan", PolicyID: "demo-direct-policy"}, {ServiceID: "demo-service", PolicyID: "demo-direct-policy"}}}, "", "network-a", now, "")
	if err != nil || selected.CandidateID != "direct" {
		t.Fatalf("direct = %+v, %v", selected, err)
	}
}

func TestExpiredFailuresDoNotStarveOtherAuthorizedPaths(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	routes := []RouteCandidate{
		{ID: "demo-a", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "service:demo-service", PolicyID: "demo-policy"},
		{ID: "demo-b", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}, Scope: "service:demo-service", PolicyID: "demo-policy"},
		{ID: "demo-c", FinalExit: "demo-exit", Chain: []string{"demo-other", "demo-exit"}, Scope: "service:demo-service", PolicyID: "demo-policy"},
		{ID: "demo-0", FinalExit: "direct", Scope: "service:demo-service", PolicyID: "demo-direct-policy"},
	}
	failed := func(id string, at time.Time) Observation {
		return Observation{CandidateID: id, NetworkGeneration: "demo-network", Scope: routes[0].Scope,
			Result: "unavailable", Action: "https_request", ObservedAt: at.Format(time.RFC3339), ValidUntil: at.Add(30 * time.Second).Format(time.RFC3339)}
	}
	observations := []Observation{failed("demo-a", now.Add(-time.Minute)), failed("demo-b", now.Add(-2*time.Minute))}
	preference := Preference{Schema: 3, Services: []ServicePreference{{ServiceID: "demo-lan", PolicyID: "demo-policy"}, {ServiceID: "demo-service", PolicyID: "demo-policy"}}}
	selectID := func(current, generation string) string {
		t.Helper()
		selection, err := Select(routes, observations, nil, preference, current, generation, now, "")
		if err != nil {
			t.Fatal(err)
		}
		return selection.CandidateID
	}
	if got := selectID("demo-a", "demo-network"); got != "demo-c" {
		t.Fatal("expired failure hid the untried same-exit path", got)
	}
	observations = append(observations, failed("demo-c", now.Add(-40*time.Second)))
	if got := selectID("demo-a", "demo-network"); got != "demo-b" {
		t.Fatal("all expired failures did not retry the oldest attempt", got)
	}
	if got := selectID("", "demo-new-network"); got != "demo-a" {
		t.Fatal("old network attempt order affected a new network", got)
	}
	observations[0] = failed("demo-a", now)
	observations[1].Result, observations[1].ValidUntil = "available", now.Add(time.Minute).Format(time.RFC3339)
	if got := selectID("demo-c", "demo-network"); got != "demo-b" {
		t.Fatal("fresh failure or expired retry displaced valid availability", got)
	}
	observations = observations[1:2]
	observations[0].ValidUntil = now.Add(-time.Second).Format(time.RFC3339)
	if got := selectID("demo-b", "demo-network"); got != "demo-b" {
		t.Fatal("previous success was displaced without comparable evidence", got)
	}
}

func TestLocalExitIsNotDirectAndKeepsItsRuntimeIdentity(t *testing.T) {
	local := RouteCandidate{ID: "demo-local", PolicyID: "demo-policy", FinalExit: "demo-hybrid", Chain: []string{}, Scope: "service:demo-service"}
	config, err := canonicalRuntimeFixture([]byte(`{"outbounds":[{"type":"direct","tag":"demo-local"},{"type":"selector","tag":"service:demo-service","outbounds":["demo-local"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := ProjectRuntimeCandidates([]RouteCandidate{local}, RuntimeProfile{Kind: "sing_box", Config: config})
	if err != nil || len(runtime) != 1 || runtime[0].FinalExit != local.FinalExit || runtime[0].ID != local.ID || len(runtime[0].Chain) != 0 || runtime[0].Transport != "direct" {
		t.Fatalf("local runtime projection: %+v, %v", runtime, err)
	}
}

func TestRuntimeProfileRequiresExactRouteMapping(t *testing.T) {
	raw := `{"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"service:demo-service","outbounds":["direct","relay"]},{"type":"hysteria2","tag":"relay"}]}`
	config, err := canonicalRuntimeFixture([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	routes := []RouteCandidate{{ID: "direct", FinalExit: "direct", Scope: "service:demo-service", PolicyID: "demo-policy"},
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}, Scope: "service:demo-service", PolicyID: "demo-policy"}}
	if err := (RuntimeProfile{Kind: "sing_box", Config: config}).Validate(routes); err != nil {
		t.Fatal(err)
	}
	bad := raw[:len(raw)-2] + `,"extra"]}}`
	if canonical, err := canonicalRuntimeFixture([]byte(bad)); err == nil &&
		(RuntimeProfile{Kind: "sing_box", Config: canonical}).Validate(routes) == nil {
		t.Fatal("unauthorized selector member accepted")
	}
}

func TestRuntimeCandidatesArePureStableProjection(t *testing.T) {
	raw := `{"outbounds":[{"type":"selector","tag":"service:demo-service","outbounds":["relay","direct"]},{"type":"hysteria2","tag":"relay"},{"type":"direct","tag":"direct"}]}`
	config, err := canonicalRuntimeFixture([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	profile := RuntimeProfile{Kind: "sing_box", Config: config}
	routes := []RouteCandidate{
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}, Scope: "service:demo-service", PolicyID: "demo-policy"},
		{ID: "direct", FinalExit: "direct", Scope: "service:demo-service", PolicyID: "demo-policy"},
	}
	want := []RuntimeCandidate{
		{ID: "direct", PolicyID: "demo-policy", FinalExit: "direct", Scope: "service:demo-service", Transport: "direct"},
		{ID: "relay", PolicyID: "demo-policy", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}, Scope: "service:demo-service", Transport: "hysteria2"},
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

// Test fixtures use the contract renderer; production validates the original
// authenticated bytes without any alternate JSON canonicalization.
func canonicalRuntimeFixture(body []byte) (string, error) {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return "", err
	}
	document := value.(map[string]any)
	if raw, ok := document["outbounds"].([]any); ok {
		hasReject := false
		for _, item := range raw {
			outbound := item.(map[string]any)
			if outbound["tag"] == "reject" {
				hasReject = true
			}
			if outbound["type"] == "selector" {
				outbound["default"] = "reject"
				members, _ := outbound["outbounds"].([]any)
				outbound["outbounds"] = append([]any{"reject"}, members...)
			}
		}
		if !hasReject {
			document["outbounds"] = append(raw, map[string]any{"type": "block", "tag": "reject"})
		}
	}
	result, err := control.CanonicalEncode(value)
	return string(result), err
}
func TestRuntimeProfileUsesContractEscapingForCertificates(t *testing.T) {
	config, err := canonicalRuntimeFixture([]byte(`{"outbounds":[{"type":"hysteria2","tag":"demo-hop","tls":{"certificate":["demo\ncertificate\n"]}},{"type":"selector","tag":"service:demo-service","outbounds":["demo-hop"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	routes := []RouteCandidate{{ID: "demo-hop", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "service:demo-service", PolicyID: "demo-policy"}}
	if err := (RuntimeProfile{Kind: "sing_box", Config: config}).Validate(routes); err != nil {
		t.Fatal(err)
	}
	alternative := strings.ReplaceAll(config, `\u000a`, `\n`)
	if alternative == config || (RuntimeProfile{Kind: "sing_box", Config: alternative}).Validate(routes) == nil {
		t.Fatal("accepted a second certificate string encoding")
	}
}
