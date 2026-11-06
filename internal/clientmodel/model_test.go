package clientmodel

import (
	"encoding/json"
	"loom/internal/control"
	"reflect"
	"strings"
	"testing"
)

func TestLocalNetworkSelectedPolicyRetainsGateway(t *testing.T) {
	routes, samples, at := firstHopSelectionFixture()
	for i := range routes {
		routes[i].Scope = "local_network:demo-lan"
		routes[i].FinalExit = "demo-gateway"
		routes[i].Chain = []string{"demo-gateway"}
		routes[i].FixedExit = true
	}
	samples[0].Result = "unavailable"
	choice, err := Select(routes, nil, samples, Preference{Schema: 3, PolicyID: "demo-policy"}, routes[0].ID, "demo-network", at)
	if err != nil || choice.CandidateID != routes[1].ID {
		t.Fatal("LAN failed its authorized alternate gateway path", choice, err)
	}
	routes[0].FinalExit, routes[0].Chain = "direct", nil
	if _, err := Select(routes, nil, nil, Preference{Schema: 3, PolicyID: "demo-policy"}, "", "demo-network", at); err == nil {
		t.Fatal("LAN escaped through Direct")
	}
}

func TestLocalExitIsNotDirectAndKeepsItsRuntimeIdentity(t *testing.T) {
	local := RouteCandidate{ID: "demo-local", Transport: "direct", PolicyID: "demo-policy", FinalExit: "demo-hybrid", Chain: []string{}, Scope: "service:demo-service"}
	config, err := canonicalRuntimeFixture([]byte(`{"outbounds":[{"type":"direct","tag":"demo-local"},{"type":"selector","tag":"access","outbounds":["demo-local"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := ProjectRuntimeCandidates([]RouteCandidate{local}, RuntimeProfile{Kind: "sing_box", Config: config})
	if err != nil || len(runtime) != 1 || runtime[0].FinalExit != local.FinalExit || runtime[0].ID != local.ID || len(runtime[0].Chain) != 0 || runtime[0].Transport != "direct" {
		t.Fatalf("local runtime projection: %+v, %v", runtime, err)
	}
}

func TestRuntimeProfileRequiresExactRouteMapping(t *testing.T) {
	raw := `{"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"access","outbounds":["direct","relay"]},{"type":"hysteria2","tag":"relay"}]}`
	config, err := canonicalRuntimeFixture([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	routes := []RouteCandidate{{ID: "direct", Transport: "direct", FinalExit: "direct", Scope: "service:demo-service", PolicyID: "demo-policy"},
		{ID: "relay", Transport: "hysteria2", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}, Scope: "service:demo-service", PolicyID: "demo-policy"}}
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
	raw := `{"outbounds":[{"type":"selector","tag":"access","outbounds":["relay","direct"]},{"type":"hysteria2","tag":"relay"},{"type":"direct","tag":"direct"}]}`
	config, err := canonicalRuntimeFixture([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	profile := RuntimeProfile{Kind: "sing_box", Config: config}
	routes := []RouteCandidate{
		{ID: "relay", Transport: "hysteria2", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}, Scope: "service:demo-service", PolicyID: "demo-policy"},
		{ID: "direct", Transport: "direct", FinalExit: "direct", Scope: "service:demo-service", PolicyID: "demo-policy"},
	}
	want := []RuntimeCandidate{
		{ID: "direct", Transport: "direct", PolicyID: "demo-policy", FinalExit: "direct", Scope: "service:demo-service"},
		{ID: "relay", Transport: "hysteria2", PolicyID: "demo-policy", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}, Scope: "service:demo-service"},
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
				bindings := map[string]string{}
				for _, member := range members {
					bindings[member.(string)] = "demo-policy"
				}
				outbound["candidate_policies"] = bindings
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
	config, err := canonicalRuntimeFixture([]byte(`{"outbounds":[{"type":"hysteria2","tag":"demo-hop","tls":{"certificate":["demo\ncertificate\n"]}},{"type":"selector","tag":"access","outbounds":["demo-hop"]}]}`))
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
