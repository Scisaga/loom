package loomcore

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

func TestAndroidSelectionConsumesRemoteRelayFailureAndOriginalExpiry(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	ref := clientmodel.LinkSampleRef{LinkID: "demo-link", DeviceID: "demo-relay", ResourceID: "demo-resource", SpecDigest: "sha256:" + strings.Repeat("1", 64), Target: "[fdab::53]:53", Action: "wireguard_echo"}
	routes := []clientmodel.RouteCandidate{{ID: "demo-relayed", FinalExit: "demo-exit", Chain: []string{"demo-relay", "demo-exit"}, Scope: "service:demo-service", RelayLinks: []clientmodel.LinkSampleRef{ref}, PolicyID: "demo-policy"},
		{ID: "demo-direct-exit", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "service:demo-service", PolicyID: "demo-policy"}}
	routesBody, _ := json.Marshal(routes)
	current, _ := json.Marshal(map[string]clientmodel.Selection{"access": {CandidateID: "demo-relayed", Targets: map[string]string{}}})
	preference, _ := testPolicyPreference()
	sample := control.DeviceLinkObservation{DeviceID: ref.DeviceID, ReportSequence: 1, ReportDigest: "sha256:" + strings.Repeat("2", 64), CurrentUntil: at.Add(30 * time.Second).UnixMilli(),
		Observation: control.Observation{Level: "link", LinkID: ref.LinkID, ResourceID: ref.ResourceID, SpecDigest: ref.SpecDigest, Target: ref.Target, Action: ref.Action,
			NetworkGeneration: "demo-remote-underlay", Result: "unavailable", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli(), DurationMS: new(int64(3000))}}
	for _, test := range []struct {
		after    time.Duration
		expected string
	}{{time.Second, "demo-direct-exit"}, {30 * time.Second, "demo-relayed"}} {
		body, _ := json.Marshal([]control.DeviceLinkObservation{sample})
		value, err := evaluateTestRoutes(routesBody, nil, preference, current, "demo-local-underlay", at.Add(test.after).UnixMilli(), nil, nil, body, nil, nil, 0, nil)
		var application runtimeApplication
		if err != nil || json.Unmarshal(value, &application) != nil || len(application.Selections) != 1 || application.Selections[0].Candidate != test.expected || application.Selections[0].State != "unknown" {
			t.Fatalf("remote relay state or expiry did not control the Android selector without inventing Service health: %s, %v", value, err)
		}
	}
	onlyRelay, _ := json.Marshal(routes[:1])
	body, _ := json.Marshal([]control.DeviceLinkObservation{sample})
	for _, after := range []time.Duration{time.Second, 30 * time.Second} {
		value, err := evaluateTestRoutes(onlyRelay, nil, preference, current, "demo-local-underlay", at.Add(after).UnixMilli(), nil, nil, body, nil, nil, 0, nil)
		var application runtimeApplication
		if err != nil || json.Unmarshal(value, &application) != nil || len(application.BlockedScopes) != 0 ||
			len(application.Selections) != 1 || application.Selections[0].Candidate != "demo-relayed" || application.Selections[0].State != "unknown" {
			t.Fatal("remote diagnostic failure or expiry blocked the only qualified attempt or invented Service health", string(value), err)
		}
	}
	sample.Observation.SpecDigest = "sha256:" + strings.Repeat("3", 64)
	body, _ = json.Marshal([]control.DeviceLinkObservation{sample})
	value, err := evaluateTestRoutes(routesBody, nil, preference, current, "demo-local-underlay", at.Add(time.Second).UnixMilli(), nil, nil, body, nil, nil, 0, nil)
	var application runtimeApplication
	if err != nil || json.Unmarshal(value, &application) != nil || application.Selections[0].Candidate != "demo-relayed" {
		t.Fatal("another relay specification displaced the current Android route", string(value), err)
	}
}

func TestAndroidObservationBridgesRequireAcceptedIdentity(t *testing.T) {
	_, body := androidFixture(t, 7, false)
	state, err := decodeState(body)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := base64.RawURLEncoding.DecodeString(state.PrivateKey)
	fresh, err := deviceclient.NewIdentityState(*state.Invite, "android", ed25519.PrivateKey(private), state.ClaimRequestID)
	if err != nil {
		t.Fatal(err)
	}
	freshBody, err := deviceclient.EncodeIdentityState(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAndroidLinkObservationRequest(freshBody, nil); err == nil {
		t.Fatal("remote link fetch accepted an unauthenticated identity")
	}

}
