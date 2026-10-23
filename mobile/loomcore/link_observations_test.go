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
	ref := clientmodel.LinkSampleRef{LinkID: "demo-link", DeviceID: "demo-relay", ResourceID: "demo-resource", SpecDigest: "sha256:" + strings.Repeat("1", 64), Target: "[fdab::53]:53", Action: "wireguard_dns"}
	routes := []clientmodel.RouteCandidate{{ID: "demo-relayed", FinalExit: "demo-exit", Chain: []string{"demo-relay", "demo-exit"}, Scope: "service:demo-service", RelayLinks: []clientmodel.LinkSampleRef{ref}, PolicyID: "demo-policy"},
		{ID: "demo-direct-exit", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "service:demo-service", PolicyID: "demo-policy"}}
	routesBody, _ := json.Marshal(routes)
	current, _ := json.Marshal(map[string]string{"service:demo-service": "demo-relayed"})
	preference, _ := testPolicyPreference()
	sample := control.DeviceLinkObservation{DeviceID: ref.DeviceID, ReportSequence: 1, ReportDigest: "sha256:" + strings.Repeat("2", 64), CurrentUntil: at.Add(30 * time.Second).UnixMilli(),
		Observation: control.Observation{Level: "link", LinkID: ref.LinkID, ResourceID: ref.ResourceID, SpecDigest: ref.SpecDigest, Target: ref.Target, Action: ref.Action,
			NetworkGeneration: "demo-remote-underlay", Result: "unavailable", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli(), DurationMS: new(int64(3000))}}
	for _, test := range []struct {
		after    time.Duration
		expected string
	}{{time.Second, "demo-direct-exit"}, {30 * time.Second, "demo-direct-exit"}} {
		body, _ := json.Marshal([]control.DeviceLinkObservation{sample})
		value, err := EvaluateAndroidRoutes(routesBody, nil, preference, current, "demo-local-underlay", at.Add(test.after).Format(time.RFC3339), nil, nil, body, nil)
		var application runtimeApplication
		if err != nil || json.Unmarshal(value, &application) != nil || len(application.Selections) != 1 || application.Selections[0].Candidate != test.expected || application.Selections[0].State != "unknown" {
			t.Fatalf("remote relay state or expiry did not control the Android selector without inventing Service health: %s, %v", value, err)
		}
	}
	onlyRelay, _ := json.Marshal(routes[:1])
	body, _ := json.Marshal([]control.DeviceLinkObservation{sample})
	for _, test := range []struct {
		after   time.Duration
		blocked bool
	}{{time.Second, true}, {30 * time.Second, false}} {
		value, err := EvaluateAndroidRoutes(onlyRelay, nil, preference, current, "demo-local-underlay", at.Add(test.after).Format(time.RFC3339), nil, nil, body, nil)
		var application runtimeApplication
		if err != nil || json.Unmarshal(value, &application) != nil || (len(application.BlockedScopes) == 1) != test.blocked {
			t.Fatal("Android extended the remote failure past its authenticated deadline", string(value), err)
		}
	}
	sample.Observation.SpecDigest = "sha256:" + strings.Repeat("3", 64)
	body, _ = json.Marshal([]control.DeviceLinkObservation{sample})
	value, err := EvaluateAndroidRoutes(routesBody, nil, preference, current, "demo-local-underlay", at.Add(time.Second).Format(time.RFC3339), nil, nil, body, nil)
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
	if _, err := FetchAndroidLinkObservations(freshBody); err == nil {
		t.Fatal("remote link fetch accepted an unauthenticated identity")
	}
	if _, err := ObserveAndroidAlternateBusiness(freshBody, nil, nil, nil, "demo-generation", nil, nil); err == nil {
		t.Fatal("alternate probe accepted an unauthenticated identity")
	}
}
