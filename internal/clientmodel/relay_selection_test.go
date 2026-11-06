package clientmodel

import (
	"loom/internal/control"
	"strings"
	"testing"
	"time"
)

func TestRemoteRelayFailureLowersPreferenceAndBusinessCannotProveItsSuffix(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	ref := LinkSampleRef{LinkID: "demo-link", DeviceID: "demo-entry", ResourceID: "demo-exit-wg", SpecDigest: "sha256:" + strings.Repeat("a", 64), Target: "[fdab::1]:53", Action: "wireguard_echo"}
	routes := []RouteCandidate{{ID: "demo-relay", Scope: "service:demo-service", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}, RelayLinks: []LinkSampleRef{ref}, PolicyID: "demo-policy"}, {ID: "demo-direct", Scope: "service:demo-service", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, PolicyID: "demo-policy"}}
	sample := control.DeviceLinkObservation{DeviceID: ref.DeviceID, ReportSequence: 1, ReportDigest: "sha256:" + strings.Repeat("b", 64), CurrentUntil: at.Add(30 * time.Second).UnixMilli(), Observation: control.Observation{Level: "link", ResourceID: ref.ResourceID, LinkID: ref.LinkID, SpecDigest: ref.SpecDigest, Target: ref.Target, Action: ref.Action, NetworkGeneration: "demo-remote-generation", Result: "unavailable", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(30 * time.Second).UnixMilli()}}
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	targets := []string{"https://demo.example/a", "https://demo.example/b"}
	selectRoute := func(samples []Observation, remote control.DeviceLinkObservation, now time.Time) string {
		t.Helper()
		v, err := SelectWithLinks(routes, samples, nil, []control.DeviceLinkObservation{remote}, pref, routes[0].ID, "demo-local-generation", now, targets...)
		if err != nil {
			t.Fatal(err)
		}
		return v.CandidateID
	}
	if got := selectRoute(nil, sample, at); got != "demo-direct" {
		t.Fatal("remote failure ignored", got)
	}
	for _, change := range []func(*control.DeviceLinkObservation){func(v *control.DeviceLinkObservation) { v.DeviceID = "demo-other" }, func(v *control.DeviceLinkObservation) { v.Observation.SpecDigest = "sha256:" + strings.Repeat("c", 64) }} {
		v := sample
		change(&v)
		if got := selectRoute(nil, v, at); got != "demo-relay" {
			t.Fatal("unrelated source/spec excluded path", got)
		}
	}
	if _, err := SelectWithLinks(routes[:1], nil, nil, []control.DeviceLinkObservation{sample}, pref, routes[0].ID, "demo-local-generation", at.Add(30*time.Second), targets...); err != nil {
		t.Fatal("expired remote failure still excluded path", err)
	}
	good := []Observation{}
	for _, target := range targets {
		good = append(good, Observation{CandidateID: routes[0].ID, Scope: control.AccessSelectorScope, Target: target, NetworkGeneration: "demo-local-generation", Result: "available", Action: "https_request", ObservedAt: at.Add(time.Second).Format(time.RFC3339), ValidUntil: at.Add(time.Minute).Format(time.RFC3339)})
	}
	if got := selectRoute(good[:1], sample, at.Add(2*time.Second)); got != "demo-direct" {
		t.Fatal("business success erased a remote link it need not have traversed", got)
	}
	if got := selectRoute(good, sample, at.Add(2*time.Second)); got != "demo-direct" {
		t.Fatal("additional URLs invented proof of an independently chosen suffix", got)
	}
	sample.Observation.Result = "available"
	if got := selectRoute(nil, sample, at); got != "demo-relay" {
		t.Fatal(got)
	}
	if state, _ := ObservationState(nil, "demo-relay", routes[0].Scope, "demo-local-generation", targets, at); state != "unknown" {
		t.Fatal("relay success invented business", state)
	}
}
