package clientmodel

import (
	"reflect"
	"testing"
	"time"

	"loom/internal/control"
)

func routingEvidenceFixture() (time.Time, []RouteCandidate, []control.Observation, func(string, string, string, int64) control.DeviceLinkObservation) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	routes := []RouteCandidate{}
	samples := []control.Observation{}
	for i, exit := range []string{"demo-fast", "demo-covered"} {
		id := "demo-entry-" + exit
		spec := control.ReleaseDigest([]byte(id))
		rtt := int64(10 + i*30)
		routes = append(routes, RouteCandidate{ID: "demo-path-" + exit, PolicyID: "demo-policy", SourceNode: "demo-access", Scope: "service:demo-service", FinalExit: exit, Chain: []string{exit},
			FirstHop: &ResourceSampleRef{ResourceID: id, SpecDigest: spec, Target: "192.0.2.1:51820", Action: "wireguard_echo"}})
		samples = append(samples, control.Observation{Level: "resource", ResourceID: id, SpecDigest: spec, Target: "192.0.2.1:51820", Action: "wireguard_echo", NetworkGeneration: "demo-local", Result: "available", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli(), RoundTripMS: new(rtt), DurationMS: new(rtt + 1)})
	}
	egress := func(exit, target, result string, delta int64) control.DeviceLinkObservation {
		sample := control.Observation{Level: "egress", Target: target, Action: "https_request", SpecDigest: control.ReleaseDigest([]byte("demo-egress-" + exit + target)), NetworkGeneration: "demo-remote-" + exit,
			Result: result, ObservedAt: at.UnixMilli() + delta, ValidUntil: at.Add(time.Minute).UnixMilli() + delta, DurationMS: new(int64(80))}
		return control.DeviceLinkObservation{DeviceID: exit, ReportSequence: 1, ReportDigest: control.ReleaseDigest([]byte("demo-original")), CurrentUntil: sample.ValidUntil, Observation: sample}
	}
	return at, routes, samples, egress
}

func TestRoutingDefaultUsesSharedCoverageThenSegmentsAndTargetsKeepTheirOwnExit(t *testing.T) {
	at, routes, resources, egress := routingEvidenceFixture()
	a, b := "https://demo-a.example/health", "https://demo-b.example/health"
	shared := []control.DeviceLinkObservation{egress("demo-fast", a, "available", 0), egress("demo-fast", b, "unavailable", 0), egress("demo-covered", a, "available", 0), egress("demo-covered", b, "available", 0)}
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	selection, err := SelectWithLinks(routes, nil, resources, shared, pref, "", "demo-local", at.Add(time.Second), a, b)
	if err != nil || selection.CandidateID != routes[1].ID || selection.Targets["tcp://demo-a.example:443"] != routes[0].ID || len(selection.Targets) != 1 {
		t.Fatal("shared coverage or target-specific selection was lost", selection, err)
	}
	// Map iteration and the order of equivalent inputs cannot alter the result.
	for range 12 {
		got, err := SelectWithLinks([]RouteCandidate{routes[1], routes[0]}, nil, resources, shared, pref, "", "demo-local", at.Add(time.Second), b, a)
		if err != nil || !reflect.DeepEqual(got, selection) {
			t.Fatal("routing was not a deterministic projection", got, err)
		}
	}
	// No measurements for C: there is no target override, so C uses the default.
	if _, exists := selection.Targets["tcp://demo-c.example:443"]; exists {
		t.Fatal("unmeasured target acquired an invented route")
	}
}

func TestFixedExitIgnoresEveryWebsiteOutcomeAndUsesMeasuredTransport(t *testing.T) {
	at, routes, resources, egress := routingEvidenceFixture()
	for i := range routes {
		routes[i].FinalExit = "demo-fixed"
		routes[i].Chain = []string{"demo-fixed"}
		routes[i].FixedExit = true
	}
	target := "https://demo-service.example/health"
	local := []Observation{{CandidateID: routes[0].ID, Scope: "access", Target: target, NetworkGeneration: "demo-local", Action: "https_request", Result: "unavailable", ObservedAt: at.Format(time.RFC3339), ValidUntil: at.Add(time.Minute).Format(time.RFC3339)}}
	for _, result := range []string{"available", "unavailable", "unknown"} {
		selection, err := SelectWithLinks(routes, local, resources, []control.DeviceLinkObservation{egress("demo-fixed", target, result, 0)}, Preference{Schema: 3, PolicyID: "demo-policy"}, routes[1].ID, "demo-local", at.Add(time.Second), target)
		if err != nil || selection.CandidateID != routes[0].ID || len(selection.Targets) != 0 {
			t.Fatal("fixed exit ranked a URL or ignored transport latency", selection, err)
		}
	}
}

func TestRoutingUnknownSamplesRemainExplorableAndNeverBecomeZeroCost(t *testing.T) {
	at, routes, resources, egress := routingEvidenceFixture()
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	target := "https://demo-service.example/health"
	// One measured slower segment outranks a missing segment; unknown is not 0ms.
	selection, err := SelectWithLinks(routes, nil, resources[1:], nil, pref, "", "demo-local", at.Add(time.Second), target)
	if err != nil || selection.CandidateID != routes[1].ID {
		t.Fatal("missing RTT became a zero-cost path", selection, err)
	}
	selection, err = SelectWithLinks(routes, nil, nil, nil, pref, "", "demo-local", at.Add(time.Second), target)
	if err != nil || selection.CandidateID == "" {
		t.Fatal("no samples prevented initial Internet access", selection, err)
	}
	// A failed website never disqualifies the only authorized transport path.
	selection, err = SelectWithLinks(routes[:1], nil, resources[:1], []control.DeviceLinkObservation{egress("demo-fast", target, "unavailable", 0)}, pref, "", "demo-local", at.Add(time.Second), target)
	if err != nil || selection.CandidateID != routes[0].ID {
		t.Fatal("one website failure blocked ordinary Internet", selection, err)
	}
	// Expiry discards the metric, not the candidate or the current connection.
	selection, err = SelectWithLinks(routes, nil, resources, nil, pref, routes[1].ID, "demo-local", at.Add(time.Minute), target)
	if err != nil || selection.CandidateID != routes[1].ID {
		t.Fatal("expiry was treated as a connection failure", selection, err)
	}
}

func TestRoutingCoverageCountsConnectionTargetsAndDoesNotBorrowAnotherPolicy(t *testing.T) {
	at, routes, resources, egress := routingEvidenceFixture()
	resources[0].RoundTripMS = new(int64(60))
	resources[0].DurationMS = new(int64(61))
	a1, a2, b := "https://demo-a.example/one", "https://demo-a.example/two", "https://demo-b.example/health"
	shared := []control.DeviceLinkObservation{egress("demo-fast", a1, "available", 0), egress("demo-fast", a2, "available", 0), egress("demo-covered", b, "available", 0)}
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	selection, err := SelectWithLinks(routes, nil, resources, shared, pref, "", "demo-local", at.Add(time.Second), a1, a2, b)
	if err != nil || selection.CandidateID != routes[1].ID {
		t.Fatal("two URLs of one target received duplicate coverage weight", selection, err)
	}
	other := routes[0]
	other.ID = "demo-other-policy"
	other.PolicyID = "demo-unselected"
	business := Observation{CandidateID: other.ID, Scope: "access", Target: "https://demo-unrelated.example/", Action: "https_request", NetworkGeneration: "demo-local", Result: "available", ObservedAt: at.Format(time.RFC3339), ValidUntil: at.Add(time.Minute).Format(time.RFC3339)}
	withOther, err := SelectWithLinks(append(routes, other), []Observation{business}, resources, shared, pref, "", "demo-local", at.Add(time.Second), a1, a2, b)
	if err != nil || !reflect.DeepEqual(selection, withOther) {
		t.Fatal("unselected Policy influenced an ordinary target", withOther, err)
	}
}

func TestHybridConsumesOwnEgressSamplesWithoutBorrowingAnotherNetworkGeneration(t *testing.T) {
	at, routes, resources, egress := routingEvidenceFixture()
	target := "https://demo-service.example/health"
	other := "https://demo-other.example/health"
	shared := []control.DeviceLinkObservation{egress("demo-fast", other, "available", 0)}
	for i := range routes {
		routes[i].SourceNode = "demo-covered"
	}
	local := egress("demo-covered", target, "available", 0).Observation
	local.NetworkGeneration = "demo-local"
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	selection, err := SelectWithLinks(routes, nil, append(resources, local), shared, pref, "", "demo-local", at.Add(time.Second), target, other)
	if err != nil || selection.CandidateID != routes[1].ID {
		t.Fatal("hybrid waited for its own report round trip", selection, err)
	}
	local.NetworkGeneration = "demo-before-switch"
	selection, err = SelectWithLinks(routes, nil, append(resources, local), shared, pref, "", "demo-local", at.Add(time.Second), target, other)
	if err != nil || selection.CandidateID != routes[0].ID {
		t.Fatal("hybrid reused an exit result from the previous network", selection, err)
	}
}

func TestFixedExitInputCannotDescribeTwoDifferentExits(t *testing.T) {
	at, routes, resources, _ := routingEvidenceFixture()
	for i := range routes {
		routes[i].FixedExit = true
	}
	_, err := SelectWithLinks(routes, nil, resources, nil, Preference{Schema: 3, PolicyID: "demo-policy"}, "", "demo-local", at, "https://demo-service.example/")
	if err == nil {
		t.Fatal("inconsistent fixed exit constraints were accepted")
	}
}
