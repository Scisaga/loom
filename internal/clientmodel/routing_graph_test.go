package clientmodel

import (
	"loom/internal/control"
	"reflect"
	"testing"
	"time"
)

func TestMeasuredGraphChangesRelayEstimateWithoutChangingEntryExitIdentity(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	graph := PolicyGraph{PolicyID: "demo-policy", SourceNode: "demo-access", RelayScope: control.PolicyScope{Mode: "any", NodeIDs: []string{}}, Links: []GraphLink{}}
	samples := []control.DeviceLinkObservation{}
	for _, edge := range []struct {
		id, from, to string
		cost         int64
	}{{"demo-direct", "demo-entry", "demo-exit", 100}, {"demo-middle", "demo-entry", "demo-relay", 10}, {"demo-suffix", "demo-relay", "demo-exit", 10}} {
		spec := control.ReleaseDigest([]byte(edge.id))
		ref := LinkSampleRef{LinkID: edge.id, DeviceID: edge.from, ResourceID: "demo-resource-" + edge.to, SpecDigest: spec, Target: "[fdab::1]:53", Action: "wireguard_echo"}
		graph.Links = append(graph.Links, GraphLink{From: edge.from, To: edge.to, Ref: ref})
		sample := control.Observation{Level: "link", LinkID: edge.id, ResourceID: ref.ResourceID, SpecDigest: spec, Target: ref.Target, Action: ref.Action, NetworkGeneration: "demo-source-generation", Result: "available", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli(), DurationMS: new(edge.cost + 1), RoundTripMS: new(edge.cost)}
		samples = append(samples, control.DeviceLinkObservation{DeviceID: edge.from, ReportSequence: 1, ReportDigest: control.ReleaseDigest([]byte("demo-report-" + edge.id)), CurrentUntil: sample.ValidUntil, Observation: sample})
	}
	route := RouteCandidate{ID: "demo-candidate", PolicyID: "demo-policy", SourceNode: "demo-access", Scope: "service:demo-service", FinalExit: "demo-exit", FixedExit: true, Chain: []string{"demo-entry", "demo-exit"}, RelayLinks: []LinkSampleRef{graph.Links[0].Ref}}
	result, err := EstimateRoutePaths([]RouteCandidate{route}, []PolicyGraph{graph}, nil, samples, "demo-network", at.Add(time.Second))
	if err != nil || len(result) != 1 {
		t.Fatal(err)
	}
	if result[0].ID != route.ID || !reflect.DeepEqual(result[0].Chain, []string{"demo-entry", "demo-relay", "demo-exit"}) || len(result[0].RelayLinks) != 2 {
		t.Fatal("measured relay was frozen into the signed candidate", result[0])
	}
	if !reflect.DeepEqual(route.Chain, []string{"demo-entry", "demo-exit"}) {
		t.Fatal("path estimation mutated its accepted projection")
	}
	// Expiry leaves a topology exploration path instead of inventing zero RTT or
	// declaring the whole network unavailable.
	expired, err := EstimateRoutePaths([]RouteCandidate{route}, []PolicyGraph{graph}, nil, samples, "demo-network", at.Add(time.Minute))
	if err != nil || expired[0].GraphUnavailable || len(expired[0].Chain) == 0 {
		t.Fatal("expiry became a physical fault", err)
	}
	// Diagnostic failures lower preference but do not remove a legal suffix.
	for index := range samples {
		samples[index].Observation.Result = "unavailable"
		samples[index].Observation.RoundTripMS = nil
	}
	failed, err := EstimateRoutePaths([]RouteCandidate{route}, []PolicyGraph{graph}, nil, samples, "demo-network", at.Add(time.Second))
	if err != nil || failed[0].GraphUnavailable || len(failed[0].RelayLinks) == 0 {
		t.Fatal("diagnostic failures removed every qualified topology attempt", err)
	}
	unknown, err := EstimateRoutePaths([]RouteCandidate{route}, []PolicyGraph{graph}, nil, samples[:1], "demo-network", at.Add(time.Second))
	if err != nil || !reflect.DeepEqual(unknown[0].Chain, []string{"demo-entry", "demo-relay", "demo-exit"}) {
		t.Fatal("a failed shorter suffix outranked an unknown legal suffix", unknown, err)
	}
	// Revocation and hop constraints still remove topology, independently of
	// whether a prior measurement happened to be successful.
	for _, blocked := range []PolicyGraph{
		{PolicyID: graph.PolicyID, SourceNode: graph.SourceNode, RelayScope: graph.RelayScope, Links: []GraphLink{}},
		{PolicyID: graph.PolicyID, SourceNode: graph.SourceNode, RelayScope: graph.RelayScope, MaxHops: 1, Links: graph.Links},
	} {
		got, err := EstimateRoutePaths([]RouteCandidate{route}, []PolicyGraph{blocked}, nil, samples, "demo-network", at.Add(time.Second))
		if err != nil || !got[0].GraphUnavailable {
			t.Fatal("measurement fallback bypassed a missing/restricted legal graph", got, err)
		}
	}
}
