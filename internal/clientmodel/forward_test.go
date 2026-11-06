package clientmodel

import (
	"errors"
	"slices"
	"testing"
	"time"

	"loom/internal/control"
)

func forwardParallelFixture(relay bool) (time.Time, []RouteCandidate, PolicyGraph, []control.Observation, []control.DeviceLinkObservation) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	graph := PolicyGraph{PolicyID: "demo-policy", SourceNode: "demo-forward", RelayScope: control.PolicyScope{Mode: "any", NodeIDs: []string{}}}
	next := "demo-exit"
	if relay {
		next = "demo-next"
	}
	routes := []RouteCandidate{}
	local := []control.Observation{}
	sample := func(ref LinkSampleRef, rtt int64) control.Observation {
		return control.Observation{Level: "link", ResourceID: ref.ResourceID, LinkID: ref.LinkID, SpecDigest: ref.SpecDigest, Target: ref.Target, Action: ref.Action,
			NetworkGeneration: "demo-network", Result: "available", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli(), RoundTripMS: new(rtt), DurationMS: new(rtt + 1)}
	}
	for i, kind := range []string{"wireguard", "hysteria2"} {
		ref := LinkSampleRef{LinkID: "demo-link-" + kind, DeviceID: graph.SourceNode, ResourceID: "demo-resource-" + kind, SpecDigest: control.ReleaseDigest([]byte(kind)), Target: "192.0.2.1:443", Action: "hysteria2_echo"}
		if kind == "wireguard" {
			ref.Target, ref.Action = "[fdab::1]:53", "wireguard_echo"
		}
		graph.Links = append(graph.Links, GraphLink{From: graph.SourceNode, To: next, Ref: ref})
		chain := []string{next}
		if relay {
			chain = append(chain, "demo-exit")
		}
		routes = append(routes, RouteCandidate{ID: "demo-candidate-" + kind, Transport: kind, PolicyID: graph.PolicyID, FixedExit: true, SourceNode: graph.SourceNode, FirstResourceID: ref.ResourceID, FinalExit: "demo-exit", Chain: chain, Scope: "forward:demo-policy"})
		local = append(local, sample(ref, []int64{100, 25}[i]))
	}
	shared := []control.DeviceLinkObservation{}
	if relay {
		// Parallel suffix resources also retain their own Link IDs and specs.
		for i, kind := range []string{"wireguard", "hysteria2"} {
			ref := LinkSampleRef{LinkID: "demo-suffix-" + kind, DeviceID: next, ResourceID: "demo-exit-" + kind, SpecDigest: control.ReleaseDigest([]byte("suffix-" + kind)), Target: "192.0.2.2:443", Action: "hysteria2_echo"}
			if kind == "wireguard" {
				ref.Target, ref.Action = "[fdab::2]:53", "wireguard_echo"
			}
			graph.Links = append(graph.Links, GraphLink{From: next, To: "demo-exit", Ref: ref})
			observation := sample(ref, []int64{10, 60}[i])
			shared = append(shared, control.DeviceLinkObservation{DeviceID: next, ReportSequence: 1, ReportDigest: control.ReleaseDigest([]byte(ref.LinkID)), CurrentUntil: observation.ValidUntil, Observation: observation})
		}
	}
	return at, routes, graph, local, shared
}

func TestForwardParallelResourcesKeepTheirOwnMeasurements(t *testing.T) {
	for _, relay := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			t.Run(map[bool]string{false: "one-hop", true: "relay"}[relay]+map[bool]string{false: "/hy2-faster", true: "/wg-faster"}[reverse], func(t *testing.T) {
				at, routes, graph, local, shared := forwardParallelFixture(relay)
				want := routes[1].ID
				if reverse {
					local[0].RoundTripMS, local[1].RoundTripMS = new(int64(20)), new(int64(120))
					local[1].DurationMS = new(int64(121))
					want = routes[0].ID
				}
				// Graph iteration order must not decide a resource's measurement.
				for _, reversedGraph := range []bool{false, true} {
					if reversedGraph {
						slices.Reverse(graph.Links)
					}
					got, err := ForwardRoutePaths(routes, []PolicyGraph{graph}, local, shared, "demo-network", at)
					if err != nil {
						t.Fatal(err)
					}
					for i, route := range got {
						if route.RelayLinks[0].ResourceID != routes[i].FirstResourceID || route.RelayLinks[0].LinkID != local[i].LinkID || route.RelayLinks[0].SpecDigest != local[i].SpecDigest || route.FinalExit != routes[i].FinalExit || route.ID != routes[i].ID {
							t.Fatal("candidate consumed another transport's identity or evidence", route)
						}
						if relay && (len(route.RelayLinks) != 2 || route.RelayLinks[1].LinkID != shared[0].Observation.LinkID) {
							t.Fatal("suffix lost the actual measured Link reference", route)
						}
					}
					choices, _, err := ChooseForwardWithStability(got, local, shared, Preference{Schema: 3, PolicyID: graph.PolicyID}, Selection{CandidateID: "reject", Targets: map[string]string{}}, SelectionMemory{}, "demo-network", at, 0, DefaultPerformanceRule)
					if err != nil || len(choices) != 2 || choices[0] != want {
						t.Fatal("forward did not compare independent resource RTTs", choices, want, err)
					}
				}
				if len(routes[0].RelayLinks) != 0 || routes[0].Chain[0] == graph.SourceNode {
					t.Fatal("estimation mutated its input")
				}
			})
		}
	}
}

func TestForwardResourceEvidenceDoesNotCrossSpecsOrFailureBoundaries(t *testing.T) {
	for _, scenario := range []string{"spec", "resource", "link", "expired", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			at, routes, graph, local, shared := forwardParallelFixture(false)
			switch scenario {
			case "spec":
				local[1].SpecDigest = local[0].SpecDigest
			case "resource":
				local[1].ResourceID = local[0].ResourceID
			case "link":
				local[1].LinkID = local[0].LinkID
			case "expired":
				local[1].ObservedAt, local[1].ValidUntil = at.Add(-time.Minute).UnixMilli(), at.UnixMilli()
			case "unavailable":
				local[1].Result, local[1].RoundTripMS = "unavailable", nil
			}
			got, err := ForwardRoutePaths(routes, []PolicyGraph{graph}, local, shared, "demo-network", at)
			if err != nil {
				t.Fatal(err)
			}
			evaluation, err := evaluateRouting(got, nil, local, shared, Preference{Schema: 3, PolicyID: graph.PolicyID}, "reject", "demo-network", at, nil)
			if err != nil {
				t.Fatal(err)
			}
			wg, hy2 := evaluation.paths[routes[0].ID], evaluation.paths[routes[1].ID]
			if wg.cost == nil || *wg.cost != 100 || wg.failed || hy2.cost != nil || hy2.failed != (scenario == "unavailable") {
				t.Fatal("one resource's stale/mismatched/failed sample contaminated another", wg, hy2)
			}
			choices, _, err := ChooseForwardWithStability(got, local, shared, Preference{Schema: 3, PolicyID: graph.PolicyID}, Selection{CandidateID: "reject", Targets: map[string]string{}}, SelectionMemory{}, "demo-network", at, 0, DefaultPerformanceRule)
			if err != nil || choices[0] != routes[0].ID {
				t.Fatal("another resource's invalid evidence displaced the measured path", choices, err)
			}
		})
	}
}

func TestForwardMeasurementsCannotRestoreWithdrawnTopology(t *testing.T) {
	for _, scenario := range []string{"local-link", "resource-binding", "source-binding", "receiver-binding", "ambiguous-resource", "suffix", "hops", "policy"} {
		t.Run(scenario, func(t *testing.T) {
			at, routes, graph, local, shared := forwardParallelFixture(true)
			expectError := true
			switch scenario {
			case "local-link":
				graph.Links = graph.Links[1:]
			case "resource-binding":
				routes[0].FirstResourceID = "demo-withdrawn-resource"
			case "source-binding":
				routes[0].SourceNode = "demo-other"
			case "receiver-binding":
				graph.Links[0].To = "demo-other"
			case "ambiguous-resource":
				graph.Links = append(graph.Links, graph.Links[0])
			case "suffix":
				graph.Links, expectError = graph.Links[:2], false
			case "hops":
				graph.MaxHops, expectError = 2, false
			case "policy":
				graph.PolicyID = "demo-other-policy"
			}
			got, err := ForwardRoutePaths(routes, []PolicyGraph{graph}, local, shared, "demo-network", at)
			if expectError {
				if err == nil {
					t.Fatal("missing or ambiguous current authorization accepted", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = ChooseForwardWithStability(got, local, shared, Preference{Schema: 3, PolicyID: graph.PolicyID}, Selection{CandidateID: "reject", Targets: map[string]string{}}, SelectionMemory{}, "demo-network", at, 0, DefaultPerformanceRule)
			if !errors.Is(err, ErrNoUsableCandidate) {
				t.Fatal("measurements restored withdrawn topology", got, err)
			}
		})
	}
}

func TestForwardParallelResourcesPreserveStableConfirmation(t *testing.T) {
	at, routes, graph, local, shared := forwardParallelFixture(false)
	current := Selection{Scope: routes[0].Scope, CandidateID: routes[0].ID, Targets: map[string]string{}}
	memory := SelectionMemory{}
	choose := func(clock int64) []string {
		t.Helper()
		paths, err := ForwardRoutePaths(routes, []PolicyGraph{graph}, local, shared, "demo-network", at.Add(time.Duration(clock)*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		choices, next, err := ChooseForwardWithStability(paths, local, shared, Preference{Schema: 3, PolicyID: graph.PolicyID}, current, memory, "demo-network", at.Add(time.Duration(clock)*time.Millisecond), clock, DefaultPerformanceRule)
		if err != nil {
			t.Fatal(err)
		}
		memory = next
		return choices
	}
	if got := choose(0); got[0] != current.CandidateID {
		t.Fatal("performance change bypassed confirmation", got)
	}
	if got := choose(35_000); got[0] != current.CandidateID {
		t.Fatal("replayed samples confirmed improvement", got)
	}
	for i := range local {
		local[i].ObservedAt = at.Add(20 * time.Second).UnixMilli()
		local[i].ValidUntil = at.Add(80 * time.Second).UnixMilli()
	}
	if got := choose(35_000); got[0] != routes[1].ID {
		t.Fatal("independent fresh resource samples did not confirm improvement", got)
	}
	if memory.Decisions[""].Current != current.CandidateID {
		t.Fatal("proposal became confirmed before CAS/readback")
	}
	current.CandidateID = routes[1].ID
	confirmed, err := ConfirmSelection(memory, current, 35_000)
	if err != nil || confirmed.Decisions[""].Current != current.CandidateID {
		t.Fatal("confirmation failed", err)
	}
}
