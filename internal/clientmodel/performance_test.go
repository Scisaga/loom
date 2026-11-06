package clientmodel

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"loom/internal/control"
)

func TestStableTransportOptimizationMeasuresThroughCooldownAndRequiresNewPairedSamples(t *testing.T) {
	at, routes, resources, _ := routingEvidenceFixture()
	for i := range routes {
		routes[i].FixedExit = true
		routes[i].FinalExit = "demo-fixed"
		routes[i].Chain = []string{"demo-fixed"}
	}
	current := Selection{Scope: "access", CandidateID: routes[1].ID, Targets: map[string]string{}}
	memory := SelectionMemory{}
	choose := func(seconds int64) Selection {
		t.Helper()
		selected, next, err := ChooseWithStability(routes, nil, resources, nil, Preference{Schema: 3, PolicyID: "demo-policy"}, current, memory, "demo-local", at.Add(time.Duration(seconds)*time.Second), seconds*1000, DefaultPerformanceRule)
		if err != nil {
			t.Fatal(err)
		}
		memory = next
		return selected
	}
	if got := choose(0); got.CandidateID != current.CandidateID {
		t.Fatal("first better metric skipped confirmation/cooldown")
	}
	if got := choose(35); got.CandidateID != current.CandidateID {
		t.Fatal("repeated old samples counted as sustained improvement")
	}
	// A new sample from only one of the relevant sources is not a paired round.
	resources[0].ObservedAt = at.Add(20 * time.Second).UnixMilli()
	resources[0].ValidUntil = at.Add(80 * time.Second).UnixMilli()
	if got := choose(35); got.CandidateID != current.CandidateID {
		t.Fatal("only one source remeasured, yet both were treated as fresh")
	}
	resources[1].ObservedAt = at.Add(20 * time.Second).UnixMilli()
	resources[1].ValidUntil = at.Add(80 * time.Second).UnixMilli()
	selected := choose(35)
	if selected.CandidateID != routes[0].ID {
		t.Fatal("significant sustained transport improvement was never applied")
	}
	if memory.Decisions[""].Current != current.CandidateID {
		t.Fatal("proposal was recorded as an actual application")
	}
	var err error
	memory, err = ConfirmSelection(memory, selected, 35_000)
	if err != nil || memory.Decisions[""].Current != selected.CandidateID || memory.Decisions[""].AppliedMS != 35_000 {
		t.Fatal("actual application did not set its own interval", err)
	}
}

func TestStableChoiceSeparatesExpiryFaultNetworkChangeAndPolicyWithdrawal(t *testing.T) {
	for _, scenario := range []string{"expired", "fault", "network", "withdrawal"} {
		t.Run(scenario, func(t *testing.T) {
			at, routes, resources, _ := routingEvidenceFixture()
			for i := range routes {
				routes[i].FixedExit = true
				routes[i].FinalExit = "demo-fixed"
				routes[i].Chain = []string{"demo-fixed"}
			}
			current := Selection{Scope: "access", CandidateID: routes[1].ID, Targets: map[string]string{}}
			pref := Preference{Schema: 3, PolicyID: "demo-policy"}
			_, memory, err := ChooseWithStability(routes, nil, resources, nil, pref, current, SelectionMemory{}, "demo-local", at, 0, DefaultPerformanceRule)
			if err != nil {
				t.Fatal(err)
			}
			generation := "demo-local"
			when := at.Add(5 * time.Second)
			want := routes[0].ID
			switch scenario {
			case "expired":
				when = at.Add(time.Minute)
				want = current.CandidateID
			case "fault":
				resources[1].Result = "unavailable"
				resources[1].RoundTripMS = nil
			case "network":
				generation = "demo-other"
				resources[0].NetworkGeneration = generation
			case "withdrawal":
				routes = routes[:1]
			}
			chosen, _, err := ChooseWithStability(routes, nil, resources, nil, pref, current, memory, generation, when, 5_000, DefaultPerformanceRule)
			if err != nil || chosen.CandidateID != want {
				t.Fatal("expiry/fault/network/withdrawal semantics were conflated", chosen, err)
			}
		})
	}
}

func TestCoverageOptimizationAndInitialTargetDiscoveryUseOriginalRemoteMeasurements(t *testing.T) {
	at, routes, resources, egress := routingEvidenceFixture()
	a, b := "https://demo-a.example/health", "https://demo-b.example/health"
	shared := []control.DeviceLinkObservation{egress("demo-fast", a, "available", 0), egress("demo-fast", b, "unavailable", 0), egress("demo-covered", a, "available", 0), egress("demo-covered", b, "available", 0)}
	current := Selection{Scope: "access", CandidateID: routes[0].ID, Targets: map[string]string{}}
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	selected, memory, err := ChooseWithStability(routes, nil, resources, shared, pref, current, SelectionMemory{}, "demo-local", at, 0, DefaultPerformanceRule, a, b)
	if err != nil || selected.CandidateID != current.CandidateID || selected.Targets["tcp://demo-b.example:443"] != routes[1].ID {
		t.Fatal("target discovery waited for global optimization or changed the global choice early", selected, err)
	}
	memory, err = ConfirmSelection(memory, selected, 0)
	if err != nil {
		t.Fatal(err)
	}
	current = selected
	// Merely delivering the originals at newer report positions is not new work.
	for i := range shared {
		shared[i].ReportSequence = 100
		shared[i].ReportDigest = control.ReleaseDigest([]byte("demo-later-report"))
	}
	selected, memory, err = ChooseWithStability(routes, nil, resources, shared, pref, current, memory, "demo-local", at.Add(35*time.Second), 35_000, DefaultPerformanceRule, a, b)
	if err != nil || selected.CandidateID != current.CandidateID {
		t.Fatal("report delivery renewed confirmation", selected, err)
	}
	for i := range shared {
		shared[i].Observation.ObservedAt += 20_000
		shared[i].Observation.ValidUntil += 20_000
		shared[i].CurrentUntil += 20_000
	}
	selected, _, err = ChooseWithStability(routes, nil, resources, shared, pref, current, memory, "demo-local", at.Add(35*time.Second), 35_000, DefaultPerformanceRule, a, b)
	if err != nil || selected.CandidateID != routes[1].ID || selected.Targets["tcp://demo-a.example:443"] != routes[0].ID {
		t.Fatal("sustained wider coverage was not preferred", selected, err)
	}
}

func TestStableTransportUsesAsynchronousSamplesUntilTheirOriginalExpiry(t *testing.T) {
	for _, expires := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "expired"}[expires], func(t *testing.T) {
			at, routes, resources, _ := routingEvidenceFixture()
			for i := range routes {
				routes[i].FixedExit, routes[i].FinalExit = true, "demo-fixed"
				routes[i].Chain = []string{"demo-fixed"}
				resources[i].ValidUntil = at.Add(10 * time.Minute).UnixMilli()
			}
			current := Selection{Scope: "access", CandidateID: routes[1].ID, Targets: map[string]string{}}
			pref := Preference{Schema: 3, PolicyID: "demo-policy"}
			_, memory, err := ChooseWithStability(routes, nil, resources, nil, pref, current, SelectionMemory{}, "demo-local", at, 0, DefaultPerformanceRule)
			if err != nil || memory.Decisions[""].Confirmations != 1 {
				t.Fatal("first improvement was not recorded", memory, err)
			}
			// Sources measure independently. One source is newer than the old
			// pairing window; both originals are still valid in this network.
			resources[0].ObservedAt = at.Add(3 * time.Minute).UnixMilli()
			if expires {
				resources[1].ValidUntil = resources[0].ObservedAt
			}
			selected, memory, err := ChooseWithStability(routes, nil, resources, nil, pref, current, memory, "demo-local", at.Add(3*time.Minute), 180_000, DefaultPerformanceRule)
			if err != nil || selected.CandidateID != current.CandidateID {
				t.Fatal("one source update changed the connection preference", selected, err)
			}
			if expires {
				if memory.Decisions[""].Confirmations != 0 {
					t.Fatal("expired evidence retained an improvement vote")
				}
				return
			}
			if memory.Decisions[""].Confirmations != 1 {
				t.Fatal("an asynchronous valid update erased the previous comparison")
			}
			// Replaying the same originals does not confirm the improvement.
			selected, memory, err = ChooseWithStability(routes, nil, resources, nil, pref, current, memory, "demo-local", at.Add(181*time.Second), 181_000, DefaultPerformanceRule)
			if err != nil || selected.CandidateID != current.CandidateID || memory.Decisions[""].Confirmations != 1 {
				t.Fatal("a replay became another measurement", selected, memory, err)
			}
			resources[1].ObservedAt = at.Add(182 * time.Second).UnixMilli()
			selected, _, err = ChooseWithStability(routes, nil, resources, nil, pref, current, memory, "demo-local", at.Add(182*time.Second), 182_000, DefaultPerformanceRule)
			if err != nil || selected.CandidateID != routes[0].ID {
				t.Fatal("independent new measurements never confirmed the better path", selected, err)
			}
		})
	}
}

func TestStableTransportDoesNotCombineDifferentComparisonSpecifications(t *testing.T) {
	at, routes, resources, _ := routingEvidenceFixture()
	for i := range routes {
		routes[i].FixedExit, routes[i].FinalExit = true, "demo-fixed"
		routes[i].Chain = []string{"demo-fixed"}
		resources[i].ValidUntil = at.Add(10 * time.Minute).UnixMilli()
	}
	current := Selection{Scope: "access", CandidateID: routes[1].ID, Targets: map[string]string{}}
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	_, memory, err := ChooseWithStability(routes, nil, resources, nil, pref, current, SelectionMemory{}, "demo-local", at, 0, DefaultPerformanceRule)
	if err != nil {
		t.Fatal(err)
	}
	spec := control.ReleaseDigest([]byte("demo-replaced-resource-specification"))
	routes[0].FirstHop.SpecDigest, resources[0].SpecDigest = spec, spec
	for i := range resources {
		resources[i].ObservedAt = at.Add(40 * time.Second).UnixMilli()
	}
	selected, memory, err := ChooseWithStability(routes, nil, resources, nil, pref, current, memory, "demo-local", at.Add(40*time.Second), 40_000, DefaultPerformanceRule)
	if err != nil || selected.CandidateID != current.CandidateID || memory.Decisions[""].Confirmations != 1 {
		t.Fatal("another measurement specification reused the previous improvement vote", selected, memory, err)
	}
	for i := range resources {
		resources[i].ObservedAt = at.Add(80 * time.Second).UnixMilli()
	}
	selected, _, err = ChooseWithStability(routes, nil, resources, nil, pref, current, memory, "demo-local", at.Add(80*time.Second), 80_000, DefaultPerformanceRule)
	if err != nil || selected.CandidateID != routes[0].ID {
		t.Fatal("the new specification could not form its own improvement evidence", selected, err)
	}
}

func TestMeasurementCandidatesUseOnlyTheCurrentPolicyNetworkAndActualChoice(t *testing.T) {
	current := Selection{Scope: "access", PolicyID: "demo-policy", CandidateID: "demo-current", Targets: map[string]string{"tcp://demo.example:443": "demo-target"}}
	memory := SelectionMemory{PolicyID: "demo-policy", NetworkGeneration: "demo-network", Decisions: map[string]SelectionDecision{
		"":                       {Current: current.CandidateID, Pending: "demo-better", Confirmations: 1},
		"tcp://demo.example:443": {Current: "demo-target", Pending: "demo-better", Confirmations: 1},
	}}
	for _, scenario := range []string{"pending", "other-policy", "other-network", "changed-current", "not-confirmed"} {
		t.Run(scenario, func(t *testing.T) {
			value := copySelectionMemory(memory)
			want := []string{"demo-current", "demo-target"}
			switch scenario {
			case "pending":
				want = append([]string{"demo-better"}, want...)
			case "other-policy":
				value.PolicyID = "demo-other"
			case "other-network":
				value.NetworkGeneration = "demo-other"
			case "changed-current":
				for key, decision := range value.Decisions {
					decision.Current = "demo-replaced"
					value.Decisions[key] = decision
				}
			case "not-confirmed":
				for key, decision := range value.Decisions {
					decision.Confirmations = 0
					value.Decisions[key] = decision
				}
			}
			got := MeasurementCandidates(current, value, "demo-network")
			if !slices.Equal(got, want) {
				t.Fatal("measurement priority became stale, duplicated, or crossed its owner", got, want)
			}
		})
	}
}

func TestStableTransportTracksNewSamplesInEachSourcesOwnClock(t *testing.T) {
	at, routes, resources, _ := routingEvidenceFixture()
	for i := range routes {
		routes[i].FixedExit, routes[i].FinalExit = true, "demo-fixed"
		routes[i].Chain = []string{"demo-fixed"}
		resources[i].ValidUntil = at.Add(10 * time.Minute).UnixMilli()
	}
	resources[1].ObservedAt = at.Add(-90 * time.Second).UnixMilli()
	current := Selection{Scope: "access", CandidateID: routes[1].ID, Targets: map[string]string{}}
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	_, memory, err := ChooseWithStability(routes, nil, resources, nil, pref, current, SelectionMemory{}, "demo-local", at, 0, DefaultPerformanceRule)
	if err != nil || memory.Decisions[""].Confirmations != 1 {
		t.Fatal("independent valid source times prevented the first comparison", memory, err)
	}
	for i := range resources {
		resources[i].ObservedAt += 40_000
	}
	selected, _, err := ChooseWithStability(routes, nil, resources, nil, pref, current, memory, "demo-local", at.Add(40*time.Second), 40_000, DefaultPerformanceRule)
	if err != nil || selected.CandidateID != routes[0].ID {
		t.Fatal("a source's new sample was rejected by another source's clock", selected, err)
	}
}

func TestManyTargetsShareMeasurementProgressWithoutExpandingPathProofs(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	e := routingEvaluation{paths: map[string]routeEvidence{}, origins: map[string][]string{}, knownOrigins: map[string]bool{},
		exits: map[string]map[string]routeFact{"demo-exit": {}}, originCache: map[string]map[string]originEvidence{}, now: at,
		selection: Selection{Scope: "access", CandidateID: "demo-better", Targets: map[string]string{}}}
	for i, id := range []string{"demo-current", "demo-better"} {
		path := routeEvidence{route: RouteCandidate{ID: id, FinalExit: "demo-exit"}, entryReady: true, cost: new(int64(200 - 180*i)), facts: map[string]routeFact{}}
		for segment := 0; segment < 12; segment++ {
			key := fmt.Sprintf("%s/demo-segment-%d", id, segment)
			path.facts[key] = routeFact{id: key, result: "available", at: at.UnixMilli(), until: at.Add(10 * time.Minute).UnixMilli()}
		}
		e.paths[id] = path
	}
	configuredURLs := []string{}
	for i := 0; i < 512; i++ {
		host := fmt.Sprintf("demo-%d.example", i)
		origin, url := "tcp://"+host+":443", "https://"+host+"/"
		configuredURLs = append(configuredURLs, url)
		e.origins[origin], e.knownOrigins[origin] = []string{url}, true
		e.exits["demo-exit"][url] = routeFact{id: url, result: "available", at: at.UnixMilli(), until: at.Add(10 * time.Minute).UnixMilli()}
	}
	current := Selection{Scope: "access", CandidateID: "demo-current", Targets: map[string]string{}}
	pref := Preference{Schema: 3, PolicyID: "demo-policy"}
	_, memory, err := chooseStable(e, pref, current, SelectionMemory{}, "demo-network", at, 0, DefaultPerformanceRule, configuredURLs)
	if err != nil || len(memory.Samples) != 24 || len(memory.Decisions) != 513 {
		t.Fatal("targets expanded the shared segment progress table", len(memory.Samples), len(memory.Decisions), err)
	}
	before, err := json.Marshal(memory)
	if err != nil || len(before) > 1<<20 {
		t.Fatal("selection memory exceeded the existing mobile input bound", len(before), err)
	}
	e.now = at.Add(40 * time.Second)
	for id, path := range e.paths {
		for key, fact := range path.facts {
			fact.at += 40_000
			path.facts[key] = fact
		}
		e.paths[id] = path
	}
	selected, next, err := chooseStable(e, pref, current, memory, "demo-network", e.now, 40_000, DefaultPerformanceRule, configuredURLs)
	after, _ := json.Marshal(memory)
	if err != nil || selected.CandidateID != "demo-better" || len(next.Samples) != 24 || next.Version-memory.Version != 24 || string(before) != string(after) {
		t.Fatal("new source originals were duplicated per target or mutated previous memory", selected, next.Version-memory.Version, err)
	}
}
