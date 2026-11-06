package control

import (
	"reflect"
	"testing"
	"time"
)

func policyVisibilityFixture() (DeviceView, time.Time, []DeviceLinkObservation) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	service := Service{ID: "demo-service", Name: "Demo service", Kind: "internet", ProbeURLs: []string{"https://demo-a.example/health", "https://demo-b.example/health"}}
	policy := materialTestPolicy("demo-policy", service.ID)
	policy.AllowDirect = new(false)
	other := policy
	other.ID = "demo-unselected"
	view := DeviceView{NetworkID: "demo-network", DeviceID: "demo-access", Responsibilities: []string{"access"}, PolicyIDs: []string{policy.ID, other.ID}, Services: []Service{service}, Policies: []NetworkPolicy{policy, other}, DNSServers: []string{},
		Nodes: []ViewNode{{ID: "demo-exit-a", Responsibilities: []string{"internet_egress"}}, {ID: "demo-exit-b", Responsibilities: []string{"internet_egress"}}}}
	rows := []DeviceLinkObservation{}
	for _, exit := range view.Nodes {
		for _, url := range service.ProbeURLs {
			sample := Observation{Level: "egress", Target: url, Action: "https_request", SpecDigest: ReleaseDigest([]byte(exit.ID + url)), NetworkGeneration: "demo-remote-" + exit.ID,
				Result: "unavailable", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli(), DurationMS: new(int64(10))}
			rows = append(rows, DeviceLinkObservation{DeviceID: exit.ID, ReportSequence: 1, ReportDigest: ReleaseDigest([]byte("demo-original")), CurrentUntil: sample.ValidUntil, Observation: sample})
		}
	}
	return view, at, rows
}

func TestPolicyVisibilityUsesAllExpectedExitRequestsAndPreservesCurrentChoice(t *testing.T) {
	view, at, rows := policyVisibilityFixture()
	rows[0].CurrentUntil = at.Add(30 * time.Second).UnixMilli()
	want := map[string]int64{"demo-policy": rows[0].CurrentUntil, "demo-unselected": rows[0].CurrentUntil}
	hidden, err := HiddenInternetPolicies(view, "", rows, nil, "", at.Add(time.Second))
	if err != nil || !reflect.DeepEqual(hidden, want) {
		t.Fatal("complete current failure evidence did not hide unselected options", hidden, err)
	}
	hidden, err = HiddenInternetPolicies(view, "demo-policy", rows, nil, "", at.Add(time.Second))
	delete(want, "demo-policy")
	if err != nil || !reflect.DeepEqual(hidden, want) {
		t.Fatal("current valid Policy was hidden or another option lost its deadline", hidden, err)
	}
	// Scope is an authorized exit set, not a precomputed list of full paths.
	view.Policies[1].ExitScope = &PolicyScope{Mode: "only", NodeIDs: []string{"demo-exit-a"}}
	hidden, err = HiddenInternetPolicies(view, "", rows[:2], nil, "", at.Add(time.Second))
	if err != nil || !reflect.DeepEqual(hidden, want) {
		t.Fatal("fixed exit borrowed an unrelated exit or missing samples became failures", hidden, err)
	}
	hidden, err = HiddenInternetPolicies(view, "", rows, nil, "", at.Add(30*time.Second))
	if err != nil || len(hidden) != 0 {
		t.Fatal("expired evidence kept an option hidden", hidden, err)
	}
}

func TestPolicyVisibilityKeepsUnknownPartialDirectAndUnmeasuredOptions(t *testing.T) {
	for _, scenario := range []string{"missing", "single-failure", "unknown", "available", "future", "expired", "conflict", "source-generation-conflict", "no-urls", "direct", "no-exit"} {
		t.Run(scenario, func(t *testing.T) {
			view, at, rows := policyVisibilityFixture()
			switch scenario {
			case "missing":
				rows = nil
			case "single-failure":
				rows = rows[:1]
			case "unknown":
				rows[0].Observation.Result = "unknown"
			case "available":
				rows[0].Observation.Result = "available"
			case "future":
				rows[0].Observation.ObservedAt = at.Add(2 * time.Second).UnixMilli()
			case "expired":
				rows[0].CurrentUntil = at.Add(500 * time.Millisecond).UnixMilli()
			case "conflict", "source-generation-conflict":
				other := rows[0]
				if scenario == "conflict" {
					other.Observation.Result = "available"
				} else {
					other.Observation.NetworkGeneration = "demo-other-generation"
				}
				rows = append(rows, other, rows[0])
				if scenario == "source-generation-conflict" {
					later := rows[0]
					later.Observation.ObservedAt += 200
					rows = append(rows, later)
				}
			case "no-urls":
				view.Services[0].ProbeURLs = nil
			case "direct":
				for i := range view.Policies {
					view.Policies[i].AllowDirect = new(true)
				}
			case "no-exit":
				view.Nodes = nil
			}
			hidden, err := HiddenInternetPolicies(view, "", rows, nil, "", at.Add(time.Second))
			if err != nil || len(hidden) != 0 {
				t.Fatal("unknown or partial evidence hid authorized options", hidden, err)
			}
		})
	}
}

func TestPolicyVisibilityLocalExitRequiresItsCurrentGenerationAndSpecification(t *testing.T) {
	view, at, rows := policyVisibilityFixture()
	view.Responsibilities = []string{"access", "internet_egress"}
	for i := range view.Policies {
		view.Policies[i].LocalEgressDevices = new([]string{view.DeviceID})
	}
	probes, err := EgressProbes(view)
	if err != nil || len(probes) != 2 {
		t.Fatal("missing own current probe specifications", probes, err)
	}
	local := []Observation{}
	for _, probe := range probes {
		local = append(local, Observation{Level: "egress", Target: probe.Target, Action: "https_request", SpecDigest: probe.SpecDigest, NetworkGeneration: "demo-local", Result: "unavailable", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli()})
	}
	for _, scenario := range []string{"missing-local", "current", "old-generation", "old-spec"} {
		values := append([]Observation(nil), local...)
		switch scenario {
		case "missing-local":
			values = nil
		case "old-generation":
			values[0].NetworkGeneration = "demo-old-network"
		case "old-spec":
			values[0].SpecDigest = ReleaseDigest([]byte("demo-retired-spec"))
		}
		hidden, err := HiddenInternetPolicies(view, "", rows, values, "demo-local", at.Add(time.Second))
		if err != nil || (len(hidden) == 2) != (scenario == "current") {
			t.Fatal("local exit evidence lost its scope", scenario, hidden, err)
		}
	}
	// Receiver-side or LAN policies are never new access choices.
	view.PolicyIDs = nil
	hidden, err := HiddenInternetPolicies(view, "", rows, local, "demo-local", at.Add(time.Second))
	if err != nil || len(hidden) != 0 {
		t.Fatal("unassigned policy acquired visibility state", hidden, err)
	}
}
