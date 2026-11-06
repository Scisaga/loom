package clientadapter

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestForwardMeasurementPriorityStaysOnOwnAllowedLinks(t *testing.T) {
	tag := func(id string) string {
		t.Helper()
		value, err := control.ForwardSegmentTag(id)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	for _, scenario := range []string{"pending", "other-network", "other-role", "other-exit", "withdrawn-policy", "forbidden-next-hop", "remote-link", "not-an-entry-or-relay"} {
		t.Run(scenario, func(t *testing.T) {
			view := control.DeviceExecution{DeviceView: control.DeviceView{DeviceID: "demo-forward", Responsibilities: []string{"forward"}, Policies: []control.NetworkPolicy{{ID: "demo-policy", Action: "allow", EntryScope: control.PolicyScope{Mode: "any", NodeIDs: []string{}}, RelayScope: control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-peer"}}}}},
				PolicyExits: []control.PolicyExits{{PolicyID: "demo-policy", NodeIDs: []string{"demo-exit"}}},
				Links: []control.NetworkLink{
					{ID: "demo-link-current", FromNodeID: "demo-forward", ToNodeID: "demo-exit", ResourceID: "demo-current"},
					{ID: "demo-link-better", FromNodeID: "demo-forward", ToNodeID: "demo-peer", ResourceID: "demo-better"},
					{ID: "demo-link-forbidden", FromNodeID: "demo-forward", ToNodeID: "demo-forbidden", ResourceID: "demo-forbidden"},
					{ID: "demo-link-remote", FromNodeID: "demo-other", ToNodeID: "demo-exit", ResourceID: "demo-remote"},
				}}
			decision := clientmodel.SelectionDecision{Current: tag("demo-current"), Pending: tag("demo-better"), Confirmations: 1}
			memory := clientmodel.SelectionMemory{PolicyID: "demo-policy", NetworkGeneration: "demo-network"}
			key := "forward:demo-policy\x00demo-exit"
			want := []string{"demo-link-better", "demo-link-current"}
			switch scenario {
			case "other-network":
				memory.NetworkGeneration, want = "demo-old", nil
			case "other-role":
				view.Responsibilities, want = []string{"control"}, nil
			case "other-exit":
				key, want = "forward:demo-policy\x00demo-other-exit", nil
			case "withdrawn-policy":
				view.Policies, want = nil, nil
			case "forbidden-next-hop":
				decision.Pending, want = tag("demo-forbidden"), []string{"demo-link-current"}
			case "remote-link":
				decision.Pending, want = tag("demo-remote"), []string{"demo-link-current"}
			case "not-an-entry-or-relay":
				view.Policies[0].EntryScope = control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-exit"}}
				want = nil
			}
			memory.Decisions = map[string]clientmodel.SelectionDecision{"": decision}
			got, err := ForwardMeasurementLinks(view, map[string]clientmodel.SelectionMemory{key: memory}, "demo-network")
			if err != nil || !slices.Equal(got, want) {
				t.Fatal("measurement priority crossed its source or Policy", got, want, err)
			}
		})
	}
}

type unexpectedForwardTransport struct{ calls int }

func (transport *unexpectedForwardTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls++
	return nil, errors.New("unexpected forwarding optimization request")
}

func TestForwardOptimizationSkipsPoliciesThatCannotContinueHere(t *testing.T) {
	view, _, now := resourceProbeFixture(t)
	view.Responsibilities = []string{"access", "forward", "internet_egress"}
	for index := range view.Policies {
		view.Policies[index].EntryScope = control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-exit"}}
		view.Policies[index].RelayScope = control.PolicyScope{Mode: "none", NodeIDs: []string{}}
	}
	transport := new(unexpectedForwardTransport)
	selector := &HTTPSelector{client: &http.Client{Transport: transport}, started: time.Now()}
	memory, err := selector.OptimizeForwarding(context.Background(), view, nil, nil, "demo-network", now,
		map[string]clientmodel.SelectionMemory{"forward:demo-a\x00demo-exit": {PolicyID: "demo-a", NetworkGeneration: "demo-network"}})
	if err != nil || transport.calls != 0 || len(memory) != 0 {
		t.Fatal("inactive retained facilities caused optimization I/O or retained active priority", transport.calls, err)
	}
}

func TestAccessMeasurementPriorityReusesTargetAndPendingResources(t *testing.T) {
	selections := []SelectionStatus{{Scope: "access", PolicyID: "demo-policy", CandidateID: "demo-current", Targets: map[string]string{"demo.example:443": "demo-target"}}}
	memory := map[string]clientmodel.SelectionMemory{"access": {PolicyID: "demo-policy", NetworkGeneration: "demo-network", Decisions: map[string]clientmodel.SelectionDecision{
		"":                 {Current: "demo-current", Pending: "demo-better", Confirmations: 1},
		"demo.example:443": {Current: "demo-target", Pending: "demo-better", Confirmations: 1},
	}}}
	got := MeasurementCandidates(selections, memory, "demo-network")
	if !slices.Equal(got, []string{"demo-better", "demo-current", "demo-target"}) {
		t.Fatal("target-specific use was lost or a shared pending measurement was duplicated", got)
	}
}
