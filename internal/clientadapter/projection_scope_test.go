package clientadapter

import (
	"encoding/json"
	"reflect"
	"testing"

	"loom/internal/control"
	"loom/protocol"
)

func TestPolicyGraphsRequireExplicitCurrentScopes(t *testing.T) {
	view, _, _ := resourceProbeFixture(t)
	view.Responsibilities = []string{"access", "forward"}
	graphs, err := PolicyGraphs(view, []string{"demo-b"})
	if err != nil || len(graphs) != 1 || graphs[0].PolicyID != "demo-b" || len(graphs[0].Links) != 2 {
		t.Fatal("unselected Policies expanded the graph input", graphs, err)
	}
	for _, link := range graphs[0].Links {
		if link.From != view.DeviceID || link.To != "demo-exit" || link.Ref.DeviceID != view.DeviceID || link.Ref.LinkID == "" || link.Ref.SpecDigest == "" {
			t.Fatal("graph lost its authenticated directed sample specification", link)
		}
	}
	empty, err := PolicyGraphs(view, nil)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatal("pending selection calculated all granted Policies", empty, err)
	}
	view.Policies[2].Action = "deny"
	for _, selected := range [][]string{{"demo-missing"}, {"demo-b", "demo-b"}, {"demo-c"}} {
		if _, err := PolicyGraphs(view, selected); err == nil {
			t.Fatal("invalid calculation scope was accepted", selected)
		}
	}
}

func TestAccessRoutingInputsMatchCurrentStandaloneProjections(t *testing.T) {
	view, _, _ := resourceProbeFixture(t)
	view.Responsibilities = []string{"access", "forward"}
	for _, selected := range [][]string{nil, {"demo-a"}, {"demo-b"}} {
		routes, graphs, err := AccessRoutingInputs(view, selected)
		if err != nil {
			t.Fatal(err)
		}
		wantRoutes, routeErr := AccessCandidates(view, selected)
		wantGraphs, graphErr := PolicyGraphs(view, selected)
		if routeErr != nil || graphErr != nil || !reflect.DeepEqual(routes, wantRoutes) || !reflect.DeepEqual(graphs, wantGraphs) {
			t.Fatal("shared projection changed candidate/specification semantics", selected, routeErr, graphErr)
		}
		for _, route := range routes {
			if len(selected) != 1 || route.PolicyID != selected[0] {
				t.Fatal("shared projection expanded an unselected Policy", route.PolicyID)
			}
		}
	}
	if _, _, err := AccessRoutingInputs(view, []string{"demo-missing"}); err == nil {
		t.Fatal("shared projection bypassed the selected Policy grant")
	}
}

func TestForwardProjectionMatchesNativeFacilities(t *testing.T) {
	for _, scenario := range []string{"access-only", "forward", "outside-entry-and-relay", "denied-policy"} {
		t.Run(scenario, func(t *testing.T) {
			view, _, _ := resourceProbeFixture(t)
			if scenario != "access-only" {
				view.Responsibilities = []string{"access", "forward"}
			}
			if scenario == "outside-entry-and-relay" {
				for i := range view.Policies {
					view.Policies[i].EntryScope = control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-exit"}}
					view.Policies[i].RelayScope = control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-exit"}}
				}
			}
			if scenario == "denied-policy" {
				view.Policies[1].Action = "deny"
			}
			actual, err := forwardProjections(view)
			if err != nil {
				t.Fatal(err)
			}
			execution, err := control.ProjectDeviceExecution(view, nil)
			if err != nil {
				t.Fatal(err)
			}
			var native struct {
				Outbounds []struct {
					Tag string `json:"tag"`
					Hop *struct {
						Policy protocol.HopPolicy `json:"policy"`
						Node   string             `json:"node_id"`
						Nodes  map[string]string  `json:"nodes"`
					} `json:"hop"`
				} `json:"outbounds"`
			}
			if err := json.Unmarshal([]byte(execution.RuntimeProfile.Config), &native); err != nil {
				t.Fatal(err)
			}
			var expected []forwardProjection
			for _, outbound := range native.Outbounds {
				if outbound.Hop != nil {
					nodes := map[string]forwardNextHop{}
					for _, resource := range view.Resources {
						tag, err := control.ForwardSegmentTag(resource.ID)
						if err != nil {
							t.Fatal(err)
						}
						if node, ok := outbound.Hop.Nodes[tag]; ok {
							nodes[tag] = forwardNextHop{NodeID: node, ResourceID: resource.ID}
						}
					}
					expected = append(expected, forwardProjection{outbound.Tag, outbound.Hop.Policy, outbound.Hop.Node, nodes})
				}
			}
			if len(actual) != len(expected) || len(actual) > 0 && !reflect.DeepEqual(actual, expected) {
				t.Fatal("performance input differs from the native receiver Policy", actual, expected)
			}
			for _, value := range actual {
				if scenario == "outside-entry-and-relay" && len(value.Nodes) == 0 {
					t.Fatal("entry qualification erased retained transport facilities")
				}
			}
		})
	}
}
