package clientmodel

import (
	"loom/internal/control"
	"testing"
	"time"
)

func TestUnknownSelectionUsesHopCountOnlyAfterActualCurrentAndTransportEvidence(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	routes := []RouteCandidate{{ID: "demo-a-relay", PolicyID: "demo-policy", Scope: "service:demo-web", FinalExit: "demo-exit", Chain: []string{"demo-entry", "demo-exit"}}, {ID: "demo-z-short", PolicyID: "demo-policy", Scope: "service:demo-web", FinalExit: "demo-exit", Chain: []string{"demo-exit"}}}
	for _, test := range []struct{ current, want string }{{"", "demo-z-short"}, {"demo-a-relay", "demo-a-relay"}} {
		for _, order := range [][]RouteCandidate{routes, {routes[1], routes[0]}} {
			got, err := Select(order, nil, nil, Preference{Schema: 3, PolicyID: "demo-policy"}, test.current, "demo-network", at)
			if err != nil || got.CandidateID != test.want {
				t.Fatal("unknown tie depended on input order", got, err)
			}
		}
	}
}

func TestHTTPSDurationCannotReplaceTransportRTT(t *testing.T) {
	routes, resources, at := firstHopSelectionFixture()
	for i := range routes {
		routes[i].FixedExit = true
		resources[i].RoundTripMS = new(int64(100 - i*40))
		resources[i].DurationMS = new(int64(101 - i*40))
	}
	business := []Observation{}
	for i, route := range routes {
		business = append(business, Observation{CandidateID: route.ID, Scope: control.AccessSelectorScope, NetworkGeneration: "demo-network", Target: "https://demo.example/", Result: "available", Action: "https_request", ObservedAt: at.Format(time.RFC3339), ValidUntil: at.Add(time.Minute).Format(time.RFC3339), MetricMillis: int64(5 + i*500)})
	}
	for _, order := range [][]RouteCandidate{routes, {routes[2], routes[0], routes[1]}} {
		got, err := Select(order, business, resources, Preference{Schema: 3, PolicyID: "demo-policy"}, routes[0].ID, "demo-network", at, "https://demo.example/")
		if err != nil || got.CandidateID != routes[2].ID {
			t.Fatal("HTTPS total duration replaced measured transport RTT", got, err)
		}
	}
}
