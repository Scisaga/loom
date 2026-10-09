package clientmodel

import (
	"testing"
	"time"
)

func TestTargetSetSelectionDoesNotVoteOrBorrowAnotherScope(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	targets := []string{"https://demo.example/a", "https://demo.example/b", "https://demo.example/c"}
	routes := []RouteCandidate{{ID: "demo-a", FinalExit: "direct", Scope: "service:demo-service"}, {ID: "demo-b", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "service:demo-service"}}
	var samples []Observation
	for i, route := range routes {
		for j, target := range targets {
			result := "unavailable"
			if j <= i {
				result = "available"
			}
			samples = append(samples, Observation{CandidateID: route.ID, Scope: route.Scope, Target: target, NetworkGeneration: "demo-network", Action: "https_request", Result: result, ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)})
		}
	}
	pref := Preference{Schema: 3, Mode: ModeAuto}
	selected, err := Select(routes, samples, pref, "demo-a", "demo-network", now, targets...)
	if err != nil || selected.CandidateID != "demo-a" {
		t.Fatal("partial results were ranked by successful target count", selected, err)
	}
	samples[len(samples)-1].Result = "available"
	selected, err = Select(routes, samples, pref, "demo-a", "demo-network", now, targets...)
	if err != nil || selected.CandidateID != "demo-b" {
		t.Fatal("complete same-Service evidence did not improve an incomplete path", selected, err)
	}
	for i := range samples {
		samples[i].Scope = "service:demo-other"
	}
	selected, err = Select(routes, samples, pref, "demo-a", "demo-network", now, targets...)
	if err != nil || selected.CandidateID != "demo-a" {
		t.Fatal("another Service supplied health", selected, err)
	}
}

func TestTargetlessCacheAndConflictingSamplesCannotInventTargetResults(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	sample := Observation{CandidateID: "demo-route", Scope: "service:demo-service", NetworkGeneration: "demo-network", Action: "https_request", Result: "available", ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)}
	targets := []string{"https://demo.example/"}
	state, err := ObservationState([]Observation{sample}, sample.CandidateID, sample.Scope, sample.NetworkGeneration, targets, now)
	if err != nil || state != "unknown" {
		t.Fatal("old cache was silently assigned to the only configured target", state, err)
	}
	sample.Target = targets[0]
	conflict := sample
	conflict.Result = "unavailable"
	for _, values := range [][]Observation{{sample, conflict}, {conflict, sample}} {
		if _, err := ObservationState(values, sample.CandidateID, sample.Scope, sample.NetworkGeneration, targets, now); err == nil {
			t.Fatal("iteration order resolved equal-time contradictory samples")
		}
	}
}
