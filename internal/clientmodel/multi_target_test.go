package clientmodel

import (
	"testing"
	"time"
)

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
