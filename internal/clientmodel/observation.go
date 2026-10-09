package clientmodel

import (
	"errors"
	"strings"
	"time"

	"loom/internal/control"
)

// CurrentAt uses this device's own sample window, without changing its bytes or
// imposing a global report clock tolerance or maximum lifetime.
func (o Observation) CurrentAt(now time.Time) bool {
	observed, observedErr := time.Parse(time.RFC3339, o.ObservedAt)
	until, untilErr := time.Parse(time.RFC3339, o.ValidUntil)
	return observedErr == nil && untilErr == nil && !now.Before(observed) && now.Before(until)
}

func matchesFirstHop(ref *ResourceSampleRef, sample control.Observation, generation string) bool {
	return ref != nil && sample.Level == "resource" && sample.NetworkGeneration == generation &&
		ref.ResourceID == sample.ResourceID && ref.SpecDigest == sample.SpecDigest &&
		ref.Target == sample.Target && ref.Action == sample.Action
}

func businessSucceededAfter(values []Observation, route RouteCandidate, generation string, targets []string, at int64, now time.Time) (bool, error) {
	// Business samples have second precision. An authentication sample's
	// fractional second cannot prove that a same-second success came earlier.
	threshold := time.UnixMilli(at).UTC().Truncate(time.Second)
	for _, target := range targets {
		sample, found, err := LatestObservation(values, route.ID, route.Scope, generation, target)
		if err != nil {
			return false, err
		}
		observed, _ := time.Parse(time.RFC3339, sample.ObservedAt)
		if found && sample.Result == "available" && !observed.Before(threshold) && !observed.After(now) {
			return true, nil
		}
	}
	return false, nil
}

// Key identifies a disposable sample, not another authority or lifecycle.
func (o Observation) Key() string {
	return strings.Join([]string{o.CandidateID, o.Scope, o.Target, o.Action, o.NetworkGeneration}, "\x00")
}

// LatestObservation never infers a target from a formerly targetless sample.
// An empty target is reserved for explicitly injected local diagnostics.
func LatestObservation(values []Observation, candidate, scope, generation, target string) (Observation, bool, error) {
	var latest Observation
	found := false
	ambiguous := false
	for _, value := range values {
		if value.CandidateID != candidate || value.Scope != scope || value.NetworkGeneration != generation || value.Target != target ||
			target != "" && value.Action != "https_request" {
			continue
		}
		if !found || value.ObservedAt > latest.ObservedAt {
			latest, found = value, true
			ambiguous = false
		} else if value.ObservedAt == latest.ObservedAt && value != latest {
			ambiguous = true
		}
	}
	if ambiguous {
		return Observation{}, false, errors.New("conflicting observations have the same sample time")
	}
	return latest, found, nil
}

// ObservationState describes only the authenticated test set of one Service.
func ObservationState(values []Observation, candidate, scope, generation string, targets []string, now time.Time) (string, error) {
	state, _, _, err := candidateEvidence(values, candidate, scope, generation, targets, now)
	return state, err
}

func candidateEvidence(values []Observation, candidate, scope, generation string, targets []string, now time.Time) (state, failure string, metric int64, err error) {
	if len(targets) == 0 {
		return "unknown", "", 0, nil
	}
	allSuccess, allFailure, latestAllFailed := true, true, true
	seen := map[string]bool{}
	for _, target := range targets {
		if seen[target] {
			return "", "", 0, errors.New("probe targets are duplicated")
		}
		seen[target] = true
		sample, found, sampleErr := LatestObservation(values, candidate, scope, generation, target)
		if sampleErr != nil {
			return "", "", 0, sampleErr
		}
		observed, _ := time.Parse(time.RFC3339, sample.ObservedAt)
		found = found && !observed.After(now)
		valid := found && sample.CurrentAt(now)
		allSuccess = allSuccess && valid && sample.Result == "available"
		allFailure = allFailure && valid && sample.Result == "unavailable"
		latestAllFailed = latestAllFailed && found && sample.Result == "unavailable"
		if sample.ObservedAt > failure {
			failure = sample.ObservedAt
		}
		metric = sample.MetricMillis
	}
	if !latestAllFailed {
		failure = ""
	}
	if len(targets) != 1 {
		metric = 0
	}
	if allSuccess {
		return "available", failure, metric, nil
	}
	if allFailure {
		return "unavailable", failure, 0, nil
	}
	return "unknown", failure, 0, nil
}
