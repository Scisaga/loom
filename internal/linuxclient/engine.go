package linuxclient

import (
	"context"
	"errors"
	"sort"
	"time"

	"loom/internal/clientmodel"
)

type ProbeResult struct {
	Available   bool
	Metric      time.Duration
	Description string
}

type Probe func(context.Context) ProbeResult

type Activation struct {
	State      LocalState
	Selections []SelectionStatus
}

func scopesFor(routes []clientmodel.RouteCandidate) ([]string, map[string][]clientmodel.RouteCandidate, error) {
	byScope := map[string][]clientmodel.RouteCandidate{}
	for _, route := range routes {
		if err := route.Validate(); err != nil {
			return nil, nil, err
		}
		byScope[route.Scope] = append(byScope[route.Scope], route)
	}
	scopes := make([]string, 0, len(byScope))
	for scope := range byScope {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	if len(scopes) == 0 {
		return nil, nil, errors.New("certified LKG contains no route candidates")
	}
	return scopes, byScope, nil
}

func selectAll(routes []clientmodel.RouteCandidate, observations []clientmodel.Observation,
	preference clientmodel.Preference, current map[string]string, generation string, now time.Time) (map[string]string, error) {
	scopes, byScope, err := scopesFor(routes)
	if err != nil {
		return nil, err
	}
	desired := make(map[string]string, len(scopes))
	for _, scope := range scopes {
		selection, err := clientmodel.Select(byScope[scope], observations, preference, current[scope], generation, now)
		if err != nil {
			return nil, err
		}
		desired[scope] = selection.CandidateID
	}
	return desired, nil
}

func currentReadback(ctx context.Context, selector Selector, scopes []string) (map[string]string, error) {
	current := make(map[string]string, len(scopes))
	for _, scope := range scopes {
		value, err := selector.Read(ctx, scope)
		if err != nil {
			return nil, err
		}
		current[scope] = value
	}
	return current, nil
}

func missingObservation(selections map[string]string, observations []clientmodel.Observation, generation string, now time.Time) bool {
	seen := map[string]bool{}
	for _, observation := range observations {
		until, _ := time.Parse(time.RFC3339, observation.ValidUntil)
		if observation.NetworkGeneration == generation && now.Before(until) {
			seen[observation.CandidateID] = true
		}
	}
	for _, candidate := range selections {
		if !seen[candidate] {
			return true
		}
	}
	return false
}

func recordOutcome(state LocalState, selections map[string]string, result ProbeResult, now time.Time) LocalState {
	byID := map[string]clientmodel.Observation{}
	for _, observation := range state.Observations {
		byID[observation.CandidateID] = observation
	}
	for scope, candidate := range selections {
		outcome := "unavailable"
		if result.Available {
			outcome = "available"
		}
		metric := result.Metric.Milliseconds()
		if metric < 0 {
			metric = 0
		}
		byID[candidate] = clientmodel.Observation{CandidateID: candidate, NetworkGeneration: state.NetworkGeneration,
			Scope: scope, Result: outcome, Action: "tcp_udp_dns", ObservedAt: now.UTC().Format(time.RFC3339),
			ValidUntil: now.Add(10 * time.Minute).UTC().Format(time.RFC3339), MetricMillis: metric}
	}
	state.Observations = state.Observations[:0]
	for _, observation := range byID {
		state.Observations = append(state.Observations, observation)
	}
	sort.Slice(state.Observations, func(i, j int) bool {
		return state.Observations[i].CandidateID < state.Observations[j].CandidateID
	})
	return state
}

func selectionStatuses(routes []clientmodel.RouteCandidate, observations []clientmodel.Observation,
	selected map[string]string, generation string, now time.Time) []SelectionStatus {
	byID := map[string]clientmodel.RouteCandidate{}
	for _, route := range routes {
		byID[route.ID] = route
	}
	scopes := make([]string, 0, len(selected))
	for scope := range selected {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	statuses := make([]SelectionStatus, 0, len(scopes))
	for _, scope := range scopes {
		candidate := byID[selected[scope]]
		statuses = append(statuses, SelectionStatus{Scope: scope, CandidateID: candidate.ID,
			Chain: append([]string(nil), candidate.Chain...), State: observationState(observations, candidate.ID, generation, now)})
	}
	return statuses
}

// Activate applies the shared pure selection, accepts only selector readback as
// Selection, and performs at most one normal probe plus one necessary fallback.
func Activate(ctx context.Context, selector Selector, routes []clientmodel.RouteCandidate, state LocalState,
	probe Probe, now func() time.Time) (Activation, error) {
	scopes, _, err := scopesFor(routes)
	if err != nil {
		return Activation{}, err
	}
	current, err := currentReadback(ctx, selector, scopes)
	if err != nil {
		return Activation{}, err
	}
	at := now().UTC().Truncate(time.Second)
	desired, err := selectAll(routes, state.Observations, state.Preference, current, state.NetworkGeneration, at)
	if err != nil {
		return Activation{}, err
	}
	readback, err := applySelections(ctx, selector, desired)
	if err != nil {
		return Activation{}, err
	}
	if !missingObservation(readback, state.Observations, state.NetworkGeneration, at) {
		return Activation{State: state, Selections: selectionStatuses(routes, state.Observations, readback, state.NetworkGeneration, at)}, nil
	}
	first := probe(ctx)
	state = recordOutcome(state, readback, first, at)
	if first.Available {
		return Activation{State: state, Selections: selectionStatuses(routes, state.Observations, readback, state.NetworkGeneration, at)}, nil
	}
	fallback, err := selectAll(routes, state.Observations, state.Preference, readback, state.NetworkGeneration, at)
	if err != nil {
		return Activation{State: state, Selections: selectionStatuses(routes, state.Observations, readback, state.NetworkGeneration, at)}, err
	}
	changed := false
	for scope := range fallback {
		changed = changed || fallback[scope] != readback[scope]
	}
	if !changed {
		return Activation{State: state, Selections: selectionStatuses(routes, state.Observations, readback, state.NetworkGeneration, at)},
			errors.New("business probe failed and no fallback candidate remains")
	}
	readback, err = applySelections(ctx, selector, fallback)
	if err != nil {
		return Activation{State: state}, err
	}
	secondAt := now().UTC().Truncate(time.Second)
	second := probe(ctx)
	state = recordOutcome(state, readback, second, secondAt)
	activation := Activation{State: state,
		Selections: selectionStatuses(routes, state.Observations, readback, state.NetworkGeneration, secondAt)}
	if !second.Available {
		return activation, errors.New("business probe failed on the fallback candidate")
	}
	return activation, nil
}
