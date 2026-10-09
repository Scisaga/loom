package clientadapter

import (
	"context"
	"errors"
	"sort"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

type State struct {
	Preference           clientmodel.Preference
	NetworkGeneration    string
	Observations         []clientmodel.Observation
	ResourceObservations []control.Observation
}

type SelectionStatus struct {
	Scope       string   `json:"scope"`
	CandidateID string   `json:"candidate_id"`
	FinalExit   string   `json:"final_exit"`
	Chain       []string `json:"chain,omitempty"`
	State       string   `json:"state"`
}

type ProbeResult struct {
	Available   bool
	Metric      time.Duration
	Description string
	Action      string
}

type Probe func(context.Context) ProbeResult

type Activation struct {
	State         State
	Selections    []SelectionStatus
	BlockedScopes []string
}

const BlockedSelection = "reject"

func Scopes(routes []clientmodel.RouteCandidate) ([]string, map[string][]clientmodel.RouteCandidate, error) {
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

	return scopes, byScope, nil
}

func selectAll(routes []clientmodel.RouteCandidate, observations []clientmodel.Observation,
	preference clientmodel.Preference, current map[string]string, generation string, now time.Time) (map[string]string, error) {
	scopes, byScope, err := Scopes(routes)
	if err != nil {
		return nil, err
	}
	desired := make(map[string]string, len(scopes))
	for _, scope := range scopes {
		selection, err := clientmodel.Select(byScope[scope], observations, preference, current[scope], generation, now)
		if errors.Is(err, clientmodel.ErrNoUsableCandidate) {
			desired[scope] = BlockedSelection
			continue
		}
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
		if candidate == BlockedSelection {
			continue
		}
		if !seen[candidate] {
			return true
		}
	}
	return false
}

func recordOutcome(state State, selections map[string]string, result ProbeResult, now time.Time) State {
	action := result.Action
	if action == "" {
		action = "tcp_udp_dns"
	}
	byID := map[string]clientmodel.Observation{}
	for _, observation := range state.Observations {
		byID[observation.CandidateID] = observation
	}
	for scope, candidate := range selections {
		if candidate == BlockedSelection {
			continue
		}
		outcome := "unavailable"
		lifetime := 30 * time.Second
		if result.Available {
			outcome = "available"
			lifetime = 10 * time.Minute
		}
		metric := result.Metric.Milliseconds()
		if metric < 0 {
			metric = 0
		}
		byID[candidate] = clientmodel.Observation{CandidateID: candidate, NetworkGeneration: state.NetworkGeneration,
			Scope: scope, Result: outcome, Action: action, ObservedAt: now.UTC().Format(time.RFC3339),
			ValidUntil: now.Add(lifetime).UTC().Format(time.RFC3339), MetricMillis: metric}
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
		if selected[scope] == BlockedSelection {
			continue
		}
		candidate := byID[selected[scope]]
		statuses = append(statuses, SelectionStatus{Scope: scope, CandidateID: candidate.ID, FinalExit: candidate.FinalExit,
			Chain: append([]string(nil), candidate.Chain...), State: observationState(observations, candidate.ID, generation, now)})
	}
	return statuses
}

// Activate applies the shared pure selection, accepts only selector readback as
// Selection, and performs at most one normal probe plus one necessary fallback.
func activate(ctx context.Context, selector Selector, routes []clientmodel.RouteCandidate, state State,
	probe Probe, now func() time.Time) (Activation, error) {
	scopes, _, err := Scopes(routes)
	if err != nil {
		return Activation{}, err
	}
	if probe != nil && len(scopes) != 1 {
		return Activation{}, errors.New("one business probe requires exactly one Service scope")
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
	readback, err := ApplySelections(ctx, selector, desired)
	if err != nil {
		return Activation{}, err
	}
	if len(selectionStatuses(routes, state.Observations, readback, state.NetworkGeneration, at)) == 0 && len(scopes) != 0 {
		return Activation{State: state, Selections: []SelectionStatus{}}, clientmodel.ErrNoUsableCandidate
	}
	if probe == nil || !missingObservation(readback, state.Observations, state.NetworkGeneration, at) {
		return Activation{State: state, Selections: selectionStatuses(routes, state.Observations, readback, state.NetworkGeneration, at)}, nil
	}
	first := probe(ctx)
	if err := ctx.Err(); err != nil {
		return Activation{State: state, Selections: selectionStatuses(routes, state.Observations, readback, state.NetworkGeneration, at)}, err
	}
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
	readback, err = ApplySelections(ctx, selector, fallback)
	if err != nil {
		return Activation{}, err
	}
	if len(selectionStatuses(routes, state.Observations, readback, state.NetworkGeneration, at)) == 0 {
		return Activation{State: state, Selections: []SelectionStatus{}}, clientmodel.ErrNoUsableCandidate
	}
	secondAt := now().UTC().Truncate(time.Second)
	second := probe(ctx)
	if err := ctx.Err(); err != nil {
		return Activation{State: state, Selections: selectionStatuses(routes, state.Observations, readback, state.NetworkGeneration, secondAt)}, err
	}
	state = recordOutcome(state, readback, second, secondAt)
	activation := Activation{State: state,
		Selections: selectionStatuses(routes, state.Observations, readback, state.NetworkGeneration, secondAt)}
	if !second.Available {
		for scope := range readback {
			readback[scope] = BlockedSelection
		}
		if _, err := ApplySelections(ctx, selector, readback); err != nil {
			return Activation{}, err
		}
		activation.Selections = []SelectionStatus{}
		return activation, clientmodel.ErrNoUsableCandidate
	}
	return activation, nil
}

// Activate returns rejected scopes separately from genuine candidate selections.
// They are a disposable readback of the local selector, never report authority.
func Activate(ctx context.Context, selector Selector, routes []clientmodel.RouteCandidate, state State,
	probe Probe, now func() time.Time) (Activation, error) {
	result, err := activate(ctx, selector, routes, state, probe, now)
	if result.State.NetworkGeneration == "" || ctx.Err() != nil {
		return result, err
	}
	scopes, _, scopeErr := Scopes(routes)
	if scopeErr != nil {
		return Activation{}, scopeErr
	}
	for _, scope := range scopes {
		actual, readErr := selector.Read(ctx, scope)
		if readErr != nil {
			return Activation{}, readErr
		}
		if actual == BlockedSelection {
			result.BlockedScopes = append(result.BlockedScopes, scope)
			continue
		}
		found := false
		for _, selection := range result.Selections {
			found = found || selection.Scope == scope && selection.CandidateID == actual
		}
		if !found {
			return Activation{}, errors.New("Service selector changed after application")
		}
	}
	return result, err
}

// ActivateServices keeps each Service's outcome and failure recovery separate.
// Probe factories return nil where no unique authenticated target exists.
func ActivateServices(ctx context.Context, selector Selector, routes []clientmodel.RouteCandidate, state State,
	probeForScope func(string) Probe, now func() time.Time) (Activation, error) {
	scopes, byScope, err := Scopes(routes)
	if err != nil {
		return Activation{}, err
	}
	result := Activation{State: state, Selections: []SelectionStatus{}, BlockedScopes: []string{}}
	var outcomes []error
	for _, scope := range scopes {
		var probe Probe
		if probeForScope != nil {
			probe = probeForScope(scope)
		}
		next, err := Activate(ctx, selector, byScope[scope], result.State, probe, now)
		if next.State.NetworkGeneration == "" {
			return Activation{}, err
		}
		result.State = next.State
		result.Selections = append(result.Selections, next.Selections...)
		result.BlockedScopes = append(result.BlockedScopes, next.BlockedScopes...)
		if err != nil {
			outcomes = append(outcomes, err)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return result, errors.Join(outcomes...)
}

func observationState(observations []clientmodel.Observation, candidateID, generation string, now time.Time) string {
	for _, observation := range observations {
		until, _ := time.Parse(time.RFC3339, observation.ValidUntil)
		if observation.CandidateID == candidateID && observation.NetworkGeneration == generation && now.Before(until) {
			return observation.Result
		}
	}
	return "unknown"
}
