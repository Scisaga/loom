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
	Target      string
}

type Probe func(context.Context) ProbeResult

// Probes contains only targets projected from this Service in the accepted View.
// A nil function keeps the target scope while deferring its network operation.
type Probes map[string]Probe

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

func selectAll(routes []clientmodel.RouteCandidate, observations []clientmodel.Observation, resources []control.Observation,
	preference clientmodel.Preference, current map[string]string, generation string, now time.Time, targets ...string) (map[string]string, error) {
	scopes, byScope, err := Scopes(routes)
	if err != nil {
		return nil, err
	}
	desired := make(map[string]string, len(scopes))
	for _, scope := range scopes {
		selection, err := clientmodel.Select(byScope[scope], observations, resources, preference, current[scope], generation, now, targets...)
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

func recordOutcome(state State, selections map[string]string, result ProbeResult, now time.Time) State {
	action := result.Action
	if action == "" {
		action = "tcp_udp_dns"
	}
	byID := map[string]clientmodel.Observation{}
	for _, observation := range state.Observations {
		byID[observation.Key()] = observation
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
		observation := clientmodel.Observation{CandidateID: candidate, Target: result.Target, NetworkGeneration: state.NetworkGeneration,
			Scope: scope, Result: outcome, Action: action, ObservedAt: now.UTC().Format(time.RFC3339),
			ValidUntil: now.Add(lifetime).UTC().Format(time.RFC3339), MetricMillis: metric}
		byID[observation.Key()] = observation
	}
	state.Observations = make([]clientmodel.Observation, 0, len(byID))
	for _, observation := range byID {
		state.Observations = append(state.Observations, observation)
	}
	sort.Slice(state.Observations, func(i, j int) bool {
		return state.Observations[i].Key() < state.Observations[j].Key()
	})
	return state
}

func selectionStatuses(routes []clientmodel.RouteCandidate, observations []clientmodel.Observation,
	selected map[string]string, generation string, now time.Time, targets ...string) []SelectionStatus {
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
		state, _ := clientmodel.ObservationState(observations, candidate.ID, scope, generation, targets, now)
		statuses = append(statuses, SelectionStatus{Scope: scope, CandidateID: candidate.ID, FinalExit: candidate.FinalExit,
			Chain: append([]string(nil), candidate.Chain...), State: state})
	}
	return statuses
}

// activate samples only the current path, and at most one necessary fallback.
func activate(ctx context.Context, selector Selector, routes []clientmodel.RouteCandidate, state State,
	probes Probes, now func() time.Time) (Activation, error) {
	scopes, _, err := Scopes(routes)
	if err != nil {
		return Activation{}, err
	}
	if len(probes) > 0 && len(scopes) != 1 {
		return Activation{}, errors.New("business probes require exactly one Service scope")
	}
	targets := make([]string, 0, len(probes))
	for target := range probes {
		if target != "" && control.ValidateHTTPSURL(target) != nil {
			return Activation{}, errors.New("invalid business probe target")
		}
		targets = append(targets, target)
	}
	sort.Strings(targets)
	current, err := currentReadback(ctx, selector, scopes)
	if err != nil {
		return Activation{}, err
	}
	at := now().UTC()
	desired, err := selectAll(routes, state.Observations, state.ResourceObservations, state.Preference, current, state.NetworkGeneration, at, targets...)
	if err != nil {
		return Activation{}, err
	}
	readback, err := ApplySelections(ctx, selector, desired)
	if err != nil {
		return Activation{}, err
	}
	result := func() Activation {
		return Activation{State: state, Selections: selectionStatuses(routes, state.Observations, readback, state.NetworkGeneration, now().UTC(), targets...)}
	}
	for attempt := 0; attempt < 2; attempt++ {
		if len(result().Selections) == 0 && len(scopes) > 0 {
			return result(), clientmodel.ErrNoUsableCandidate
		}
		if len(probes) == 0 {
			return result(), nil
		}
		scope := scopes[0]
		candidate := readback[scope]
		for _, target := range targets {
			if probes[target] == nil {
				continue
			}
			sample, found, err := clientmodel.LatestObservation(state.Observations, candidate, scope, state.NetworkGeneration, target)
			if err != nil {
				return result(), err
			}
			if found && sample.CurrentAt(now()) {
				continue
			}
			outcome := probes[target](ctx)
			if err := ctx.Err(); err != nil {
				return result(), err
			}
			// User preference changes while the request is in flight invalidate
			// this attribution; never report the new path as the sampled path.
			actual, err := selector.Read(ctx, scope)
			if err != nil {
				return result(), err
			}
			if actual != candidate {
				return result(), errors.New("Service selection changed during its probe")
			}
			outcome.Target = target
			state = recordOutcome(state, readback, outcome, now().UTC().Truncate(time.Second))
		}
		at = now().UTC()
		status, err := clientmodel.ObservationState(state.Observations, candidate, scope, state.NetworkGeneration, targets, at)
		if err != nil {
			return result(), err
		}
		if status != "unavailable" {
			return result(), nil
		}
		fallback := map[string]string{scope: BlockedSelection}
		if attempt == 0 {
			fallback, err = selectAll(routes, state.Observations, state.ResourceObservations, state.Preference, readback, state.NetworkGeneration, at, targets...)
			if err != nil {
				return result(), err
			}
		}
		readback, err = ApplySelections(ctx, selector, fallback)
		if err != nil {
			return Activation{}, err
		}
	}
	return result(), clientmodel.ErrNoUsableCandidate
}

// Activate returns rejected scopes separately from genuine candidate selections.
// They are a disposable readback of the local selector, never report authority.
func Activate(ctx context.Context, selector Selector, routes []clientmodel.RouteCandidate, state State,
	probe Probes, now func() time.Time) (Activation, error) {
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
// Probe factories return nil where no authenticated target exists.
func ActivateServices(ctx context.Context, selector Selector, routes []clientmodel.RouteCandidate, state State,
	probeForScope func(string) Probes, now func() time.Time) (Activation, error) {
	scopes, byScope, err := Scopes(routes)
	if err != nil {
		return Activation{}, err
	}
	result := Activation{State: state, Selections: []SelectionStatus{}, BlockedScopes: []string{}}
	var outcomes []error
	for _, scope := range scopes {
		var probe Probes
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
