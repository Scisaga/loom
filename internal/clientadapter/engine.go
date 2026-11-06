package clientadapter

import (
	"context"
	"errors"
	"maps"
	"sort"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"
)

type State struct {
	Graphs            []clientmodel.PolicyGraph
	Preference        clientmodel.Preference
	NetworkGeneration string
	Observations      []clientmodel.Observation
	// Ordinary TCP outcomes and their execution binding are RAM-only. They
	// never enter the probe cache or the signed measurement report.
	NativeObservations   []clientmodel.Observation
	NativeExecutionSpec  string
	ResourceObservations []control.Observation
	LinkObservations     []control.DeviceLinkObservation
	LocalMeasurements    []control.Observation
	SelectionMemory      map[string]clientmodel.SelectionMemory
}

type SelectionStatus struct {
	Scope       string            `json:"scope"`
	CandidateID string            `json:"candidate_id"`
	PolicyID    string            `json:"policy_id"`
	FinalExit   string            `json:"final_exit"`
	Chain       []string          `json:"chain,omitempty"`
	State       string            `json:"state"`
	Targets     map[string]string `json:"targets"`
}

type ProbeResult struct {
	Deferred    bool
	Available   bool
	Metric      time.Duration
	Description string
	Action      string
	Target      string
}

type Probe func(context.Context) ProbeResult

type Activation struct {
	State         State
	Selections    []SelectionStatus
	BlockedScopes []string
}

// MeasurementCandidates is a one-way projection of confirmed use and pending
// improvements. The node scheduler validates these hints against its View.
func MeasurementCandidates(selections []SelectionStatus, memory map[string]clientmodel.SelectionMemory, generation string) []string {
	values := map[string]bool{}
	for _, value := range selections {
		current := clientmodel.Selection{Scope: value.Scope, PolicyID: value.PolicyID, CandidateID: value.CandidateID, Targets: value.Targets}
		for _, id := range clientmodel.MeasurementCandidates(current, memory[value.Scope], generation) {
			values[id] = true
		}
	}
	result := make([]string, 0, len(values))
	for id := range values {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

const BlockedSelection = "reject"

func Scopes(routes []clientmodel.RouteCandidate, scopeIDs ...string) ([]string, map[string][]clientmodel.RouteCandidate, error) {
	byScope := map[string][]clientmodel.RouteCandidate{}
	for _, scope := range scopeIDs {
		if !clientmodel.ValidSelectorScope(scope) {
			return nil, nil, errors.New("unexpected access selector scope")
		}
		byScope[scope] = []clientmodel.RouteCandidate{}
	}
	for _, route := range routes {
		if err := route.Validate(); err != nil {
			return nil, nil, err
		}
		scope := clientmodel.CandidateSelectorScope(route)
		byScope[scope] = append(byScope[scope], route)
	}
	scopes := make([]string, 0, len(byScope))
	for scope := range byScope {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)

	return scopes, byScope, nil
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
		statuses = append(statuses, SelectionStatus{Scope: scope, CandidateID: candidate.ID, PolicyID: candidate.PolicyID, FinalExit: candidate.FinalExit,
			Chain: append([]string(nil), candidate.Chain...), State: state})
	}
	return statuses
}

// Activate applies one Policy's shared-evidence recommendation. It performs
// no URL probes, full-path scans or per-Service request loops.
func Activate(ctx context.Context, selector Selector, routes []clientmodel.RouteCandidate, state State,
	targets []string, now func() time.Time, scopeIDs ...string) (Activation, error) {
	result := Activation{State: state, Selections: []SelectionStatus{}, BlockedScopes: []string{}}
	scopes, _, err := Scopes(routes, scopeIDs...)
	if err != nil {
		return result, err
	}
	transport := append(append([]control.Observation{}, state.ResourceObservations...), state.LocalMeasurements...)
	routes, err = clientmodel.EstimateRoutePaths(routes, state.Graphs, transport, state.LinkObservations, state.NetworkGeneration, now())
	if err != nil {
		return result, err
	}
	_, byScope, err := Scopes(routes, scopeIDs...)
	if err != nil {
		return result, err
	}
	memories := maps.Clone(state.SelectionMemory)
	if memories == nil {
		memories = map[string]clientmodel.SelectionMemory{}
	}
	unavailableAny := false
	for _, scope := range scopes {
		current, err := selector.ReadSelection(ctx, scope)
		if err != nil {
			return result, err
		}
		if scope == control.AccessSelectorScope && state.NativeExecutionSpec != "" {
			body := []byte(`{"observations":[]}`)
			if reader, ok := selector.(interface {
				ReadNativeObservations(context.Context) ([]byte, error)
			}); ok && NativeBindingMatches(memories[scope], current, state.NetworkGeneration, state.NativeExecutionSpec) {
				if completed, readErr := reader.ReadNativeObservations(ctx); readErr == nil {
					body = completed
				} else if ctx.Err() != nil {
					return result, ctx.Err()
				}
			}
			state.NativeObservations, err = ConsumeNativeObservations(body, state, routes, now())
			if err != nil {
				return result, err
			}
			result.State.NativeObservations = state.NativeObservations
		}
		probeTargets := targets
		if scope != control.AccessSelectorScope {
			probeTargets = nil
		}
		preference := clientmodel.PolicyForSelector(state.Preference, scope)
		desired, memory, err := clientmodel.ChooseWithNativeStability(byScope[scope], state.Observations, state.NativeObservations, transport, state.LinkObservations, preference, current, memories[scope], state.NetworkGeneration, now(), selector.ElapsedMillis(), clientmodel.DefaultPerformanceRule, probeTargets...)
		unavailable := errors.Is(err, clientmodel.ErrNoUsableCandidate)
		if unavailable {
			desired = clientmodel.Selection{Scope: scope, CandidateID: BlockedSelection, Targets: map[string]string{}, Choices: map[string]protocol.RouteChoice{}}
		} else if err != nil {
			return result, err
		}
		expectedRevision := current.Revision
		refreshBinding := scope == control.AccessSelectorScope && desired.CandidateID != BlockedSelection && state.NativeExecutionSpec != "" && !NativeBindingMatches(memories[scope], current, state.NetworkGeneration, state.NativeExecutionSpec)
		if !SameSelection(current, desired) || refreshBinding {
			applied, err := selector.ApplySelection(ctx, current, desired)
			if err != nil {
				return result, err
			}
			if !SameSelection(applied, desired) || applied.Revision == current.Revision {
				return result, ErrSelectionSuperseded
			}
			expectedRevision = applied.Revision
		}
		actual, err := selector.ReadSelection(ctx, scope)
		if err != nil {
			return result, err
		}
		if !SameSelection(actual, desired) || actual.Revision != expectedRevision {
			return result, ErrSelectionSuperseded
		}
		if !unavailable {
			memory, err = clientmodel.ConfirmSelection(memory, actual, selector.ElapsedMillis())
			if err != nil {
				return result, err
			}
			memory = BindNativeSelection(memory, actual, state.NetworkGeneration, state.NativeExecutionSpec)
			if scope == control.AccessSelectorScope {
				memory, _ = RefreshNativeHealth(memory, state.NativeObservations, now())
			}
			memories[scope] = memory
		}
		if actual.CandidateID == BlockedSelection {
			result.BlockedScopes = append(result.BlockedScopes, scope)
			unavailableAny = true
			continue
		}
		statuses := selectionStatuses(routes, state.Observations, map[string]string{scope: actual.CandidateID}, state.NetworkGeneration, now(), probeTargets...)
		if len(statuses) != 1 || statuses[0].CandidateID == "" {
			return result, errors.New("actual selector candidate is outside the accepted scope")
		}
		statuses[0].Targets = actual.Targets
		result.Selections = append(result.Selections, statuses[0])
	}
	result.State.SelectionMemory = memories
	if unavailableAny {
		return result, clientmodel.ErrNoUsableCandidate
	}
	return result, nil
}
