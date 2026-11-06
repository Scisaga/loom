package loomcore

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/deviceclient"
	"loom/protocol"
)

type runtimeApplication struct {
	Schema             int                                    `json:"schema"`
	PolicyID           string                                 `json:"policy_id,omitempty"`
	ServiceID          string                                 `json:"service_id,omitempty"`
	Selections         []runtimeSelection                     `json:"selections"`
	BlockedScopes      []string                               `json:"blocked_scopes"`
	Memory             map[string]clientmodel.SelectionMemory `json:"memory"`
	LANPolicyIDs       map[string]string                      `json:"lan_policy_ids,omitempty"`
	NativeObservations []clientmodel.Observation              `json:"native_observations"`
	NativeFixedExit    bool                                   `json:"native_fixed_exit"`
}

type runtimeSelection struct {
	PolicyID          string                          `json:"policy_id"`
	Choices           map[string]protocol.RouteChoice `json:"choices"`
	ExpectedPolicyID  string                          `json:"expected_policy_id"`
	ExpectedChoices   map[string]protocol.RouteChoice `json:"expected_choices"`
	ExpectedRevision  string                          `json:"expected_revision"`
	Selector          string                          `json:"selector"`
	Candidate         string                          `json:"candidate"`
	FinalExit         string                          `json:"final_exit"`
	Chain             []string                        `json:"chain,omitempty"`
	State             string                          `json:"state"`
	Targets           map[string]string               `json:"targets"`
	ExpectedCandidate string                          `json:"expected_candidate"`
	ExpectedTargets   map[string]string               `json:"expected_targets"`
	ForceCAS          bool                            `json:"force_cas"`
}

// EvaluateAndroidRoutes computes from the current protected identity. Graphs,
// candidates, Policy and target scopes remain in Go instead of crossing the
// host bridge as repeated per-Policy JSON. It performs no I/O or state writes.
func EvaluateAndroidRoutes(stateBody, observationsBody, currentBody []byte,
	generation string, nowMS int64, resourcesBody, linksBody, memoryBody []byte, monotonicMS int64, nativeBody, nativeEventsBody []byte) ([]byte, error) {
	identity, err := decodeState(stateBody)
	if err != nil {
		return nil, err
	}
	if identity.LKG == nil {
		return nil, errors.New("no accepted Android authorization")
	}
	preference := androidPreference(identity)
	selected := clientmodel.MeasurementPolicies(preference)
	view := identity.LKG.View
	routes, graphs, err := clientadapter.AccessRoutingInputs(view, selected)
	if err != nil {
		return nil, err
	}
	state, current, err := decodeAndroidRoutingSamples(observationsBody, currentBody, resourcesBody, linksBody, memoryBody, generation)
	if err != nil {
		return nil, err
	}
	state.Preference, state.Graphs = preference, graphs
	state.NativeExecutionSpec, err = clientadapter.NativeExecutionSpec(view, routes, graphs, preference.PolicyID)
	if err != nil {
		return nil, err
	}
	if len(nativeBody) > 0 {
		if err := decodeStrictJSON(nativeBody, clientadapter.NativeObservationReadbackLimit, &state.NativeObservations); err != nil {
			return nil, err
		}
	}
	if len(nativeEventsBody) == 0 || !clientadapter.NativeBindingMatches(state.SelectionMemory[control.AccessSelectorScope], current[control.AccessSelectorScope], generation, state.NativeExecutionSpec) {
		nativeEventsBody = []byte(`{"observations":[]}`)
	}
	state.NativeObservations, err = clientadapter.ConsumeNativeObservations(nativeEventsBody, state, routes, time.UnixMilli(nowMS))
	if err != nil {
		return nil, err
	}
	targets := map[string][]string{}
	for _, policy := range view.Policies {
		if policy.ID != preference.PolicyID {
			continue
		}
		for _, service := range view.Services {
			if service.ID == policy.ServiceID {
				targets[service.Scope()] = service.ProbeURLs
				break
			}
		}
		break
	}
	return evaluateAndroidRouting(routes, state, current, clientmodel.SelectorScopes(view), targets, nowMS, monotonicMS)
}

func decodeAndroidRoutingSamples(observationsBody, currentBody, resourcesBody, linksBody, memoryBody []byte, generation string) (clientadapter.State, map[string]clientmodel.Selection, error) {
	state := clientadapter.State{NetworkGeneration: generation}
	current := map[string]clientmodel.Selection{}
	if len(linksBody) > 0 {
		if err := decodeStrictJSON(linksBody, androidMeasurementSnapshotLimit, &state.LinkObservations); err != nil {
			return state, nil, err
		}
	}
	if len(resourcesBody) > 0 {
		if err := decodeStrictJSON(resourcesBody, clientadapter.ResourceObservationCacheLimit, &state.ResourceObservations); err != nil {
			return state, nil, err
		}
	}
	if len(observationsBody) == 0 {
		observationsBody = []byte("[]")
	}
	var measured []androidObservation
	if err := decodeStrictJSON(observationsBody, 1<<20, &measured); err != nil {
		return state, nil, err
	}
	for _, item := range measured {
		metric := int64(0)
		if item.MetricMillis != nil {
			metric = *item.MetricMillis
		}
		state.Observations = append(state.Observations, clientmodel.Observation{CandidateID: item.CandidateID, Target: item.Target, NetworkGeneration: item.NetworkGeneration, Scope: item.Scope, Result: item.Result, Action: item.Action, ObservedAt: item.ObservedAt, ValidUntil: item.ValidUntil, MetricMillis: metric})
	}
	if len(currentBody) > 0 {
		if err := decodeStrictJSON(currentBody, 1<<20, &current); err != nil {
			return state, nil, err
		}
	}
	if len(memoryBody) > 0 {
		if err := decodeStrictJSON(memoryBody, 1<<20, &state.SelectionMemory); err != nil {
			return state, nil, err
		}
	}
	return state, current, nil
}

func evaluateAndroidRouting(routes []clientmodel.RouteCandidate, state clientadapter.State, current map[string]clientmodel.Selection, explicitScopes []string, targetsByScope map[string][]string, nowMS, monotonicMS int64) ([]byte, error) {
	now := time.UnixMilli(nowMS)
	if nowMS <= 0 || now.Year() > 9999 {
		return nil, errors.New("invalid selection time")
	}
	routes, err := clientmodel.EstimateRoutePaths(routes, state.Graphs, state.ResourceObservations, state.LinkObservations, state.NetworkGeneration, now.UTC())
	if err != nil {
		return nil, err
	}
	scopes, byScope, err := clientadapter.Scopes(routes, explicitScopes...)
	if err != nil {
		return nil, err
	}
	application := runtimeApplication{Schema: 3, PolicyID: state.Preference.PolicyID, LANPolicyIDs: state.Preference.LANPolicyIDs, Selections: []runtimeSelection{}, BlockedScopes: []string{}, Memory: map[string]clientmodel.SelectionMemory{}, NativeObservations: state.NativeObservations}
	for _, route := range routes {
		if route.PolicyID == state.Preference.PolicyID {
			application.NativeFixedExit = route.FixedExit
			break
		}
	}
	var selectedTargets []string
	for _, route := range routes {
		if route.PolicyID == state.Preference.PolicyID {
			_, application.ServiceID, _ = strings.Cut(route.Scope, ":")
			selectedTargets = targetsByScope[route.Scope]
			break
		}
	}
	for _, scope := range scopes {
		actual := current[scope]
		actual.Scope = scope
		if actual.Choices == nil {
			actual.Choices = map[string]protocol.RouteChoice{}
		}
		if actual.Targets == nil {
			actual.Targets = map[string]string{}
		}
		scopeTargets := selectedTargets
		if scope != control.AccessSelectorScope {
			scopeTargets = nil
		}
		selection, nextMemory, err := clientmodel.ChooseWithNativeStability(byScope[scope], state.Observations, state.NativeObservations, state.ResourceObservations, state.LinkObservations, clientmodel.PolicyForSelector(state.Preference, scope), actual, state.SelectionMemory[scope], state.NetworkGeneration, now.UTC(), monotonicMS, clientmodel.DefaultPerformanceRule, scopeTargets...)
		if errors.Is(err, clientmodel.ErrNoUsableCandidate) {
			application.BlockedScopes = append(application.BlockedScopes, scope)
			continue
		}
		if err != nil {
			return nil, err
		}
		forceCAS := scope == control.AccessSelectorScope && state.NativeExecutionSpec != "" && !clientadapter.NativeBindingMatches(state.SelectionMemory[scope], actual, state.NetworkGeneration, state.NativeExecutionSpec)
		if scope == control.AccessSelectorScope && state.NativeExecutionSpec != "" {
			nextMemory.NativeBinding = &clientmodel.NativeBinding{NetworkGeneration: state.NetworkGeneration, ExecutionSpec: state.NativeExecutionSpec}
			nextMemory, _ = clientadapter.RefreshNativeHealth(nextMemory, state.NativeObservations, now)
		}
		application.Memory[scope] = nextMemory
		var chain []string
		var finalExit string
		observationState := "unknown"
		for _, route := range byScope[scope] {
			if route.ID == selection.CandidateID {
				chain = append([]string(nil), route.Chain...)
				finalExit = route.FinalExit
				break
			}
		}
		observationState, err = clientmodel.ObservationState(state.Observations, selection.CandidateID, scope, state.NetworkGeneration, scopeTargets, now)
		if err != nil {
			return nil, err
		}
		application.Selections = append(application.Selections, runtimeSelection{Selector: scope, PolicyID: selection.PolicyID, Choices: selection.Choices, ExpectedPolicyID: actual.PolicyID, ExpectedChoices: actual.Choices,
			Candidate: selection.CandidateID, FinalExit: finalExit, Chain: chain, State: observationState, Targets: selection.Targets, ExpectedCandidate: actual.CandidateID, ExpectedTargets: actual.Targets, ExpectedRevision: actual.Revision, ForceCAS: forceCAS})
	}
	return json.Marshal(application)
}

// AndroidCachedResourceObservations decodes a disposable cache using the owner
// binding in the accepted profile projection. Selection still matches each
// sample to the current candidate's exact first-hop execution reference.
func AndroidCachedResourceObservations(body []byte, identity, generation string) ([]byte, error) {
	if len(body) == 0 {
		return []byte("[]"), nil
	}
	values, err := clientadapter.ReadResourceObservationCache(body, identity, generation)
	if err != nil {
		return nil, err
	}
	return json.Marshal(values)
}

// MergeAndroidResourceObservations consumes a completion delta using the public
// cache binding. Actual selection still checks the current execution specs.
func MergeAndroidResourceObservations(previous, completed []byte, identity, generation string) ([]byte, error) {
	values := []control.Observation{}
	var err error
	if len(previous) != 0 {
		values, err = clientadapter.ReadResourceObservationCache(previous, identity, generation)
		if err != nil {
			return nil, err
		}
	}
	updates, err := clientadapter.ReadResourceObservationCache(completed, identity, generation)
	if err != nil {
		return nil, err
	}
	return clientadapter.EncodeResourceObservationCache(identity, clientadapter.MergeNodeMeasurements(values, updates))
}

// AndroidPreference is a read-only projection of the sole identity record.
func AndroidPreference(stateBody []byte) ([]byte, error) {
	state, err := decodeState(stateBody)
	if err != nil {
		return nil, err
	}
	if state.LKG == nil || state.Preference == nil {
		return nil, errors.New("no authenticated Android configuration")
	}
	return control.CanonicalEncode(*state.Preference)
}

// ChooseAndroidPolicy updates the one identity value; callers persist and read
// back these bytes through the normal identity store before applying selectors.
func ChooseAndroidPolicy(stateBody []byte, policyID string) ([]byte, error) {
	state, err := decodeState(stateBody)
	if err != nil {
		return nil, err
	}
	if state.LKG == nil || state.Preference == nil {
		return nil, errors.New("no authenticated Android configuration")
	}
	next, err := clientmodel.ChoosePolicy(*state.Preference, state.LKG.View, policyID)
	if err != nil {
		return nil, err
	}
	state.Preference = &next
	return deviceclient.EncodeIdentityState(state)
}

// ConfirmAndroidSelectionMemory is called only after complete native readback.
// This disposable value is never committed to the protected identity record.
func ConfirmAndroidSelectionMemory(memoryBody, selectionBody []byte, monotonicMS int64) ([]byte, error) {
	var memory map[string]clientmodel.SelectionMemory
	var actual clientmodel.Selection
	if err := decodeStrictJSON(memoryBody, 1<<20, &memory); err != nil {
		return nil, err
	}
	if err := decodeStrictJSON(selectionBody, 1<<20, &actual); err != nil {
		return nil, err
	}
	scopeMemory, exists := memory[actual.Scope]
	if !exists || !clientmodel.ValidSelectorScope(actual.Scope) {
		return nil, errors.New("selection has no proposed scope memory")
	}
	next, err := clientmodel.ConfirmSelection(scopeMemory, actual, monotonicMS)
	if err != nil {
		return nil, err
	}
	if scopeMemory.NativeBinding != nil {
		next = clientadapter.BindNativeSelection(next, actual, scopeMemory.NativeBinding.NetworkGeneration, scopeMemory.NativeBinding.ExecutionSpec)
	}
	memory[actual.Scope] = next
	return json.Marshal(memory)
}

// AndroidSelectedRoutes derives choices from the current saved intent without
// serializing a new native configuration or changing authorization progress.
func AndroidSelectedRoutes(stateBody []byte) ([]byte, error) {
	state, err := decodeState(stateBody)
	if err != nil {
		return nil, err
	}
	if state.LKG == nil {
		return nil, errors.New("no accepted Android authorization")
	}
	routes, err := clientadapter.AccessCandidates(state.LKG.View, clientmodel.MeasurementPolicies(androidPreference(state)))
	if err != nil {
		return nil, err
	}
	return json.Marshal(routes)
}

// ServiceConnectionIDs projects the native snapshot's pinned Service ownership.
// It performs no I/O, changes no preference and grants no network permission.
func ServiceConnectionIDs(body []byte, serviceID, scope string) ([]byte, error) {
	ids, err := clientadapter.ServiceConnectionIDs(body, serviceID, scope)
	if err != nil {
		return nil, err
	}
	return json.Marshal(ids)
}
