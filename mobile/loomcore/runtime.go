package loomcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

type runtimeApplication struct {
	Schema        int                    `json:"schema"`
	PolicyChoices []control.PolicyChoice `json:"policy_choices"`
	Selections    []runtimeSelection     `json:"selections"`
	BlockedScopes []string               `json:"blocked_scopes"`
}

type runtimeSelection struct {
	Selector  string   `json:"selector"`
	Candidate string   `json:"candidate"`
	FinalExit string   `json:"final_exit"`
	Chain     []string `json:"chain,omitempty"`
	State     string   `json:"state"`
}

// EvaluateAndroidRoutes applies one Preference to every authorized scope. It performs no I/O.
func EvaluateAndroidRoutes(routesBody, observationsBody, preferenceBody, currentBody []byte,
	generation, nowRFC3339 string, targetsBody, resourcesBody, linksBody, scopesBody []byte) ([]byte, error) {
	var links []control.DeviceLinkObservation
	if len(linksBody) > 0 {
		if err := decodeStrictJSON(linksBody, 4<<20, &links); err != nil {
			return nil, err
		}
	}
	var resources []control.Observation
	if len(resourcesBody) > 0 {
		if err := decodeStrictJSON(resourcesBody, clientadapter.ResourceObservationCacheLimit, &resources); err != nil {
			return nil, err
		}
	}
	var groups []control.ServiceProbeTargets
	if len(targetsBody) > 0 {
		if err := decodeStrictJSON(targetsBody, 1<<20, &groups); err != nil {
			return nil, err
		}
	}
	targetsByScope := map[string][]string{}
	for _, group := range groups {
		if control.ValidateID(group.ServiceID) != nil {
			return nil, errors.New("invalid Service probe group")
		}
		if _, exists := targetsByScope["service:"+group.ServiceID]; exists {
			return nil, errors.New("duplicate Service probe group")
		}
		for _, target := range group.Targets {
			if control.ValidateHTTPSURL(target) != nil {
				return nil, errors.New("invalid Service probe target")
			}
		}
		targetsByScope["service:"+group.ServiceID], targetsByScope["local_network:"+group.ServiceID] = group.Targets, group.Targets
	}
	var routes []clientmodel.RouteCandidate
	var measured []androidObservation
	var observations []clientmodel.Observation
	var preference clientmodel.Preference
	current := map[string]string{}
	if err := decodeStrictJSON(routesBody, 1<<20, &routes); err != nil {
		return nil, fmt.Errorf("Android route projection: %w", err)
	}
	if len(observationsBody) == 0 {
		observationsBody = []byte("[]")
	}
	if err := decodeStrictJSON(observationsBody, 1<<20, &measured); err != nil {
		return nil, err
	}
	for _, item := range measured {
		metric := int64(0)
		if item.MetricMillis != nil {
			metric = *item.MetricMillis
		}
		observations = append(observations, clientmodel.Observation{CandidateID: item.CandidateID, Target: item.Target, NetworkGeneration: item.NetworkGeneration, Scope: item.Scope, Result: item.Result, Action: item.Action, ObservedAt: item.ObservedAt, ValidUntil: item.ValidUntil, MetricMillis: metric})
	}
	if len(preferenceBody) == 0 {
		preferenceBody, _ = control.CanonicalEncode(clientmodel.EmptyPreference())
	}
	if err := control.DecodeCanonical(preferenceBody, &preference, control.ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 8, MaxItems: 1024}); err != nil {
		return nil, err
	}
	if len(currentBody) > 0 {
		if err := decodeStrictJSON(currentBody, 1<<20, &current); err != nil {
			return nil, err
		}
	}
	now, err := time.Parse(time.RFC3339, nowRFC3339)
	if err != nil || now.UTC().Format(time.RFC3339) != nowRFC3339 {
		return nil, errors.New("invalid selection time")
	}
	byScope := map[string][]clientmodel.RouteCandidate{}
	var explicitScopes []string
	if len(scopesBody) > 0 {
		if err := decodeStrictJSON(scopesBody, 1<<20, &explicitScopes); err != nil {
			return nil, err
		}
	}
	for _, scope := range explicitScopes {
		byScope[scope] = []clientmodel.RouteCandidate{}
	}
	for _, route := range routes {
		if err := route.Validate(); err != nil {
			return nil, err
		}
		byScope[route.Scope] = append(byScope[route.Scope], route)

	}
	scopes := make([]string, 0, len(byScope))
	for scope := range byScope {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	application := runtimeApplication{Schema: 3, PolicyChoices: append([]control.PolicyChoice{}, preference.Services...), Selections: []runtimeSelection{}, BlockedScopes: []string{}}
	for _, scope := range scopes {
		selection, err := clientmodel.SelectWithLinks(byScope[scope], observations, resources, links, preference, current[scope], generation, now.UTC(), targetsByScope[scope]...)
		if errors.Is(err, clientmodel.ErrNoUsableCandidate) {
			application.BlockedScopes = append(application.BlockedScopes, scope)
			continue
		}
		if err != nil {
			return nil, err
		}
		var chain []string
		var finalExit string
		state := "unknown"
		for _, route := range byScope[scope] {
			if route.ID == selection.CandidateID {
				chain = append([]string(nil), route.Chain...)
				finalExit = route.FinalExit
				break
			}
		}
		state, err = clientmodel.ObservationState(observations, selection.CandidateID, scope, generation, targetsByScope[scope], now)
		if err != nil {
			return nil, err
		}
		application.Selections = append(application.Selections, runtimeSelection{Selector: scope,
			Candidate: selection.CandidateID, FinalExit: finalExit, Chain: chain, State: state})
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

// ReconcileAndroidPreference initializes choices from the authenticated identity only.
func ReconcileAndroidPreference(stateBody, preferenceBody []byte) ([]byte, error) {
	state, err := decodeState(stateBody)
	if err != nil {
		return nil, err
	}
	if state.LKG == nil {
		return nil, errors.New("no authenticated Android configuration")
	}
	preference := clientmodel.EmptyPreference()
	if len(preferenceBody) != 0 {
		if err := control.DecodeCanonical(preferenceBody, &preference, control.ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 8, MaxItems: 4096}); err != nil {
			return nil, err
		}
	}
	next, err := clientmodel.ReconcilePreference(preference, state.LKG.View)
	if err != nil {
		return nil, err
	}
	return control.CanonicalEncode(next)
}

func ChooseAndroidPolicy(stateBody, preferenceBody []byte, serviceID, policyID string) ([]byte, error) {
	state, err := decodeState(stateBody)
	if err != nil {
		return nil, err
	}
	if state.LKG == nil {
		return nil, errors.New("no authenticated Android configuration")
	}
	var preference clientmodel.Preference
	if err := control.DecodeCanonical(preferenceBody, &preference, control.ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 8, MaxItems: 4096}); err != nil {
		return nil, err
	}
	next, err := clientmodel.ChoosePolicy(preference, state.LKG.View, serviceID, policyID)
	if err != nil {
		return nil, err
	}
	return control.CanonicalEncode(next)
}
