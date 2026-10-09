package loomcore

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

type runtimeApplication struct {
	Schema          int                `json:"schema"`
	Mode            string             `json:"mode"`
	Exit            string             `json:"exit,omitempty"`
	DirectAvailable bool               `json:"direct_available"`
	Exits           []string           `json:"exits"`
	Selections      []runtimeSelection `json:"selections"`
	BlockedScopes   []string           `json:"blocked_scopes"`
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
	generation, nowRFC3339 string) ([]byte, error) {
	var routes []clientmodel.RouteCandidate
	var measured []androidObservation
	var observations []clientmodel.Observation
	var preference clientmodel.Preference
	current := map[string]string{}
	if err := decodeStrictJSON(routesBody, 1<<20, &routes); err != nil {
		return nil, err
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
		observations = append(observations, clientmodel.Observation{CandidateID: item.CandidateID, NetworkGeneration: item.NetworkGeneration, Scope: item.Scope, Result: item.Result, Action: item.Action, ObservedAt: item.ObservedAt, ValidUntil: item.ValidUntil, MetricMillis: metric})
	}
	if len(preferenceBody) == 0 {
		preferenceBody, _ = NewAndroidPreference("auto", "")
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
	exits, direct := map[string]bool{}, false
	for _, route := range routes {
		if err := route.Validate(); err != nil {
			return nil, err
		}
		byScope[route.Scope] = append(byScope[route.Scope], route)
		if route.FinalExit == "direct" {
			direct = true
		} else {
			exits[route.FinalExit] = true
		}
	}
	scopes := make([]string, 0, len(byScope))
	for scope := range byScope {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	application := runtimeApplication{Schema: 3, Mode: string(preference.Mode), Exit: preference.Exit,
		DirectAvailable: direct, Exits: make([]string, 0, len(exits)), Selections: []runtimeSelection{}, BlockedScopes: []string{}}
	for exit := range exits {
		application.Exits = append(application.Exits, exit)
	}
	sort.Strings(application.Exits)
	for _, scope := range scopes {
		selection, err := clientmodel.Select(byScope[scope], observations, preference, current[scope], generation, now.UTC())
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
		for _, observation := range observations {
			if observation.CandidateID == selection.CandidateID && observation.NetworkGeneration == generation {
				until, _ := time.Parse(time.RFC3339, observation.ValidUntil)
				if now.Before(until) {
					state = observation.Result
				}
			}
		}
		application.Selections = append(application.Selections, runtimeSelection{Selector: scope,
			Candidate: selection.CandidateID, FinalExit: finalExit, Chain: chain, State: state})
	}
	return json.Marshal(application)
}

// NewAndroidPreference emits the single canonical local preference value.
func NewAndroidPreference(mode, exit string) ([]byte, error) {
	preference := clientmodel.Preference{Schema: 3, Mode: clientmodel.Mode(mode), Exit: exit}
	return control.CanonicalEncode(preference)
}
