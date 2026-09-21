package loomcore

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	"loom/internal/clientmodel"
)

type runtimeApplication struct {
	Schema          int                `json:"schema"`
	Mode            string             `json:"mode"`
	Exit            string             `json:"exit,omitempty"`
	DirectAvailable bool               `json:"direct_available"`
	Exits           []string           `json:"exits"`
	Selections      []runtimeSelection `json:"selections"`
}

type runtimeSelection struct {
	Selector  string   `json:"selector"`
	Candidate string   `json:"candidate"`
	Chain     []string `json:"chain,omitempty"`
	State     string   `json:"state"`
}

// EvaluateAndroidRoutes applies one Preference to every authorized scope. It performs no I/O.
func EvaluateAndroidRoutes(routesBody, observationsBody, preferenceBody, currentBody []byte,
	generation, nowRFC3339 string) ([]byte, error) {
	var routes []clientmodel.RouteCandidate
	var observations []clientmodel.Observation
	var preference clientmodel.Preference
	current := map[string]string{}
	if err := decodeStrictJSON(routesBody, 1<<20, &routes); err != nil {
		return nil, err
	}
	if len(observationsBody) == 0 {
		observationsBody = []byte("[]")
	}
	if err := decodeStrictJSON(observationsBody, 1<<20, &observations); err != nil {
		return nil, err
	}
	if len(preferenceBody) == 0 {
		preferenceBody = []byte(`{"schema":1,"mode":"auto"}`)
	}
	if err := decodeStrictJSON(preferenceBody, 1<<20, &preference); err != nil {
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
		if len(route.Chain) == 0 {
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
	application := runtimeApplication{Schema: 1, Mode: string(preference.Mode), Exit: preference.Exit,
		DirectAvailable: direct, Exits: make([]string, 0, len(exits))}
	for exit := range exits {
		application.Exits = append(application.Exits, exit)
	}
	sort.Strings(application.Exits)
	for _, scope := range scopes {
		selection, err := clientmodel.Select(byScope[scope], observations, preference, current[scope], generation, now.UTC())
		if err != nil {
			return nil, err
		}
		var chain []string
		state := "unknown"
		for _, route := range byScope[scope] {
			if route.ID == selection.CandidateID {
				chain = append([]string(nil), route.Chain...)
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
			Candidate: selection.CandidateID, Chain: chain, State: state})
	}
	return json.Marshal(application)
}
