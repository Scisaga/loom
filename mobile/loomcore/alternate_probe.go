package loomcore

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

// ObserveAndroidAlternateBusiness reuses the already applied native instance.
// Its samples are ordinary local business outcomes, never remote report copies.
func ObserveAndroidAlternateBusiness(stateBody, observationsBody, preferenceBody, currentBody []byte,
	generation string, resourcesBody, linksBody []byte) ([]byte, error) {
	identity, err := decodeState(stateBody)
	if err != nil || identity.LKG == nil {
		return nil, errors.New("Android alternate probe requires an accepted View")
	}
	routes, _, err := clientadapter.AccessProjection(identity.LKG.View)
	if err != nil {
		return nil, err
	}
	state := clientadapter.State{NetworkGeneration: generation}
	if len(preferenceBody) == 0 {
		preferenceBody, _ = NewAndroidPreference("auto", "")
	}
	if err := control.DecodeCanonical(preferenceBody, &state.Preference, control.ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 8, MaxItems: 1024}); err != nil {
		return nil, err
	}
	var measured []androidObservation
	if len(observationsBody) == 0 {
		observationsBody = []byte("[]")
	}
	if err := decodeStrictJSON(observationsBody, 1<<20, &measured); err != nil {
		return nil, err
	}
	for _, value := range measured {
		metric := int64(0)
		if value.MetricMillis != nil {
			metric = *value.MetricMillis
		}
		state.Observations = append(state.Observations, clientmodel.Observation{CandidateID: value.CandidateID, Target: value.Target, NetworkGeneration: value.NetworkGeneration,
			Scope: value.Scope, Result: value.Result, Action: value.Action, ObservedAt: value.ObservedAt, ValidUntil: value.ValidUntil, MetricMillis: metric})
	}
	if len(resourcesBody) > 0 {
		if err := decodeStrictJSON(resourcesBody, clientadapter.ResourceObservationCacheLimit, &state.ResourceObservations); err != nil {
			return nil, err
		}
	}
	if len(linksBody) > 0 {
		if err := decodeStrictJSON(linksBody, 4<<20, &state.LinkObservations); err != nil {
			return nil, err
		}
		value := control.DeviceLinkObservations{Schema: 3, NetworkID: identity.LKG.View.NetworkID, DeviceID: identity.LKG.View.DeviceID,
			ViewDigest: identity.LKG.ViewDigest, Observations: state.LinkObservations}
		if err := value.ValidateForView(identity.LKG.View); err != nil {
			return nil, err
		}
	}
	current := map[string]string{}
	if len(currentBody) > 0 {
		if err := decodeStrictJSON(currentBody, 1<<20, &current); err != nil {
			return nil, err
		}
	}
	scopes, byScope, err := clientadapter.Scopes(routes)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 30*time.Second)
	defer cancel()
	ctx, err = clientadapter.NativeDiagnosticContext(ctx, androidLocalRuntimeSecret(identity), nil)
	if err != nil {
		return nil, err
	}
	targetsByScope := map[string][]string{}
	selectedScope, selectedAt, selectedKey := "", "", ""
	at := time.Now()
	for _, scope := range scopes {
		targets := []string{}
		for _, group := range identity.LKG.View.BusinessProbeTargets {
			if scope == "service:"+group.ServiceID || scope == "local_network:"+group.ServiceID {
				targets = group.Targets
				break
			}
		}
		targetsByScope[scope] = targets
		request, found, probeErr := clientadapter.NextAlternateProbe(byScope[scope], state, current[scope], targets, at)
		if probeErr != nil {
			return nil, probeErr
		}
		if !found {
			continue
		}
		sample, sampled, sampleErr := clientmodel.LatestObservation(state.Observations, request.CandidateID, scope, generation, request.Target)
		if sampleErr != nil {
			return nil, sampleErr
		}
		observed := ""
		if sampled {
			when, _ := time.Parse(time.RFC3339, sample.ObservedAt)
			if !when.After(at) {
				observed = sample.ObservedAt
			}
		}
		key := request.CandidateID + "\x00" + request.Target
		if selectedScope == "" || observed < selectedAt || observed == selectedAt && key < selectedKey {
			selectedScope, selectedAt, selectedKey = scope, observed, key
		}
	}
	if selectedScope != "" {
		state, err = clientadapter.SampleAlternateBusiness(ctx, byScope[selectedScope], state, current[selectedScope], targetsByScope[selectedScope], time.Now)
		if err != nil {
			return nil, err
		}
	}
	result := make([]androidObservation, 0, len(state.Observations))
	for _, value := range state.Observations {
		item := androidObservation{CandidateID: value.CandidateID, Target: value.Target, NetworkGeneration: value.NetworkGeneration, Scope: value.Scope,
			Result: value.Result, Action: value.Action, ObservedAt: value.ObservedAt, ValidUntil: value.ValidUntil}
		if value.Result == "available" {
			item.MetricMillis = new(value.MetricMillis)
		}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.CandidateID != b.CandidateID {
			return a.CandidateID < b.CandidateID
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.Action < b.Action
	})
	return json.Marshal(result)
}
