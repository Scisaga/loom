package loomcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/deviceclient"
	"loom/protocol"
)

func androidSelectedCandidates(view control.DeviceExecution, body, memoryBody []byte, generation string) ([]string, error) {
	var selections []androidSelection
	if err := decodeStrictJSON(body, 1<<20, &selections); err != nil {
		return nil, err
	}
	if selections == nil {
		return nil, errors.New("Android selector readback is missing")
	}
	var memory map[string]clientmodel.SelectionMemory
	if len(memoryBody) > 0 {
		if err := decodeStrictJSON(memoryBody, 1<<20, &memory); err != nil {
			return nil, err
		}
	}
	routes := map[string]control.RouteCandidate{}
	for _, route := range view.Routes {
		routes[route.ID] = route
	}
	seen := map[string]bool{}
	selected := make([]string, 0, len(selections))
	for _, value := range selections {
		route, found := routes[value.CandidateID]
		if !found || clientmodel.CandidateSelectorScope(clientmodel.RouteCandidate{Scope: route.Scope}) != value.Scope || seen[value.Scope] {
			return nil, errors.New("Android selector readback is outside the current authorization")
		}
		seen[value.Scope] = true
		for target, id := range value.Targets {
			_, _, _, targetErr := protocol.ParseConnectionTargetKey(target)
			if candidate, exists := routes[id]; !exists || targetErr != nil || candidate.PolicyID != route.PolicyID {
				return nil, errors.New("target priority is outside the actual Policy")
			}
		}
		actual := clientmodel.Selection{Scope: value.Scope, PolicyID: route.PolicyID, CandidateID: value.CandidateID, Targets: value.Targets}
		for _, id := range clientmodel.MeasurementCandidates(actual, memory[value.Scope], generation) {
			if candidate, allowed := routes[id]; allowed && candidate.PolicyID == route.PolicyID &&
				clientmodel.CandidateSelectorScope(clientmodel.RouteCandidate{Scope: candidate.Scope}) == value.Scope {
				selected = append(selected, id)
			}
		}
	}
	slices.Sort(selected)
	return slices.Compact(selected), nil
}

// AndroidMeasurementObserver receives only newly completed original samples.
// Calls are serial and finish before Run returns, including cancellation.
type AndroidMeasurementObserver interface {
	Completed(body []byte) error
	Calibrated(body []byte) error
}

// NewAndroidFirstHopRequest reuses the cancellable call used for private I/O.
// The host rechecks its current runtime inputs before committing each delta.
func NewAndroidFirstHopRequest(stateBody, selectionsBody, previousBody, memoryBody, currentBody, nativeBody, linksBody []byte, generation string, observer AndroidMeasurementObserver) (*AndroidDeviceRequest, error) {
	state, err := decodeState(stateBody)
	if err != nil {
		return nil, err
	}
	if state.LKG == nil {
		return nil, errors.New("Android first-hop sampling requires an accepted configuration")
	}
	// gomobile borrows byte-array arguments only for this constructor call.
	// Run is a separate call, so its deferred inputs must be owned by Go.
	selectionsBody = bytes.Clone(selectionsBody)
	previousBody = bytes.Clone(previousBody)
	memoryBody = bytes.Clone(memoryBody)
	currentBody = bytes.Clone(currentBody)
	nativeBody = bytes.Clone(nativeBody)
	linksBody = bytes.Clone(linksBody)
	ctx, cancel := context.WithCancel(androidNetworkContext())
	return &AndroidDeviceRequest{ctx: ctx, cancel: cancel, run: func(ctx context.Context) ([]byte, error) {
		identity, err := clientadapter.ResourceCacheIdentity(*state.LKG)
		if err != nil {
			return nil, err
		}
		return observeAndroidFirstHops(ctx, state, selectionsBody, previousBody, memoryBody, generation, time.Now, func(batch []control.Observation) error {
			if observer == nil {
				return nil
			}
			body, err := clientadapter.EncodeResourceObservationCache(identity, clientadapter.MergeNodeMeasurements(nil, batch))
			if err != nil {
				return err
			}
			return observer.Completed(body)
		}, currentBody, nativeBody, linksBody, observer)
	}}, nil
}

func observeAndroidFirstHops(ctx context.Context, state deviceclient.State, selectionsBody, previousBody, memoryBody []byte, generation string, now func() time.Time, progress func([]control.Observation) error, currentBody, nativeBody, linksBody []byte, observer AndroidMeasurementObserver) ([]byte, error) {
	if state.LKG == nil {
		return nil, errors.New("Android first-hop sampling requires an accepted configuration")
	}
	execution, err := control.ProjectDeviceCandidates(state.LKG.View, clientmodel.MeasurementPolicies(androidPreference(state)))
	if err != nil {
		return nil, err
	}
	selected, err := androidSelectedCandidates(execution, selectionsBody, memoryBody, generation)
	if err != nil {
		return nil, err
	}
	previous := []control.Observation{}
	if len(previousBody) > 0 {
		previous, err = clientadapter.DecodeResourceObservations(previousBody, *state.LKG, generation, clientmodel.MeasurementPolicies(androidPreference(state)))
		if err != nil {
			return nil, err
		}
	}
	diagnostic, err := clientadapter.NativeDiagnosticContext(ctx, androidLocalRuntimeSecret(state), nil)
	if err != nil {
		return nil, err
	}
	var recovery *clientadapter.TCPRecoveryInput
	if len(currentBody) > 0 && len(nativeBody) > 0 && !bytes.Equal(bytes.TrimSpace(nativeBody), []byte("[]")) && len(memoryBody) > 0 {
		inputs, current, decodeErr := decodeAndroidRoutingSamples(nil, currentBody, nil, linksBody, memoryBody, generation)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if err := decodeStrictJSON(nativeBody, clientadapter.NativeObservationReadbackLimit, &inputs.NativeObservations); err != nil {
			return nil, err
		}
		routes, graphs, err := clientadapter.AccessRoutingInputsFromExecution(execution, clientmodel.MeasurementPolicies(androidPreference(state)))
		if err != nil {
			return nil, err
		}
		inputs.Preference, inputs.Graphs = androidPreference(state), graphs
		inputs.NativeExecutionSpec, err = clientadapter.NativeExecutionSpec(state.LKG.View, routes, graphs, inputs.Preference.PolicyID)
		if err != nil {
			return nil, err
		}
		nativeSelector, err := clientadapter.NativeDiagnosticSelector(diagnostic)
		if err != nil {
			return nil, err
		}
		actual := current[control.AccessSelectorScope]
		actual.Scope = control.AccessSelectorScope
		if clientadapter.NativeBindingMatches(inputs.SelectionMemory[control.AccessSelectorScope], actual, generation, inputs.NativeExecutionSpec) {
			recovery = &clientadapter.TCPRecoveryInput{Selector: nativeSelector, Routes: routes, State: inputs}
			recovery.Progress = func(batch []clientmodel.Observation) error {
				if observer == nil {
					return nil
				}
				body, err := json.Marshal(batch)
				if err != nil {
					return err
				}
				return observer.Calibrated(body)
			}
		}
	}
	values, err := clientadapter.ObserveFirstHops(diagnostic, execution, selected, previous, generation, now, progress, recovery)
	if err != nil {
		return nil, err
	}
	return clientadapter.EncodeResourceObservations(*state.LKG, values, clientmodel.MeasurementPolicies(androidPreference(state)))
}
