package loomcore

import (
	"encoding/json"
	"errors"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

// RefreshAndroidNativeObservations consumes a current confirmed selector and
// its RAM binding. The host keeps the existing View/preference/instance fence;
// this quick path cannot bind a revision or derive new authorization.
func RefreshAndroidNativeObservations(currentBody, memoryBody, nativeBody, eventsBody []byte, generation string, nowMS int64) ([]byte, error) {
	return refreshAndroidNativeObservations(currentBody, memoryBody, nativeBody, eventsBody, nil, generation, nowMS)
}

func MergeAndroidTCPRecoveryObservations(currentBody, memoryBody, nativeBody, calibratedBody []byte, generation string, nowMS int64) ([]byte, error) {
	return refreshAndroidNativeObservations(currentBody, memoryBody, nativeBody, []byte(`{"observations":[]}`), calibratedBody, generation, nowMS)
}

func refreshAndroidNativeObservations(currentBody, memoryBody, nativeBody, eventsBody, calibratedBody []byte, generation string, nowMS int64) ([]byte, error) {
	if nowMS <= 0 || time.UnixMilli(nowMS).Year() > 9999 {
		return nil, errors.New("invalid native observation consumption time")
	}
	var current map[string]clientmodel.Selection
	var memories map[string]clientmodel.SelectionMemory
	if err := decodeStrictJSON(currentBody, 1<<20, &current); err != nil {
		return nil, err
	}
	if err := decodeStrictJSON(memoryBody, 1<<20, &memories); err != nil {
		return nil, err
	}
	actual := current[control.AccessSelectorScope]
	actual.Scope = control.AccessSelectorScope
	memory := memories[control.AccessSelectorScope]
	state := clientadapter.State{NetworkGeneration: generation, Preference: clientmodel.Preference{Schema: 3, PolicyID: memory.PolicyID}, SelectionMemory: memories}
	if memory.NativeBinding != nil {
		state.NativeExecutionSpec = memory.NativeBinding.ExecutionSpec
	}
	if len(nativeBody) > 0 {
		if err := decodeStrictJSON(nativeBody, clientadapter.NativeObservationReadbackLimit, &state.NativeObservations); err != nil {
			return nil, err
		}
	}
	bound := clientadapter.NativeBindingMatches(memory, actual, generation, state.NativeExecutionSpec)
	previous := append([]clientmodel.Observation{}, state.NativeObservations...)
	if bound && len(calibratedBody) > 0 {
		var values []clientmodel.Observation
		if err := decodeStrictJSON(calibratedBody, clientadapter.NativeObservationReadbackLimit, &values); err != nil {
			return nil, err
		}
		for _, value := range values {
			if value.Validate() != nil || value.Action != "tcp_calibration" || value.NetworkGeneration != generation {
				return nil, errors.New("invalid Android TCP recovery completion")
			}
			decision := memory.Decisions["tcp://"+value.Target]
			if decision.Pending == value.CandidateID && decision.CalibrateTCP {
				state.NativeObservations = append(state.NativeObservations, value)
			}
		}
	}
	completed, err := clientadapter.ConsumeNativeSelectionObservations(eventsBody, state, actual, time.UnixMilli(nowMS))
	if err != nil {
		return nil, err
	}
	memory, healthDue := clientadapter.RefreshNativeHealth(memory, completed, time.UnixMilli(nowMS))
	memories[control.AccessSelectorScope] = memory
	return json.Marshal(struct {
		Observations   []clientmodel.Observation              `json:"native_observations"`
		NeedsRouting   bool                                   `json:"needs_routing"`
		BindingCurrent bool                                   `json:"binding_current"`
		Memory         map[string]clientmodel.SelectionMemory `json:"memory"`
	}{completed, !bound || healthDue || clientadapter.NativeRoutingChanged(previous, completed, memory), bound, memories})
}
