package loomcore

import (
	"encoding/json"
	"errors"
	"time"

	"loom/internal/control"
)

// HiddenAndroidInternetPolicies projects an already received complete batch.
// It performs no candidate projection, request, preference or authority write.
func HiddenAndroidInternetPolicies(stateBody, linksBody []byte, nowMS int64) ([]byte, error) {
	state, err := decodeState(stateBody)
	if err != nil {
		return nil, err
	}
	if state.LKG == nil || nowMS <= 0 {
		return nil, errors.New("current Android authorization and time are required")
	}
	var shared []control.DeviceLinkObservation
	if err := decodeStrictJSON(linksBody, androidMeasurementSnapshotLimit, &shared); err != nil {
		return nil, err
	}
	hidden, err := control.HiddenInternetPolicies(state.LKG.View, "", shared, nil, "", time.UnixMilli(nowMS))
	if err != nil {
		return nil, err
	}
	return json.Marshal(hidden)
}
