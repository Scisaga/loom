package clientadapter

import "loom/internal/control"

// CurrentReportObservations projects a new report's immutable sample window.
// It never changes the local evidence used for selection or fair recovery.
func CurrentReportObservations(observations []control.Observation, networkGeneration string, reportedAt int64) ([]control.Observation, error) {
	if err := control.ValidateReportObservations(observations, networkGeneration); err != nil {
		return nil, err
	}
	current := make([]control.Observation, 0, len(observations))
	for _, observation := range observations {
		if observation.ObservedAt <= reportedAt && reportedAt < observation.ValidUntil {
			current = append(current, observation)
		}
	}
	return current, nil
}
