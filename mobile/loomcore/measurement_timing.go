package loomcore

import "loom/internal/clientadapter"

// AndroidMeasurementCheckIntervalMillis derives the existing Android sampler's
// check interval from the same timing. The Go scheduler still owns actual due
// times, original validity and node budgets; checks do not promise exact repeats.
func AndroidMeasurementCheckIntervalMillis() int64 {
	timing := clientadapter.DefaultMeasurementTiming
	return timing.RecoveryPeriod().Milliseconds()
}
