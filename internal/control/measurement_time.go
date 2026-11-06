package control

import "time"

const measurementClockTolerance = 5 * time.Second

// A known authenticated head supplies execution/generation evidence, not a
// renewable lease on every measurement. Report silence alone is no failure.
func measurementHeadReady(report DeviceReport, now time.Time) bool {
	return report.Runtime.HasCurrentPermissions(report.ViewDigest) &&
		report.ReportedAt <= now.Add(measurementClockTolerance).UnixMilli()
}

// Routing uses the original producer deadline. Web display freshness is a
// separate projection and cannot shorten or extend this measurement lifetime.
func measurementObservationUntil(report DeviceReport, sample Observation, now time.Time) int64 {
	if !measurementHeadReady(report, now) || sample.NetworkGeneration != report.NetworkGeneration ||
		sample.ObservedAt > now.UnixMilli() || sample.ObservedAt > report.ReportedAt+measurementClockTolerance.Milliseconds() || sample.ValidUntil <= now.UnixMilli() {
		return 0
	}
	var lifetime time.Duration
	switch sample.Result {
	case "available":
		lifetime = 10 * time.Minute
	case "unavailable", "unknown":
		lifetime = 30 * time.Second
	default:
		return 0
	}
	if sample.ValidUntil <= sample.ObservedAt || sample.ValidUntil-sample.ObservedAt > lifetime.Milliseconds() {
		return 0
	}
	return sample.ValidUntil
}
