package control

import "time"

// These limits qualify a public readback; they never change canonical report
// validation, stored bytes, client probing, or authorization.
const (
	webReportLifetime = 3 * time.Minute
	webClockTolerance = 5 * time.Second
)

func webReportTime(report DeviceReport, now time.Time) (string, int64) {
	at := now.UnixMilli()
	if report.ReportedAt > at+webClockTolerance.Milliseconds() {
		return "clock_unknown", 0
	}
	until := report.ReportedAt + webReportLifetime.Milliseconds()
	if at >= until {
		return "stale", 0
	}
	return "current", until
}

func webObservationUntil(report DeviceReport, sample Observation, reportUntil int64, now time.Time) int64 {
	at := now.UnixMilli()
	if reportUntil == 0 || reportUntil <= at || report.Runtime.State != "running" || report.Runtime.AppliedViewDigest != report.ViewDigest ||
		sample.NetworkGeneration != report.NetworkGeneration || sample.ObservedAt > at+webClockTolerance.Milliseconds() ||
		sample.ObservedAt > report.ReportedAt+webClockTolerance.Milliseconds() || sample.ValidUntil <= at {
		return 0
	}
	lifetime := 30 * time.Second
	switch sample.Level {
	case "resource", "service":
		if sample.Result == "available" {
			lifetime = 10 * time.Minute
		}
	case "link":
	default:
		return 0
	}
	if sample.Result != "available" && sample.Result != "unavailable" && sample.Result != "unknown" ||
		sample.ValidUntil <= sample.ObservedAt || sample.ValidUntil-sample.ObservedAt > lifetime.Milliseconds() {
		return 0
	}
	return min(sample.ValidUntil, reportUntil)
}

func webPathAvailability(path Path, samples []WebObservation, now time.Time) (string, int64) {
	if len(path.Targets) == 0 {
		return "unknown", 0
	}
	result, until := "", int64(0)
	for _, target := range path.Targets {
		var found *WebObservation
		for i := range samples {
			sample := &samples[i]
			if sample.Level == "service" && sample.ServiceID == path.ServiceID && sample.CandidateID == path.CandidateID &&
				sample.SpecDigest == path.SpecDigest && sample.Target == target && sample.Action == "https_request" {
				if found != nil {
					return "unknown", 0
				}
				found = sample
			}
		}
		if found == nil || found.CurrentUntil <= now.UnixMilli() || found.Result != "available" && found.Result != "unavailable" ||
			result != "" && result != found.Result {
			return "unknown", 0
		}
		result = found.Result
		if until == 0 || found.CurrentUntil < until {
			until = found.CurrentUntil
		}
	}
	return result, until
}
