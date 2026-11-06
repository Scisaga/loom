package clientadapter

import (
	"testing"
	"time"

	"loom/internal/control"
)

func TestCompletedFailureWouldDisappearBeforeMinuteReport(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	sample := control.Observation{Level: "resource", ResourceID: "demo-resource", Target: "192.0.2.10:51820", Action: "wireguard_echo",
		SpecDigest: control.ReleaseDigest([]byte("demo-specification")), NetworkGeneration: "demo-network", Result: "unavailable",
		ObservedAt: at.Add(5 * time.Second).UnixMilli(), ValidUntil: at.Add(5*time.Second + DefaultMeasurementTiming.FailureValidity).UnixMilli(), DurationMS: new(int64(1))}
	completed, err := CurrentReportObservations([]control.Observation{sample}, "demo-network", at.Add(6*time.Second).UnixMilli())
	if err != nil || len(completed) != 1 || completed[0].ObservedAt != sample.ObservedAt || completed[0].ValidUntil != sample.ValidUntil {
		t.Fatal("completion-triggered report lost or retimed the original failure", err)
	}
	minute, err := CurrentReportObservations([]control.Observation{sample}, "demo-network", at.Add(time.Minute).UnixMilli())
	if err != nil || len(minute) != 0 {
		t.Fatal("fixture did not reproduce a short failure disappearing before the periodic report", err)
	}
	if sample.ObservedAt != at.Add(5*time.Second).UnixMilli() || sample.ValidUntil != at.Add(5*time.Second+DefaultMeasurementTiming.FailureValidity).UnixMilli() {
		t.Fatal("report filtering extended the measurement window")
	}
}
