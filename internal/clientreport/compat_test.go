//go:build !windows

package clientreport_test

import (
	"encoding/json"
	"loom/internal/report"
	"testing"
	"time"
)

func TestUnmodifiedServerObservationVerifier(t *testing.T) {
	now := time.Now()
	o, _, ca := reportFixture(t, now)
	body, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var wire report.Observation
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	state, err := report.VerifyObservationAtLeast(&wire, ca, now, time.Minute, 5)
	if err != nil || !state.MeasurementsVerified || state.Applied != o.Applied {
		t.Fatalf("server verifier: %v", err)
	}
	// relay 增加未测量过的边不能沿用空测量摘要。
	wire.Edges = []report.Edge{{To: "demo-edge", RTTMs: 1}}
	if _, err := report.VerifyObservationAtLeast(&wire, ca, now, time.Minute, 5); err == nil {
		t.Fatal("fabricated measurements accepted")
	}
}
