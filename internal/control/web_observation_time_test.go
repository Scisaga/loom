package control

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestWebReportTimeBoundaries(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		offset time.Duration
		want   string
	}{
		{"current", 0, "current"},
		{"last millisecond", 3*time.Minute - time.Millisecond, "current"},
		{"deadline", 3 * time.Minute, "stale"},
		{"allowed forward difference", -5 * time.Second, "current"},
		{"future clock", -5*time.Second - time.Millisecond, "clock_unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, until := webReportTime(DeviceReport{ReportedAt: at.UnixMilli()}, at.Add(tc.offset))
			if state != tc.want || (until != 0) != (state == "current") || until != 0 && until != at.Add(3*time.Minute).UnixMilli() {
				t.Fatal("report window changed or unknown acquired current validity", state, until)
			}
		})
	}
}

func TestWebObservationKeepsOriginalDeadlineAndScope(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	report := DeviceReport{ReportedAt: at.UnixMilli(), NetworkGeneration: "demo-network", ViewDigest: "demo-view", Runtime: RuntimeReadback{State: "running", AppliedViewDigest: "demo-view"}}
	sample := Observation{Level: "service", Result: "available", NetworkGeneration: report.NetworkGeneration, ObservedAt: at.UnixMilli(), ValidUntil: at.Add(10 * time.Minute).UnixMilli()}
	_, reportUntil := webReportTime(report, at)
	if until := webObservationUntil(report, sample, reportUntil, at); until != reportUntil {
		t.Fatal("long-lived business sample extended the runtime report", until)
	}
	for _, tc := range []struct {
		name   string
		change func(*DeviceReport, *Observation)
	}{
		{"excessive success window", func(_ *DeviceReport, s *Observation) { s.ValidUntil++ }},
		{"failure window", func(_ *DeviceReport, s *Observation) { s.Result = "unavailable" }},
		{"link window", func(_ *DeviceReport, s *Observation) { s.Level = "link" }},
		{"future sample", func(_ *DeviceReport, s *Observation) {
			s.ObservedAt = at.Add(5*time.Second + time.Millisecond).UnixMilli()
		}},
		{"other network", func(_ *DeviceReport, s *Observation) { s.NetworkGeneration = "demo-other" }},
		{"stopped runtime", func(r *DeviceReport, _ *Observation) { r.Runtime.State = "stopped" }},
		{"unapplied view", func(r *DeviceReport, _ *Observation) { r.Runtime.AppliedViewDigest = "demo-other" }},
		{"clock rollback before report", func(r *DeviceReport, _ *Observation) { r.ReportedAt -= 5001 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, s := report, sample
			tc.change(&r, &s)
			if webObservationUntil(r, s, reportUntil, at) != 0 {
				t.Fatal("out-of-window or unrelated sample became current")
			}
		})
	}
	sample.Result, sample.ValidUntil = "unavailable", at.Add(30*time.Second).UnixMilli()
	if webObservationUntil(report, sample, reportUntil, at.Add(30*time.Second-time.Millisecond)) != sample.ValidUntil ||
		webObservationUntil(report, sample, reportUntil, at.Add(30*time.Second)) != 0 {
		t.Fatal("clock allowance extended the original failure deadline")
	}
}

func TestWebPathUsesEveryMatchingTargetWithoutBorrowingResourceSuccess(t *testing.T) {
	at := time.UnixMilli(1000)
	path := Path{ServiceID: "demo-service", CandidateID: "demo-path", SpecDigest: "demo-spec", Targets: []string{"https://demo.example/a", "https://demo.example/b"}}
	samples := []WebObservation{}
	for i, target := range path.Targets {
		samples = append(samples, WebObservation{Observation: Observation{Level: "service", ServiceID: path.ServiceID, CandidateID: path.CandidateID, SpecDigest: path.SpecDigest, Target: target, Action: "https_request", Result: "available"}, CurrentUntil: 9000 + int64(i)})
	}
	if state, until := webPathAvailability(path, samples, at); state != "available" || until != 9000 {
		t.Fatal("complete target coverage was not bounded by its earliest expiry", state, until)
	}
	samples[1].Result = "unavailable"
	if state, _ := webPathAvailability(path, samples, at); state != "unknown" {
		t.Fatal("partial failure became a whole-service conclusion")
	}
	samples[0].Result = "unavailable"
	if state, _ := webPathAvailability(path, samples, at); state != "unavailable" {
		t.Fatal("complete failure was lost")
	}
	for _, change := range []func(*WebObservation){
		func(s *WebObservation) { s.CurrentUntil = at.UnixMilli() },
		func(s *WebObservation) { s.CandidateID = "demo-other" },
		func(s *WebObservation) { s.SpecDigest = "demo-other" },
		func(s *WebObservation) { s.Level, s.Result = "resource", "available" },
	} {
		copy := append([]WebObservation{}, samples...)
		change(&copy[0])
		if state, _ := webPathAvailability(path, copy, at); state != "unknown" {
			t.Fatal("missing, expired, or other-scope result filled target coverage")
		}
	}
}

func TestWebTimeProjectionPreservesSignedHistoryAcrossExpiryAndRestart(t *testing.T) {
	fixture, _, projection := deviceContractFixture(t)
	target := "https://demo-service.example/probe"
	projection.NetworkIntent.BusinessProbeTargets = []BusinessProbeTarget{{ID: "demo-probe", URL: target}}
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := DeviceViewDigest(view)
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	route := view.Routes[0]
	report := DeviceReport{Schema: 3, NetworkID: projection.NetworkID, DeviceID: view.DeviceID, ReportSequence: 1,
		ViewDigest: digest, NetworkGeneration: "demo-network", ReportedAt: at.UnixMilli(),
		Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, Components: []ComponentReadback{},
		Selections: []ReportSelection{{ServiceID: route.ServiceID, CandidateID: route.ID}},
		Observations: []Observation{{Level: "service", ServiceID: route.ServiceID, CandidateID: route.ID, Target: target, Action: "https_request", SpecDigest: route.SpecDigest,
			NetworkGeneration: "demo-network", Result: "available", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(10 * time.Minute).UnixMilli()}}}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	put := func() {
		t.Helper()
		report, err = SignDeviceReport(report, fixture.keys[0])
		if err != nil || verifyCurrentReport(report, projection) != nil || store.Put(report, projection.DeviceAuthorizations[0].DevicePublicKey) != nil {
			t.Fatal("original report could not be authenticated and persisted", err)
		}
	}
	read := func(now time.Time) WebSnapshot {
		t.Helper()
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		store, err = testOpenObservationStore(t, root)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := buildWebSnapshot(projection, true, true, true)
		projectWebObservations(&snapshot, store.Verified(projection), now)
		return snapshot
	}
	put()
	original := testObservationBytes(t, store)
	current := read(at)
	if current.Paths[0].Availability != "available" || !current.Paths[0].Selected {
		t.Fatal("authenticated target result or selector readback was lost")
	}
	for _, device := range current.Devices {
		if device.Availability != "unknown" || device.Presence != "unknown" {
			t.Fatal("target success manufactured whole-device health or continuous presence")
		}
	}
	stale := read(at.Add(3 * time.Minute))
	if stale.Paths[0].Availability != "unknown" || !stale.Paths[0].Selected || !bytes.Equal(original, testObservationBytes(t, store)) {
		t.Fatal("restart renewed old success or changed original history/selection")
	}
	report.ReportSequence, report.ReportedAt = 2, at.Add(200*time.Second).UnixMilli()
	put()
	if value := read(at.Add(200 * time.Second)); value.Paths[0].Availability != "available" {
		t.Fatal("new report could not reuse the original still-valid sample")
	}
	report.ReportSequence, report.ReportedAt = 3, at.UnixMilli()
	put()
	if value := read(at.Add(200 * time.Second)); value.Paths[0].Availability != "unknown" {
		t.Fatal("latest stale report fell back to an older current report")
	}
	report.ReportSequence, report.ReportedAt = 4, at.Add(201*time.Second).UnixMilli()
	report.Observations[0].ValidUntil++
	put() // A projection limit must not reinterpret or reject canonical signed bytes.
	original = testObservationBytes(t, store)
	if value := read(at.Add(201 * time.Second)); value.Paths[0].Availability != "unknown" || !bytes.Equal(original, testObservationBytes(t, store)) {
		t.Fatal("excessive lifetime became current or was rewritten on restart")
	}
}
