package linuxclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

func TestPrivateLinkDiagnosticsKeepExactCacheAcrossFetchFailure(t *testing.T) {
	store, path, makeView := linuxAcceptanceFixture(t)
	if err := store.SaveLKG(makeView(7, true)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	lkg := store.LKG()
	ctx, cancel := context.WithCancel(context.Background())
	requests := make(chan struct{}, 1)
	results := make(chan control.DeviceLinkObservations, 1)
	bases := make(chan string, 3)
	lines := make(chan string, 3)
	done := make(chan struct{})
	calls := 0
	diagnosticCalls := 0
	go func() {
		defer close(done)
		refreshPrivateLinkObservationsWithFetch(ctx, store, requests, results, func(_ context.Context, _ deviceclient.IdentityStore, previous *control.DeviceLinkObservations) (control.DeviceLinkObservations, error) {
			calls++
			base := "nil"
			if previous != nil {
				base = previous.Cursor
			}
			bases <- base
			if calls == 2 {
				return control.DeviceLinkObservations{}, context.DeadlineExceeded
			}
			cursor := "demo-private-cursor-first"
			if calls == 3 {
				cursor = "demo-private-cursor-next"
			}
			return control.DeviceLinkObservations{Schema: 3, NetworkID: lkg.View.NetworkID, DeviceID: lkg.View.DeviceID, ViewDigest: lkg.ViewDigest,
				Cursor: cursor, Reset: true, Removed: []string{}, Observations: []control.DeviceLinkObservation{}}, nil
		}, func(line string) error {
			diagnosticCalls++
			lines <- line
			if diagnosticCalls == 1 {
				panic("demo-private sink panic")
			}
			return errors.New("demo-private sink failure")
		})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("diagnostics left a private fetch worker running")
		}
	}()
	readLine := func() string {
		t.Helper()
		select {
		case line := <-lines:
			return line
		case <-time.After(time.Second):
			t.Fatal("private measurement lifecycle diagnostic missing")
			return ""
		}
	}
	requests <- struct{}{}
	first := <-results
	firstLog := readLine()
	if <-bases != "nil" || first.Cursor != "demo-private-cursor-first" || first.ValidateForView(lkg.View) != nil {
		t.Fatal("initial complete measurement cache differs")
	}
	requests <- struct{}{}
	failedLog := readLine()
	if <-bases != first.Cursor || !strings.Contains(failedLog, "outcome=timeout") {
		t.Fatal("failed fetch lost its exact original base or safe timeout class")
	}
	select {
	case <-results:
		t.Fatal("failed fetch published another measurement cache")
	default:
	}
	requests <- struct{}{}
	next := <-results
	nextLog := readLine()
	if <-bases != first.Cursor || next.Cursor != "demo-private-cursor-next" {
		t.Fatal("failed fetch changed the base supplied to the next real fetch")
	}
	for _, line := range []string{firstLog, failedLog, nextLog} {
		if !strings.Contains(line, "wire_mode=unknown") {
			t.Fatal("merged cache was mislabeled as a wire reset/delta")
		}
		for _, secret := range []string{"demo-private", "demo-network", "demo-device", "192.0.2.1"} {
			if strings.Contains(line, secret) {
				t.Fatal("measurement diagnostic leaked an identifier, cursor, target or callback error")
			}
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("measurement diagnostics wrote authenticated identity or progress")
	}
}

func TestPrivateLinkDiagnosticsMatchConsumedSetWithoutExposingFacts(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	one := control.DeviceLinkObservation{DeviceID: "demo-private-source", ReportSequence: 1, ReportDigest: control.ReleaseDigest([]byte("demo-report")), CurrentUntil: at + 60_000,
		Observation: control.Observation{Level: "link", ResourceID: "demo-private-resource", LinkID: "demo-link", SpecDigest: control.ReleaseDigest([]byte("demo-spec")), Target: "192.0.2.1:443", Action: "hysteria2_echo", NetworkGeneration: "demo-private-network", Result: "available", ObservedAt: at, ValidUntil: at + 60_000, DurationMS: new(int64(1)), RoundTripMS: new(int64(1))}}
	two := one
	two.Observation.ResourceID = "demo-private-other"
	two.Observation.LinkID = "demo-other-link"
	values := []control.DeviceLinkObservation{one, two}
	want := measurementDiagnosticSet(values)
	if want == "unavailable" || want == "-" || want != measurementDiagnosticSet([]control.DeviceLinkObservation{two, one}) {
		t.Fatal("public sample-set diagnostic depends on order or cannot encode real facts")
	}
	changed := one
	changed.Observation.ObservedAt++
	if measurementDiagnosticSet([]control.DeviceLinkObservation{changed, two}) == want {
		t.Fatal("a changed original sample kept the same diagnostic digest")
	}
	value := control.DeviceLinkObservations{Cursor: "demo-private-cursor", ViewDigest: control.ReleaseDigest([]byte("demo-view")), Observations: values}
	var line string
	logPrivateLinkDelivery(func(value string) error { line = value; return nil }, "consume", nil, &value, value.ViewDigest, "valid", nil, values)
	if !strings.Contains(line, "merged_set="+want) || !strings.Contains(line, "adopted_set="+want) || !strings.Contains(line, "base=unknown") || !strings.Contains(line, "wire_mode=unknown") {
		t.Fatal("received and adopted exact sets cannot be correlated", line)
	}
	logPrivateLinkDelivery(func(value string) error { line = value; return nil }, "consume", nil, &value, value.ViewDigest, "invalid", errors.New("192.0.2.1 demo-private failure"), nil)
	if !strings.Contains(line, "adopted_count=0") || !strings.Contains(line, "validate=invalid") || strings.Contains(line, "demo-private") || strings.Contains(line, "192.0.2.1") {
		t.Fatal("invalid consumption exposed facts or claimed an adopted set", line)
	}
}

func TestRuntimeReportUploadCoalescesPendingSnapshotsAndCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requests := make(chan *runtimeReportAttempt, 1)
	results := make(chan runtimeReportResult, 1)
	started := make(chan control.DeviceReport, 2)
	release := make(chan struct{})
	done := make(chan struct{})
	firstErr := errors.New("demo report connection failed")
	go func() {
		defer close(done)
		uploadRuntimeReports(ctx, requests, results, func(ctx context.Context, report control.DeviceReport) error {
			started <- report
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
				return firstErr
			}
		})
	}()
	waitStarted := func() control.DeviceReport {
		t.Helper()
		select {
		case report := <-started:
			return report
		case <-time.After(time.Second):
			t.Fatal("report request did not start")
			return control.DeviceReport{}
		}
	}
	first := &runtimeReportAttempt{report: control.DeviceReport{ReportedAt: 1}}
	offerLatest(requests, first)
	if waitStarted().ReportedAt != 1 {
		t.Fatal("wrong initial snapshot")
	}
	var latest *runtimeReportAttempt
	for i := int64(2); i <= 100; i++ {
		latest = &runtimeReportAttempt{report: control.DeviceReport{ReportedAt: i}}
		offerLatest(requests, latest)
	}
	select {
	case <-started:
		t.Fatal("uploads overlapped while the first connection was waiting")
	default:
	}
	release <- struct{}{}
	if report := waitStarted(); report.ReportedAt != 100 {
		t.Fatal("waiting upload did not use the latest original snapshot", report)
	}
	result := <-results
	if result.attempt != first || !errors.Is(result.err, firstErr) {
		t.Fatal("completion lost its exact snapshot identity")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stop left a report request running")
	}
	select {
	case <-results:
		t.Fatal("cancellation manufactured an upload result")
	default:
	}
}

func TestReportConfirmationCannotOverwriteNewerReadback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	status := Status{Schema: 3, DeviceID: "demo-device", ViewDigest: control.ReleaseDigest([]byte("demo-view")),
		FactFrontier: []control.FactFrontier{}, Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"},
		Runtime: "running", NetworkGeneration: "demo-old-network", Selections: []SelectionStatus{}, Observations: []clientmodel.Observation{}}
	previous := &runtimeReportAttempt{status: status}
	status.NetworkGeneration = "demo-new-network"
	current := &runtimeReportAttempt{status: status}
	if err := WriteStatus(path, current.status); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := writeReportConfirmation(path, current, runtimeReportResult{attempt: previous}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("old upload acknowledgement overwrote current local state")
	}
	if err := writeReportConfirmation(path, current, runtimeReportResult{attempt: current}); err != nil {
		t.Fatal(err)
	}
	actual, err := ReadStatus(path)
	if err != nil || !actual.Reported || actual.NetworkGeneration != current.status.NetworkGeneration || current.status.Reported {
		t.Fatal("current confirmation was lost or mutated its immutable snapshot", err)
	}
	actual.Reported = false
	actual.Selections = []SelectionStatus{{Scope: "access", CandidateID: "demo-new-path", Targets: map[string]string{}}}
	if err := WriteStatus(path, actual); err != nil {
		t.Fatal(err)
	}
	before, _ = os.ReadFile(path)
	if err := writeReportConfirmation(path, current, runtimeReportResult{attempt: current}); err != nil {
		t.Fatal(err)
	}
	after, _ = os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("old ACK overwrote newer same-network local route optimization")
	}
}

func TestPrivateRefreshInterruptsWorkForRevocationAndStopsForPersistenceFailure(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "revocation", true: "persistence"}[failure], func(t *testing.T) {
			store, path, makeView := linuxAcceptanceFixture(t)
			if err := store.SaveLKG(makeView(7, true)); err != nil {
				t.Fatal(err)
			}
			stale, err := deviceclient.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			next := makeView(8, false)
			if failure {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else if err := store.SaveLKG(next); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			work, interrupt := context.WithCancel(ctx)
			defer interrupt()
			requests := make(chan struct{}, 1)
			notices := make(chan string, 1)
			failures := make(chan error, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				refreshPrivateConfiguration(ctx, stale, requests, notices, failures, cancel, interrupt)
			}()
			requests <- struct{}{}
			if failure {
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
					t.Fatal("persistence failure did not cancel execution")
				}
				<-done
				if err = <-failures; !errors.Is(err, errCertifiedPersistence) {
					t.Fatal("private refresh lost its persistence failure", err)
				}
				return
			}
			select {
			case <-notices:
			case <-time.After(time.Second):
				t.Fatal("accepted change did not wake the runtime apply owner")
			}
			select {
			case <-work.Done():
			case <-time.After(time.Second):
				t.Fatal("accepted change left old measurement work blocking its application")
			}
			if ctx.Err() != nil || !reflect.DeepEqual(stale.LKG(), &next) {
				t.Fatal("accepted revocation destroyed execution before local apply or lost authority")
			}
			select {
			case err := <-failures:
				t.Fatal("accepted change was reported as a runtime failure", err)
			default:
			}
			cancel()
			<-done
		})
	}
}
