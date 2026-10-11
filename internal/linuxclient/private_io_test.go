package linuxclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

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
		FactFrontier: []control.FactFrontier{}, Preference: clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeAuto},
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
}

func TestPrivateRefreshCancelsForAcceptedRevocationAndPersistenceFailure(t *testing.T) {
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
			requests := make(chan struct{}, 1)
			notices := make(chan string, 1)
			failures := make(chan error, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				refreshPrivateConfiguration(ctx, stale, requests, notices, failures, cancel)
			}()
			requests <- struct{}{}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("accepted change or persistence failure did not cancel old execution")
			}
			<-done
			err = <-failures
			want := errCertifiedViewChanged
			if failure {
				want = errCertifiedPersistence
			}
			if !errors.Is(err, want) || !failure && !reflect.DeepEqual(stale.LKG(), &next) {
				t.Fatal("private refresh lost accepted authority or failure semantics", err)
			}
		})
	}
}
