package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestWindowsConfigurationFollowsWhileReportIOIsBlockedAndJoinsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requests := make(chan *windowsReportAttempt, 1)
	results := make(chan windowsReportResult, 1)
	reportStarted := make(chan struct{})
	reportJoined := make(chan struct{})
	go func() {
		defer close(reportJoined)
		uploadWindowsReports(ctx, requests, results, func(ctx context.Context, _ control.DeviceReport) error {
			close(reportStarted)
			<-ctx.Done() // the underlying request must observe cancellation
			return ctx.Err()
		})
	}()
	requests <- &windowsReportAttempt{}
	select {
	case <-reportStarted:
	case <-time.After(time.Second):
		t.Fatal("report I/O did not start")
	}
	accepted := make(chan uint64, 2)
	configurationJoined := make(chan error, 1)
	go func() {
		var round uint64
		configurationJoined <- followWindowsConfiguration(ctx, time.Hour, func(ctx context.Context) (bool, error) {
			if round < 2 {
				accepted <- round
				round++
				return true, nil
			}
			<-ctx.Done()
			return false, ctx.Err()
		})
	}()
	for expected := uint64(0); expected < 2; expected++ {
		select {
		case got := <-accepted:
			if got != expected {
				t.Fatal("healthy configuration follow did not renew immediately")
			}
		case <-time.After(time.Second):
			t.Fatal("report request blocked authenticated configuration following")
		}
	}
	cancel()
	select {
	case err := <-configurationJoined:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("configuration wait did not return cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("configuration request was not joined")
	}
	select {
	case <-reportJoined:
	case <-time.After(time.Second):
		t.Fatal("report request was not canceled and joined")
	}
	select {
	case <-results:
		t.Fatal("canceled generation published a stale report confirmation")
	default:
	}
}

func TestWindowsFailedConfigurationChannelWaitsAndCancellationDoesNotWaitForRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	done := make(chan error, 1)
	calls := 0
	go func() {
		done <- followWindowsConfiguration(ctx, time.Hour, func(context.Context) (bool, error) {
			calls++
			close(started)
			return false, nil
		})
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || calls != 1 {
			t.Fatal("failed-channel retry ignored cancellation or spun", err)
		}
	case <-time.After(time.Second):
		t.Fatal("failed-channel retry delayed shutdown")
	}
}

func TestWindowsReportQueueKeepsInflightAndOnlyNewestPendingSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requests := make(chan *windowsReportAttempt, 1)
	results := make(chan windowsReportResult, 1)
	started := make(chan int64, 2)
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		uploadWindowsReports(ctx, requests, results, func(ctx context.Context, report control.DeviceReport) error {
			started <- report.ReportedAt
			if report.ReportedAt == 1 {
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
	}()
	first := &windowsReportAttempt{report: control.DeviceReport{ReportedAt: 1}, facts: "demo-first"}
	latest := &windowsReportAttempt{report: control.DeviceReport{ReportedAt: 3}, facts: "demo-latest"}
	offerLatestWindows(requests, first)
	<-started
	offerLatestWindows(requests, &windowsReportAttempt{report: control.DeviceReport{ReportedAt: 2}})
	offerLatestWindows(requests, latest)
	close(release)
	select {
	case got := <-started:
		if got != 3 {
			t.Fatal("superseded queued report was sent")
		}
	case <-time.After(time.Second):
		t.Fatal("latest report was not sent")
	}
	// Wait for the second result, allowing the consumer to observe the first
	// in flight. Its attempt identity prevents an old ACK confirming new facts.
	for {
		select {
		case result := <-results:
			if result.attempt == latest {
				cancel()
				<-done
				return
			}
			if result.attempt != first {
				t.Fatal("report ACK has no exact originating snapshot")
			}
		case <-time.After(time.Second):
			t.Fatal("latest report did not complete")
		}
	}
}

func TestWindowsNetworkChangeInvalidatesEmptySampleReportAndItsACK(t *testing.T) {
	activation := clientadapter.Activation{
		State: clientadapter.State{
			Preference:        clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"},
			NetworkGeneration: "demo-network-before",
		},
		Selections: []clientadapter.SelectionStatus{{Scope: control.AccessSelectorScope, CandidateID: "demo-direct", State: "unknown"}},
	}
	const view = "demo-view"
	previous := windowsRuntimeFactsDigest(activation, nil)
	pending := &windowsReportAttempt{report: control.DeviceReport{ViewDigest: view, NetworkGeneration: activation.State.NetworkGeneration}, facts: previous}
	if !windowsReportMatches(pending, view, previous) {
		t.Fatal("current report snapshot did not match itself")
	}
	activation.State.NetworkGeneration = "demo-network-after"
	current := windowsRuntimeFactsDigest(activation, nil)
	if current == previous {
		t.Fatal("unchanged Direct selection and empty samples hid a new network generation")
	}
	// This is the same predicate used to suppress duplicate pending reports
	// and to accept their ACK. Both must reject the old network snapshot.
	if windowsReportMatches(pending, view, current) {
		t.Fatal("old network report suppressed the new report or confirmed its current status")
	}
}

func TestWindowsResourceCompletionInvalidatesPendingReportAndItsACK(t *testing.T) {
	activation := clientadapter.Activation{State: clientadapter.State{NetworkGeneration: "demo-network"}}
	view := control.ReleaseDigest([]byte("demo-view"))
	pendingRuntime := windowsResourceReadback(view, true, false)
	if pendingRuntime.Validate() != nil || pendingRuntime.State != "unknown" || pendingRuntime.AppliedViewDigest != "" || pendingRuntime.Resources != nil {
		t.Fatal("pending resources manufactured a complete application proof")
	}
	previous := windowsRuntimeFactsDigest(activation, nil, pendingRuntime)
	pending := &windowsReportAttempt{report: control.DeviceReport{ViewDigest: view, Runtime: pendingRuntime}, facts: previous}
	ready := windowsResourceReadback(view, true, true)
	if ready.Validate() != nil {
		t.Fatal("completed resource proof did not retain its exact accepted View")
	}
	current := windowsRuntimeFactsDigest(activation, nil, ready)
	if current == previous || windowsReportMatches(pending, view, current) {
		t.Fatal("resource completion reused an unknown report or accepted its old ACK")
	}
	if unconfirmed := windowsResourceReadback(view, false, false); unconfirmed.PermissionViewDigest != "" || unconfirmed.HasCurrentPermissions(view) {
		t.Fatal("an unconfirmed permission acquired a report proof")
	}
}
