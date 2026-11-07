package linuxclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

func measurementDiagnosticHash(value string) string {
	if value == "" {
		return "-"
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Hash canonical public facts as an unordered set. No cursor, target, source
// identifier or sample content reaches the log, and ordering cannot change it.
func measurementDiagnosticSet(values []control.DeviceLinkObservation) string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		body, err := control.CanonicalEncode(value)
		if err != nil {
			return "unavailable"
		}
		items = append(items, measurementDiagnosticHash(string(body)))
	}
	sort.Strings(items)
	body, err := control.CanonicalEncode(items)
	if err != nil {
		return "unavailable"
	}
	return measurementDiagnosticHash(string(body))
}

func logPrivateLinkDelivery(log func(string) error, event string, base, value *control.DeviceLinkObservations, expectedView, validation string, cause error, adopted []control.DeviceLinkObservation) {
	if log == nil {
		return
	}
	defer func() { _ = recover() }()
	mode, baseCursor, baseSet, baseCount := "nil", "-", "-", 0
	if event == "consume" {
		mode = "unknown"
	} else if base != nil {
		mode, baseCursor, baseSet, baseCount = "cache", measurementDiagnosticHash(base.Cursor), measurementDiagnosticSet(base.Observations), len(base.Observations)
	}
	cursor, set, view, count := "-", "-", "-", 0
	if value != nil {
		cursor, set, view, count = measurementDiagnosticHash(value.Cursor), measurementDiagnosticSet(value.Observations), measurementDiagnosticHash(value.ViewDigest), len(value.Observations)
	}
	outcome := "success"
	var timeout net.Error
	switch {
	case errors.Is(cause, context.Canceled):
		outcome = "canceled"
	case errors.Is(cause, context.DeadlineExceeded), errors.As(cause, &timeout) && timeout.Timeout():
		outcome = "timeout"
	case cause != nil:
		outcome = "failed"
	}
	// Fetch returns an already merged cache. Its Reset field cannot reveal the
	// server's wire reset/delta, so that unavailable fact stays explicitly unknown.
	_ = log(fmt.Sprintf("measurements event=%s base=%s base_cursor=%s base_count=%d base_set=%s cursor=%s merged_count=%d merged_set=%s view=%s expected_view=%s validate=%s outcome=%s adopted_count=%d adopted_set=%s wire_mode=unknown",
		event, mode, baseCursor, baseCount, baseSet, cursor, count, set, view, measurementDiagnosticHash(expectedView), validation, outcome, len(adopted), measurementDiagnosticSet(adopted)))
}

// These values belong only to the running generation. The report and its
// readback are immutable snapshots, not a durable delivery queue.
type runtimeReportAttempt struct {
	report control.DeviceReport
	status Status
}

// Delivery is replaced as a whole and lives only in this running generation.
// Failed reads preserve the exact base and cursor without extending deadlines.
func refreshPrivateLinkObservations(ctx context.Context, store *deviceclient.Store, requests <-chan struct{}, results chan control.DeviceLinkObservations, diagnostic ...func(string) error) {
	var log func(string) error
	if len(diagnostic) > 0 {
		log = diagnostic[0]
	}
	refreshPrivateLinkObservationsWithFetch(ctx, store, requests, results, deviceclient.FetchLinkObservations, log)
}

func refreshPrivateLinkObservationsWithFetch(ctx context.Context, store *deviceclient.Store, requests <-chan struct{}, results chan control.DeviceLinkObservations,
	fetch func(context.Context, deviceclient.IdentityStore, *control.DeviceLinkObservations) (control.DeviceLinkObservations, error), diagnostic func(string) error) {
	var cached *control.DeviceLinkObservations
	for {
		select {
		case <-ctx.Done():
			return
		case <-requests:
		}
		lkg := store.LKG()
		if lkg == nil {
			return
		}
		pending, cancel := context.WithTimeout(ctx, 10*time.Second)
		base := cached
		value, err := fetch(pending, store, cached)
		cancel()
		if ctx.Err() != nil {
			logPrivateLinkDelivery(diagnostic, "fetch", base, nil, lkg.ViewDigest, "not-run", ctx.Err(), nil)
			return
		}
		if err != nil {
			logPrivateLinkDelivery(diagnostic, "fetch", base, nil, lkg.ViewDigest, "not-run", err, nil)
			continue
		}
		cached = &value
		offerLatest(results, value)
		if diagnostic != nil {
			validation := "valid"
			if value.ValidateForView(lkg.View) != nil {
				validation = "invalid"
			}
			logPrivateLinkDelivery(diagnostic, "fetch", base, &value, lkg.ViewDigest, validation, nil, nil)
		}
	}
}

type runtimeReportResult struct {
	attempt *runtimeReportAttempt
	err     error
}

// Each one-slot channel has exactly one producer. Replacing a pending value
// cannot interfere with the consumer's in-flight request.
func offerLatest[T any](pending chan T, value T) {
	select {
	case pending <- value:
		return
	default:
	}
	select {
	case <-pending:
	default:
	}
	pending <- value
}

func refreshPrivateConfiguration(ctx context.Context, store *deviceclient.Store, requests <-chan struct{}, notices chan string, failures chan<- error, cancel context.CancelFunc, interruptWork func()) {
	select {
	case <-ctx.Done():
		return
	case <-requests:
	}
	var round uint64
	for {
		// Reload requests may shorten a failed-channel retry. A healthy
		// channel follows continuously, independent of the runtime's ticker.
		select {
		case <-requests:
		default:
		}
		if ctx.Err() != nil {
			return
		}
		var log bytes.Buffer
		before := store.LKG()
		changed, reachable, err := refreshCertifiedView(ctx, store, &log, func(ctx context.Context, identity deviceclient.IdentityStore) (control.DeviceViewEnvelope, error) {
			return deviceclient.AwaitConfiguration(ctx, identity, round)
		})
		round++
		if err != nil {
			failures <- err
			cancel()
			return
		}
		after := store.LKG()
		if changed || before != nil && after != nil && before.Signature != after.Signature {
			// The runtime owner applies accepted permissions and peer deltas.
			// Stop outstanding measurement work so it reaches that boundary now;
			// do not tear down unrelated business connections in this I/O worker.
			offerLatest(notices, "authenticated configuration accepted; applying runtime changes\n")
			if changed {
				interruptWork()
			}
			continue
		}
		if log.Len() != 0 && ctx.Err() == nil {
			offerLatest(notices, log.String())
		}
		if !reachable {
			timer := time.NewTimer(5 * time.Second)
			select {
			case <-ctx.Done():
			case <-requests:
			case <-timer.C:
			}
			timer.Stop()
		}
	}
}

func uploadRuntimeReports(ctx context.Context, requests <-chan *runtimeReportAttempt, results chan runtimeReportResult, post func(context.Context, control.DeviceReport) error) {
	for {
		select {
		case <-ctx.Done():
			return
		case attempt := <-requests:
			if ctx.Err() != nil {
				return
			}
			err := post(ctx, attempt.report)
			if ctx.Err() != nil {
				return
			}
			offerLatest(results, runtimeReportResult{attempt: attempt, err: err})
		}
	}
}

func writeReportConfirmation(path string, pending *runtimeReportAttempt, result runtimeReportResult) error {
	if result.attempt != pending {
		return nil
	}
	current, err := ReadStatus(path)
	if err != nil {
		return err
	}
	expected := pending.status
	current.Reported, expected.Reported = false, false
	currentBody, currentErr := control.CanonicalEncode(current)
	expectedBody, expectedErr := control.CanonicalEncode(expected)
	if currentErr != nil {
		return currentErr
	}
	if expectedErr != nil {
		return expectedErr
	}
	if !bytes.Equal(currentBody, expectedBody) {
		return nil
	}
	status := pending.status
	status.Reported = result.err == nil
	return WriteStatus(path, status)
}
