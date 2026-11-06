package linuxclient

import (
	"bytes"
	"context"
	"time"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

// These values belong only to the running generation. The report and its
// readback are immutable snapshots, not a durable delivery queue.
type runtimeReportAttempt struct {
	report control.DeviceReport
	status Status
}

// Delivery is replaced as a whole and lives only in this running generation.
// Failed reads preserve the exact base and cursor without extending deadlines.
func refreshPrivateLinkObservations(ctx context.Context, store *deviceclient.Store, requests <-chan struct{}, results chan control.DeviceLinkObservations) {
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
		value, err := deviceclient.FetchLinkObservations(pending, store, cached)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			continue
		}
		cached = &value
		offerLatest(results, value)
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
