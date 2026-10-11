package linuxclient

import (
	"bytes"
	"context"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

// These values belong only to the running generation. The report and its
// readback are immutable snapshots, not a durable delivery queue.
type runtimeReportAttempt struct {
	report control.DeviceReport
	status Status
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

func refreshPrivateConfiguration(ctx context.Context, store *deviceclient.Store, requests <-chan struct{}, notices chan string, failures chan<- error, cancel context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-requests:
		}
		if ctx.Err() != nil {
			return
		}
		var log bytes.Buffer
		changed, err := certifiedViewChanged(ctx, store, &log)
		if err != nil || changed {
			if err == nil {
				err = errCertifiedViewChanged
			}
			failures <- err
			cancel()
			return
		}
		if log.Len() != 0 && ctx.Err() == nil {
			offerLatest(notices, log.String())
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
	status := pending.status
	status.Reported = result.err == nil
	return WriteStatus(path, status)
}
