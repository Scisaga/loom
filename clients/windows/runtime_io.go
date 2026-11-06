package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

// These one-slot messages belong only to the running client. They are wakeups
// and immutable report inputs, never another configuration or delivery store.
type windowsReportAttempt struct {
	report control.DeviceReport
	facts  string
}

type windowsReportResult struct {
	attempt *windowsReportAttempt
	err     error
}

// A channel has one producer. Replacing a queued value does not disturb an
// in-flight request, whose caller owns its cancellation and completion.
func offerLatestWindows[T any](pending chan T, value T) {
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

// A healthy private channel waits continuously through the existing config
// operation. A failed channel retries independently of measurements/reports.
func followWindowsConfiguration(ctx context.Context, retry time.Duration, refresh func(context.Context) (bool, error)) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		reachable, err := refresh(ctx)
		if err != nil {
			return err
		}
		if !reachable {
			timer := time.NewTimer(retry)
			select {
			case <-ctx.Done():
			case <-timer.C:
			}
			timer.Stop()
		}
	}
}

func uploadWindowsReports(ctx context.Context, requests <-chan *windowsReportAttempt, results chan windowsReportResult, post func(context.Context, control.DeviceReport) error) {
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
			offerLatestWindows(results, windowsReportResult{attempt, err})
		}
	}
}

func windowsResourceReadback(viewDigest string, permissionCurrent, ready bool) control.RuntimeReadback {
	if !permissionCurrent {
		return control.RuntimeReadback{State: "unknown", ErrorCode: "authorization_unconfirmed"}
	}
	if !ready {
		return control.RuntimeReadback{State: "unknown", PermissionViewDigest: viewDigest, ErrorCode: "resources_pending"}
	}
	return control.RuntimeReadback{State: "running", AppliedViewDigest: viewDigest, PermissionViewDigest: viewDigest}
}

func windowsRuntimeFactsDigest(activation clientadapter.Activation, components []control.ComponentReadback, runtime ...control.RuntimeReadback) string {
	var readback *control.RuntimeReadback
	if len(runtime) != 0 {
		readback = &runtime[0]
	}
	body, _ := json.Marshal(struct {
		NetworkGeneration    string                          `json:"network_generation"`
		Preference           clientmodel.Preference          `json:"preference"`
		Selections           []clientadapter.SelectionStatus `json:"selections"`
		BlockedScopes        []string                        `json:"blocked_scopes,omitempty"`
		Observations         []clientmodel.Observation       `json:"observations"`
		ResourceObservations []control.Observation           `json:"resource_observations,omitempty"`
		Components           []control.ComponentReadback     `json:"components"`
		Runtime              *control.RuntimeReadback        `json:"runtime,omitempty"`
	}{NetworkGeneration: activation.State.NetworkGeneration, Preference: activation.State.Preference, Selections: activation.Selections, BlockedScopes: activation.BlockedScopes, Observations: activation.State.Observations,
		ResourceObservations: activation.State.ResourceObservations, Components: components, Runtime: readback})
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func windowsReportMatches(attempt *windowsReportAttempt, viewDigest, facts string) bool {
	return attempt != nil && attempt.report.ViewDigest == viewDigest && attempt.facts == facts
}
