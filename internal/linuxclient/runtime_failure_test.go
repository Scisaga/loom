package linuxclient

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestResourceTimeoutClassificationRejectsCryptoCancellationAndUnclassifiedErrors(t *testing.T) {
	for _, err := range []error{context.DeadlineExceeded, &quic.HandshakeTimeoutError{}, &quic.IdleTimeoutError{}, &net.DNSError{IsTimeout: true}} {
		if !errors.Is(resourceProbeFailure(err), errResourceReadbackTimeout) {
			t.Fatal("a definite timeout did not preserve its retryable observation boundary")
		}
	}
	for _, err := range []error{context.Canceled, net.ErrClosed, errors.New("demo-secret 192.0.2.1"), x509.UnknownAuthorityError{},
		&quic.TransportError{ErrorCode: 0x12a, ErrorMessage: "demo-secret 192.0.2.1"}} {
		failure := resourceProbeFailure(err)
		if errors.Is(failure, errResourceReadbackTimeout) || strings.Contains(failure.Error(), "demo-secret") || strings.Contains(failure.Error(), "192.0.2.1") {
			t.Fatal("identity/cancellation/unclassified failure was retried or disclosed raw transport text")
		}
	}
	for _, safety := range []error{ErrWireGuardOwnership, ErrWireGuardCleanup, errCertifiedPersistence} {
		failure := safeRuntimeFailure(errors.Join(resourceProbeFailure(context.DeadlineExceeded), safety))
		if failure.class == "network_timeout" || !errors.Is(failure, safety) {
			t.Fatal("a timeout hid a safety failure")
		}
	}
}

func TestProcessFailureReportsOnlyExitAndSignal(t *testing.T) {
	for _, command := range []string{"exit 7", "kill -KILL $$"} {
		err := exec.Command("sh", "-c", command).Run()
		failure := processFailure("resource_process", err).(*runtimeFailure)
		if failure.class != "process_exit" || failure.exit != 7 && failure.signal != 9 || strings.Contains(failure.Error(), command) {
			t.Fatal("process exit lost its bounded diagnostic", failure)
		}
	}
}

func TestUnknownRuntimeKeepsComponentsAndOriginalObservationTimes(t *testing.T) {
	store, _, makeView := linuxAcceptanceFixture(t, func(_ uint64, view *control.DeviceView) {
		view.BusinessProbeTargets = []control.ServiceProbeTargets{{ServiceID: "demo-service", Targets: []string{"https://demo-service.example/"}}}
	})
	lkg := makeView(7, true)
	if err := store.SaveLKG(lkg); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Second)
	state := defaultState("demo-network")
	state.ObservationViewDigest = lkg.ViewDigest
	state.Observations = []clientmodel.Observation{{CandidateID: lkg.View.Routes[0].ID, Scope: lkg.View.Routes[0].Scope, NetworkGeneration: state.NetworkGeneration,
		Result: "available", Target: "https://demo-service.example/", Action: "https_request", ObservedAt: at.Format(time.RFC3339), ValidUntil: at.Add(time.Minute).Format(time.RFC3339)}}
	activation := Activation{State: state, Selections: []SelectionStatus{{CandidateID: lkg.View.Routes[0].ID, Scope: lkg.View.Routes[0].Scope}}}
	components, err := linuxComponentReadbacks(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	readback := control.RuntimeReadback{State: "unknown", ErrorCode: "resource_readback_timeout"}
	report, err := selectionReport(context.Background(), lkg, activation, at, components, readback, nil, nil)
	if err != nil || len(report.Selections) != 0 || report.Runtime.AppliedViewDigest != "" || report.Runtime.Resources != nil || report.WireGuardCounters != nil || !reflect.DeepEqual(report.Components, components) {
		t.Fatal("unknown acquired current application evidence or erased actual component coordinates", err)
	}
	report.Schema, report.NetworkID, report.DeviceID, report.ReportSequence = 3, lkg.NetworkID, lkg.View.DeviceID, 1
	signed, err := control.SignDeviceReport(report, store.PrivateKey())
	if err != nil || signed.Verify(store.PublicKey()) != nil || len(signed.Observations) != 1 || signed.Observations[0].ValidUntil != at.Add(time.Minute).UnixMilli() {
		t.Fatal("unknown could not be authenticated or renewed original observation times", err)
	}
	status := runtimeStatus(&lkg, activation, false, readback)
	path := filepath.Join(t.TempDir(), "status.json")
	if err := WriteStatus(path, status); err != nil {
		t.Fatal(err)
	}
	actual, err := ReadStatus(path)
	if err != nil || actual.Runtime != "unknown" || len(actual.Selections) != 0 || len(actual.Observations) != 0 || len(actual.Resources) != 0 || !reflect.DeepEqual(activation.State, state) {
		t.Fatal("unknown was unreadable, retained current projections, or modified its observation input", err)
	}
	status.Selections = activation.Selections
	if WriteStatus(path, status) == nil {
		t.Fatal("unknown accepted an unqualified current selection")
	}
}
