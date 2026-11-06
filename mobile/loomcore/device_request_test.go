package loomcore

import (
	"context"
	"errors"
	"testing"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

func TestAndroidPrivateRequestCancellationAndConcurrentProgress(t *testing.T) {
	state, body := androidFixture(t, 7, false)
	for _, create := range []func([]byte) (*AndroidDeviceRequest, error){
		func(body []byte) (*AndroidDeviceRequest, error) {
			return NewAndroidConfigurationRequest(body, false, 0)
		},
		func(body []byte) (*AndroidDeviceRequest, error) { return NewAndroidConfigurationRequest(body, true, 1) },
		NewAndroidEnrollmentRequest,
	} {
		request, err := create(body)
		if err != nil {
			t.Fatal(err)
		}
		request.Cancel()
		if _, err := request.Run(); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled private request attempted I/O", err)
		}
	}
	// This is the state at HTTP dispatch. The actual protected record advances
	// before the signed envelope arrives and must be the acceptance input.
	current, sequence, err := deviceclient.AdvanceReportSequence(state)
	if err != nil {
		t.Fatal(err)
	}
	currentBytes, _ := deviceclient.EncodeIdentityState(current)
	reportRequest, err := NewAndroidReportRequest(currentBytes, nil, nil, []byte("[]"), []byte("[]"),
		[]byte(`{"state":"stopped","applied_view_digest":"","error_code":""}`), []byte("[]"), nil, "demo-underlay", "2030-01-01T00:00:00.000Z")
	if err != nil {
		t.Fatal(err)
	}
	reportRequest.Cancel()
	if _, err := reportRequest.Run(); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled report attempted I/O", err)
	}
	if current.ReportSequence != sequence || state.ReportSequence >= sequence {
		t.Fatal("cancelled report reset or reused its reserved sequence")
	}
	response, _ := androidFixture(t, 8, false)
	envelope, _ := control.CanonicalEncode(response.LKG)
	acceptedBytes, err := AcceptAndroidCertifiedView(currentBytes, envelope)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := decodeState(acceptedBytes)
	if err != nil || accepted.ReportSequence != sequence || accepted.PrivateKey != state.PrivateKey || !accepted.AuthenticatedLatch {
		t.Fatal("configuration arrival lost concurrent persistent progress", err)
	}
	if err := deviceclient.CheckIdentityStateAdvance(accepted, current); err != nil {
		t.Fatal("configuration did not retain the current authentication floor", err)
	}
}
