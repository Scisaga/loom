package loomcore

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"loom/internal/control"
)

// This deterministic context changes at the encoder's next fence, without
// relying on a timing-sensitive goroutine racing the JSON encoder.
type measurementCancelAfterEncoding struct {
	context.Context
	reads int
}

func (c *measurementCancelAfterEncoding) Err() error {
	c.reads++
	if c.reads > 1 {
		return context.Canceled
	}
	return nil
}

func TestAndroidMeasurementOutputHasOneCanonicalBoundAndCancellationFence(t *testing.T) {
	value := control.DeviceLinkObservations{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-access", ViewDigest: control.ReleaseDigest([]byte("demo-view")), Cursor: "demo-base", Reset: true, Removed: []string{}, Observations: []control.DeviceLinkObservation{}}
	want, _ := control.CanonicalEncode(value)
	body, err := encodeAndroidMeasurementSnapshot(context.Background(), value)
	if err != nil || !bytes.Equal(body, want) {
		t.Fatal("bridge rewrote the complete snapshot", err)
	}
	ctx := &measurementCancelAfterEncoding{Context: context.Background()}
	if body, err := encodeAndroidMeasurementSnapshot(ctx, value); !errors.Is(err, context.Canceled) || len(body) != 0 {
		t.Fatal("cancelled encoding returned a committable snapshot", err)
	}
	// This isolated encoder test exercises the byte boundary, not View scope.
	// Scope and observation semantics are already checked by Fetch/Merge.
	value.Cursor = strings.Repeat("x", androidMeasurementSnapshotLimit)
	if body, err := encodeAndroidMeasurementSnapshot(context.Background(), value); err == nil || len(body) != 0 {
		t.Fatal("oversized canonical output reached the host")
	}
}
