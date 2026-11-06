package deviceclient

import (
	"context"
	"errors"
	"net"
	"slices"

	"loom/internal/control"
)

// FetchLinkObservations reads only current recipient-scoped samples. It never
// saves a View, advances authentication or echoes remote samples in a report.
func FetchLinkObservations(ctx context.Context, store IdentityStore, previous *control.DeviceLinkObservations) (control.DeviceLinkObservations, error) {
	if err := ctx.Err(); err != nil {
		return control.DeviceLinkObservations{}, err
	}
	lkg := store.LKG()
	if lkg == nil {
		return control.DeviceLinkObservations{}, errors.New("device has no accepted View")
	}
	// The cursor and base are one immutable request input. In-flight endpoint
	// attempts must not reread a caller's replaced cache while merging a delta.
	var base *control.DeviceLinkObservations
	cursor := ""
	if previous != nil && previous.Reset {
		snapshot := cloneMeasurementSnapshot(*previous)
		if snapshot.ValidateForView(lkg.View) == nil {
			body, err := control.CanonicalEncode(snapshot)
			if err == nil && len(body) <= control.MeasurementDeliveryLimit {
				base, cursor = &snapshot, snapshot.Cursor
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return control.DeviceLinkObservations{}, err
	}
	return requestDevice(ctx, store, lkg, 2, deviceRequestTimeout, func(attempt context.Context, connection net.Conn) (control.DeviceLinkObservations, error) {
		var result control.DeviceLinkObservations
		if _, err := postJSON(attempt, connection, "/device/link-observations", control.DeviceLinkObservationRequest{Schema: 3, ViewDigest: lkg.ViewDigest, Cursor: cursor}, &result); err != nil {
			return control.DeviceLinkObservations{}, err
		}
		merged, err := control.MergeMeasurementDelivery(base, result, lkg.View)
		if err != nil {
			return control.DeviceLinkObservations{}, err
		}
		if err := attempt.Err(); err != nil {
			return control.DeviceLinkObservations{}, err
		}
		current := store.LKG()
		if current == nil || current.ViewDigest != lkg.ViewDigest {
			return control.DeviceLinkObservations{}, errors.New("device View changed during observation fetch")
		}
		if err := attempt.Err(); err != nil {
			return control.DeviceLinkObservations{}, err
		}
		return merged, nil
	})
}

// Copy only mutable typed fields. Strings and report references are immutable;
// a JSON round trip would repeat complete decoding for an already typed cache.
func cloneMeasurementSnapshot(value control.DeviceLinkObservations) control.DeviceLinkObservations {
	value.Removed = slices.Clone(value.Removed)
	value.Observations = slices.Clone(value.Observations)
	for i := range value.Observations {
		sample := &value.Observations[i].Observation
		if sample.DurationMS != nil {
			copy := *sample.DurationMS
			sample.DurationMS = &copy
		}
		if sample.RoundTripMS != nil {
			copy := *sample.RoundTripMS
			sample.RoundTripMS = &copy
		}
		if sample.HY2Transfer != nil {
			copy := *sample.HY2Transfer
			sample.HY2Transfer = &copy
		}
	}
	return value
}
