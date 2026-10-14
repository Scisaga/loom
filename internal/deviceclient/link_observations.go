package deviceclient

import (
	"context"
	"errors"
	"loom/internal/control"
)

// FetchLinkObservations reads only current recipient-scoped samples. It never
// saves a View, advances authentication or echoes remote samples in a report.
func FetchLinkObservations(ctx context.Context, store IdentityStore) (control.DeviceLinkObservations, error) {
	lkg := store.LKG()
	if lkg == nil {
		return control.DeviceLinkObservations{}, errors.New("device has no accepted View")
	}
	connection, err := deviceConnection(ctx, store)
	if err != nil {
		return control.DeviceLinkObservations{}, err
	}
	defer connection.Close()
	var result control.DeviceLinkObservations
	if _, err = postJSON(ctx, connection, "/device/link-observations", control.DeviceLinkObservationRequest{Schema: 3, ViewDigest: lkg.ViewDigest}, &result); err != nil {
		return control.DeviceLinkObservations{}, err
	}
	current := store.LKG()
	if current == nil || current.ViewDigest != lkg.ViewDigest {
		return control.DeviceLinkObservations{}, errors.New("device View changed during observation fetch")
	}
	return result, result.ValidateForView(current.View)
}
