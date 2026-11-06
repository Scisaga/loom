package control

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// DeviceLinkObservations is a disposable, scoped delivery of original report
// samples. Transport authentication covers this projection; it is not authority.
type DeviceLinkObservations struct {
	Cursor       string                  `json:"cursor"`
	Reset        bool                    `json:"reset"`
	Removed      []string                `json:"removed"`
	Schema       int                     `json:"schema"`
	NetworkID    string                  `json:"network_id"`
	DeviceID     string                  `json:"device_id"`
	ViewDigest   string                  `json:"view_digest"`
	Observations []DeviceLinkObservation `json:"observations"`
}

type DeviceLinkObservation struct {
	DeviceID       string      `json:"device_id"`
	ReportSequence U64         `json:"report_sequence"`
	ReportDigest   string      `json:"report_digest"`
	CurrentUntil   int64       `json:"current_until"`
	Observation    Observation `json:"observation"`
}

type DeviceLinkObservationRequest struct {
	Cursor     string `json:"cursor,omitempty"`
	Schema     int    `json:"schema"`
	ViewDigest string `json:"view_digest"`
}

func (v DeviceLinkObservationRequest) Validate() error {
	if v.Schema != 3 || ValidateDigest(v.ViewDigest) != nil || v.Cursor != "" && !validMeasurementCursor(v.Cursor) {
		return errors.New("invalid link observation request")
	}
	return nil
}

func validMeasurementCursor(cursor string) bool {
	if len(cursor) == 0 || len(cursor) > 128 {
		return false
	}
	for _, ch := range cursor {
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

func (v DeviceLinkObservation) Validate() error {
	if ValidateID(v.DeviceID) != nil || v.ReportSequence == 0 || ValidateDigest(v.ReportDigest) != nil || v.Observation.Validate() != nil || v.CurrentUntil <= v.Observation.ObservedAt || v.CurrentUntil > v.Observation.ValidUntil {
		return errors.New("invalid original report observation reference")
	}
	return nil
}

func (v DeviceLinkObservations) Validate() error {
	if v.Schema != 3 || ValidateID(v.NetworkID) != nil || ValidateID(v.DeviceID) != nil || ValidateDigest(v.ViewDigest) != nil || v.Observations == nil || v.Removed == nil || !validMeasurementCursor(v.Cursor) || v.Reset && len(v.Removed) != 0 {
		return errors.New("invalid link observation delivery")
	}
	for i, sample := range v.Observations {
		if sample.Validate() != nil || sample.Observation.Level != "link" && sample.Observation.Level != "egress" || i > 0 && measurementDeliveryOrder(v.Observations[i-1]) >= measurementDeliveryOrder(sample) {
			return errors.New("link observations are not uniquely sorted")
		}
	}
	for index, id := range v.Removed {
		if ValidateDigest(id) != nil || index > 0 && v.Removed[index-1] >= id {
			return errors.New("removed measurement items are invalid or unsorted")
		}
	}
	removed := make(map[string]bool, len(v.Removed))
	for _, id := range v.Removed {
		removed[id] = true
	}
	for _, sample := range v.Observations {
		id, err := MeasurementItemID(sample)
		if err != nil || removed[id] {
			return errors.New("measurement item cannot be removed and updated in one delivery")
		}
	}
	return nil
}

// ValidateForView matches every sample to the recipient's exact signed scope.
func (v DeviceLinkObservations) ValidateForView(view DeviceView) error {
	digest, err := DeviceViewDigest(view)
	if err != nil {
		return errors.New("link observation delivery belongs to another View")
	}
	return v.validateForViewDigest(view, digest)
}

// Only the current call's successfully validated, unchanged View may supply this
// digest. External callers use ValidateForView and independently validate it.
func (v DeviceLinkObservations) validateForViewDigest(view DeviceView, digest string) error {
	if v.Validate() != nil || v.NetworkID != view.NetworkID || v.DeviceID != view.DeviceID || v.ViewDigest != digest {
		return errors.New("link observation delivery belongs to another View")
	}
	if len(v.Observations) == 0 {
		return nil
	}
	inventory := newMeasurementInventory(view)
	for _, sample := range v.Observations {
		if err := validateDeliveredMeasurement(view, inventory, sample); err != nil {
			return err
		}
	}

	return nil
}

func validateDeliveredMeasurement(view DeviceView, inventory *measurementInventory, sample DeviceLinkObservation) error {
	if sample.Validate() != nil {
		return errors.New("invalid delivered original sample")
	}
	if sample.Observation.Level == "egress" {
		if !inventory.egressAllowed(sample.DeviceID, sample.Observation.Target) {
			return errors.New("egress measurement is outside the recipient's allowed exit and Service request")
		}
		return nil
	}
	resource, found := inventory.byResource[sample.Observation.ResourceID]
	if !found {
		return errors.New("link resource is outside the recipient View")
	}
	link, allowed, err := inventory.link(sample.DeviceID, resource.ID)
	if err != nil || !allowed {
		return errors.New("link source is outside the recipient View")
	}
	spec, err := directedLinkSpec(view.NetworkID, link, inventory.nodes[sample.DeviceID], resource)
	if err != nil || !matchesNativeLinkObservation(sample.Observation, link, spec) {
		return errors.New("link observation is outside the recipient View")
	}
	return nil
}

// Queries use current role, resource and request specifications. The original
// report's unrelated View fields are not part of a measurement's identity.
func projectDeviceLinkObservations(ctx context.Context, store *ObservationStore, projection Projection, recipient, requestedDigest string, now time.Time, viewFor func(string) (DeviceView, string, error)) (DeviceLinkObservations, error) {
	result, _, err := projectDeviceMeasurementWindow(ctx, store, projection, recipient, requestedDigest, "", now, viewFor, defaultMeasurementDeliveryBounds, nil)
	return result, err
}
func deviceMeasurementQueries(projection Projection, view DeviceView, viewFor func(string) (DeviceView, string, error)) ([]reportMeasurementQuery, error) {
	page, err := deviceMeasurementQueryPage(context.Background(), projection, view, viewFor, 0, defaultMeasurementDeliveryBounds)
	if err != nil {
		return nil, err
	}
	result := make([]reportMeasurementQuery, 0, len(page.queries))
	for _, item := range page.queries {
		result = append(result, item.query)
	}
	return result, nil
}

// This closure owns only successful projections and digests for one request.
// It is discarded before the next authorization and release inputs are read.
func deviceLinkViewFor(project func(string) (DeviceView, error)) func(string) (DeviceView, string, error) {
	views := map[string]struct {
		view   DeviceView
		digest string
	}{}
	return func(id string) (DeviceView, string, error) {
		if value, ok := views[id]; ok {
			return value.view, value.digest, nil
		}
		view, err := project(id)
		if err != nil {
			return DeviceView{}, "", err
		}
		if view.DeviceID != id {
			return DeviceView{}, "", errors.New("projected View belongs to another device")
		}
		digest, err := DeviceViewDigest(view)
		if err != nil {
			return DeviceView{}, "", err
		}
		views[id] = struct {
			view   DeviceView
			digest string
		}{view, digest}
		return view, digest, nil
	}
}

func (server *Server) deviceLinkObservations(w http.ResponseWriter, r *http.Request) {
	identity, ok := tunnelAuth(r)
	if !ok || identity.Mode != "device" || server.Runtime.Reports == nil {
		http.Error(w, "device observation authentication required", http.StatusForbidden)
		return
	}
	var request DeviceLinkObservationRequest
	if !readDeviceJSON(w, r, &request) {
		return
	}
	configuration, err := server.newDeviceConfigRequest()
	if err != nil {
		http.Error(w, "current device View unavailable", http.StatusServiceUnavailable)
		return
	}
	projection := configuration.input.projection
	views := map[string]struct {
		view   DeviceView
		digest string
	}{}
	viewFor := func(id string) (DeviceView, string, error) {
		value, found := views[id]
		if !found {
			var err error
			value.view, value.digest, err = configuration.view(r.Context(), id)
			if err != nil {
				return DeviceView{}, "", err
			}
			views[id] = value
		}
		return value.view, value.digest, nil
	}
	_, digest, err := viewFor(identity.DeviceID)
	if err != nil || request.Validate() != nil || digest != request.ViewDigest {
		http.Error(w, "current device View required", http.StatusConflict)
		return
	}
	result, next, err := projectDeviceMeasurementWindow(r.Context(), server.Runtime.Reports, projection, identity.DeviceID, digest, request.Cursor, server.now(), viewFor, defaultMeasurementDeliveryBounds, server.measurementBase(request.Cursor, identity.DeviceID, digest))
	if err != nil || configuration.finish() != nil {
		http.Error(w, "link observations unavailable", http.StatusServiceUnavailable)
		return
	}
	result, err = server.issueMeasurementDelivery(result, request.Cursor, measurementDeliveryOptions{next, defaultMeasurementDeliveryBounds})
	if err != nil {
		http.Error(w, "measurement delivery unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := CanonicalEncode(result)
	if err != nil {
		http.Error(w, "canonical response unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeReportBody(w, r, body)
}
