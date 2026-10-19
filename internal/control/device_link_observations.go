package control

import (
	"errors"
	"net/http"
	"sort"
	"time"
)

// DeviceLinkObservations is a disposable, scoped delivery of original report
// samples. Transport authentication covers this projection; it is not authority.
type DeviceLinkObservations struct {
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
	Schema     int    `json:"schema"`
	ViewDigest string `json:"view_digest"`
}

func (v DeviceLinkObservationRequest) Validate() error {
	if v.Schema != 3 || ValidateDigest(v.ViewDigest) != nil {
		return errors.New("invalid link observation request")
	}
	return nil
}

func (v DeviceLinkObservation) Validate() error {
	if ValidateID(v.DeviceID) != nil || v.ReportSequence == 0 || ValidateDigest(v.ReportDigest) != nil || v.Observation.Validate() != nil || v.Observation.Level != "link" || v.CurrentUntil <= v.Observation.ObservedAt || v.CurrentUntil > v.Observation.ValidUntil {
		return errors.New("invalid scoped link observation")
	}
	return nil
}

func (v DeviceLinkObservations) Validate() error {
	if v.Schema != 3 || ValidateID(v.NetworkID) != nil || ValidateID(v.DeviceID) != nil || ValidateDigest(v.ViewDigest) != nil || v.Observations == nil {
		return errors.New("invalid link observation delivery")
	}
	for i, sample := range v.Observations {
		if sample.Validate() != nil || i > 0 && v.Observations[i-1].Observation.LinkID >= sample.Observation.LinkID {
			return errors.New("link observations are not uniquely sorted")
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
	links := map[string]NetworkLink{}
	for _, link := range view.Links {
		links[link.ID] = link
	}
	for _, sample := range v.Observations {
		link, ok := links[sample.Observation.LinkID]
		spec, e := LinkSpecDigest(view, link.ID)
		if !ok || e != nil || sample.DeviceID != link.FromNodeID || !matchesNativeLinkObservation(sample.Observation, link, spec) {
			return errors.New("link observation is outside the recipient's View")
		}
	}
	return nil
}

func projectDeviceLinkObservations(projection Projection, recipient, requestedDigest string, reports []DeviceReport, now time.Time, viewFor func(string) (DeviceView, string, error)) (DeviceLinkObservations, error) {
	return projectDeviceLinkObservationsUsing(projection, recipient, requestedDigest, reports, now, viewFor, func(report DeviceReport) error {
		return verifyCurrentReportUsingDigest(report, projection, viewFor)
	})
}

// Only the formal handler supplies a verifier reusing LatestForDevices' proof
// of the freshly read original. The ordinary projection above still verifies
// every supplied report independently; neither path caches dynamic health.
func projectDeviceLinkObservationsUsing(projection Projection, recipient, requestedDigest string, reports []DeviceReport, now time.Time, viewFor func(string) (DeviceView, string, error), verify func(DeviceReport) error) (DeviceLinkObservations, error) {
	view, digest, err := viewFor(recipient)
	if err != nil || view.DeviceID != recipient || digest != requestedDigest {
		return DeviceLinkObservations{}, errors.New("current device View required")
	}
	result := DeviceLinkObservations{Schema: 3, NetworkID: view.NetworkID, DeviceID: view.DeviceID, ViewDigest: digest, Observations: []DeviceLinkObservation{}}
	links := map[string]NetworkLink{}
	sources := map[string]bool{}
	for _, link := range view.Links {
		links[link.ID] = link
		sources[link.FromNodeID] = true
	}
	for _, report := range reports {
		if !sources[report.DeviceID] || verify(report) != nil {
			continue
		}
		_, reportUntil := webReportTime(report, now)
		body, err := CanonicalEncode(report)
		if err != nil {
			return DeviceLinkObservations{}, err
		}
		for _, sample := range report.Observations {
			link, ok := links[sample.LinkID]
			if !ok || sample.Level != "link" || report.DeviceID != link.FromNodeID {
				continue
			}
			spec, err := LinkSpecDigest(view, link.ID)
			until := webObservationUntil(report, sample, reportUntil, now)
			if err != nil || !matchesNativeLinkObservation(sample, link, spec) || until <= now.UnixMilli() || sample.ObservedAt > now.UnixMilli() {
				continue
			}
			result.Observations = append(result.Observations, DeviceLinkObservation{DeviceID: report.DeviceID, ReportSequence: report.ReportSequence, ReportDigest: ReleaseDigest(body), CurrentUntil: until, Observation: sample})
		}
	}
	sort.Slice(result.Observations, func(i, j int) bool {
		return result.Observations[i].Observation.LinkID < result.Observations[j].Observation.LinkID
	})
	return result, result.validateForViewDigest(view, digest)
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
	views := map[string]*deviceConfigValue{}
	viewFor := func(id string) (DeviceView, string, error) {
		value := views[id]
		if value == nil {
			var err error
			value, err = configuration.get(r.Context(), id)
			if err != nil {
				return DeviceView{}, "", err
			}
			views[id] = value
		}
		return value.envelope.View, value.envelope.ViewDigest, nil
	}
	view, digest, err := viewFor(identity.DeviceID)
	if err != nil || request.Validate() != nil || digest != request.ViewDigest {
		http.Error(w, "current device View required", http.StatusConflict)
		return
	}
	sources := map[string]string{}
	for _, link := range view.Links {
		if source, found := identityFor(projection, link.FromNodeID); found {
			sources[source.ID] = source.DevicePublicKey
		}
	}
	reports, err := server.Runtime.Reports.LatestForDevices(r.Context(), projection.NetworkID, sources)
	if err != nil {
		http.Error(w, "link observations unavailable", http.StatusServiceUnavailable)
		return
	}
	// LatestForDevices has just checked actual bytes, position and signature
	// under these exact current keys. Everything depending on current execution
	// inputs and time is deliberately checked again in this request.
	verify := func(report DeviceReport) error {
		source, found := identityFor(projection, report.DeviceID)
		if !found || sources[report.DeviceID] != source.DevicePublicKey || report.NetworkID != projection.NetworkID {
			return errors.New("Link source is outside the current request")
		}
		view, digest, err := viewFor(report.DeviceID)
		if err != nil || report.ViewDigest != digest {
			return errors.New("Link source View is stale")
		}
		return verifyReportViewFields(report, view)
	}
	result, err := projectDeviceLinkObservationsUsing(projection, identity.DeviceID, digest, reports, server.now(), viewFor, verify)
	if err != nil || configuration.finish() != nil {
		http.Error(w, "link observations unavailable", http.StatusServiceUnavailable)
		return
	}
	writeCanonical(w, http.StatusOK, result)
}
