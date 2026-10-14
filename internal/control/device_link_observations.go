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
	if err != nil || v.Validate() != nil || v.NetworkID != view.NetworkID || v.DeviceID != view.DeviceID || v.ViewDigest != digest {
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

func projectDeviceLinkObservations(projection Projection, view DeviceView, reports []DeviceReport, now time.Time, viewFor func(string) (DeviceView, error)) (DeviceLinkObservations, error) {
	digest, err := DeviceViewDigest(view)
	if err != nil {
		return DeviceLinkObservations{}, err
	}
	result := DeviceLinkObservations{Schema: 3, NetworkID: view.NetworkID, DeviceID: view.DeviceID, ViewDigest: digest, Observations: []DeviceLinkObservation{}}
	links := map[string]NetworkLink{}
	for _, link := range view.Links {
		links[link.ID] = link
	}
	for _, report := range reports {
		if verifyCurrentReportUsing(report, projection, viewFor) != nil {
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
	return result, result.ValidateForView(view)
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
	projection := server.Runtime.Authority.Snapshot()
	sets := server.expectedReleaseSets(projection)
	views := map[string]DeviceView{}
	viewFor := func(id string) (DeviceView, error) {
		if v, ok := views[id]; ok {
			return v, nil
		}
		v, e := ProjectDeviceView(projection, id, sets...)
		if e == nil {
			views[id] = v
		}
		return v, e
	}
	view, err := viewFor(identity.DeviceID)
	digest, digestErr := DeviceViewDigest(view)
	if err != nil || digestErr != nil || request.Validate() != nil || digest != request.ViewDigest {
		http.Error(w, "current device View required", http.StatusConflict)
		return
	}
	reports, err := server.Runtime.Reports.Latest(r.Context())
	if err != nil {
		http.Error(w, "link observations unavailable", http.StatusServiceUnavailable)
		return
	}
	result, err := projectDeviceLinkObservations(projection, view, reports, server.now(), viewFor)
	if err != nil {
		http.Error(w, "link observations unavailable", http.StatusServiceUnavailable)
		return
	}
	writeCanonical(w, http.StatusOK, result)
}
