package control

import (
	"net/http"
	"net/url"
	"sort"
	"time"
)

// These values are disposable projections of signed reports, never write input.
type WebPathHistory struct {
	Schema      int                `json:"schema"`
	DeviceID    string             `json:"device_id"`
	ServiceID   string             `json:"service_id"`
	CandidateID string             `json:"candidate_id"`
	SpecDigest  string             `json:"spec_digest"`
	Target      string             `json:"target"`
	From        int64              `json:"from"`
	Until       int64              `json:"until"`
	Buckets     []WebHistoryBucket `json:"buckets"`
}

type WebHistoryBucket struct {
	Hour        int64        `json:"hour"`
	Observation *Observation `json:"observation,omitempty"`
	Ambiguous   bool         `json:"ambiguous"`
}

func (server *Server) pathHistory(w http.ResponseWriter, r *http.Request) {
	query, queryErr := url.ParseQuery(r.URL.RawQuery)
	if queryErr != nil || len(query) != 4 {
		http.Error(w, "exact device, service, candidate and target are required", http.StatusBadRequest)
		return
	}
	for _, key := range []string{"device", "service", "candidate", "target"} {
		if len(query[key]) != 1 || query.Get(key) == "" {
			http.Error(w, "ambiguous history scope", http.StatusBadRequest)
			return
		}
	}
	if ValidateID(query.Get("device")) != nil || ValidateID(query.Get("service")) != nil || ValidateDigest(query.Get("candidate")) != nil || ValidateHTTPSURL(query.Get("target")) != nil {
		http.Error(w, "invalid history scope", http.StatusBadRequest)
		return
	}
	if server.Runtime == nil || server.Runtime.Authority == nil || server.Runtime.Reports == nil {
		http.Error(w, "original report history unavailable", http.StatusServiceUnavailable)
		return
	}
	projection := server.Runtime.Authority.Snapshot()
	authorization, found := authorizationFor(projection, query.Get("device"))
	if !found {
		http.Error(w, "device is not authorized", http.StatusNotFound)
		return
	}
	view, err := ProjectDeviceView(projection, authorization.ID, server.expectedReleaseSets(projection)...)
	if err != nil {
		http.Error(w, "current device scope unavailable", http.StatusServiceUnavailable)
		return
	}
	for _, route := range view.Routes {
		if route.ID != query.Get("candidate") || route.ServiceID != query.Get("service") {
			continue
		}
		for _, set := range view.BusinessProbeTargets {
			if set.ServiceID == route.ServiceID && containsString(set.Targets, query.Get("target")) {
				value := server.Runtime.Reports.pathHistory(projection.NetworkID, authorization, route, query.Get("target"), server.now())
				writeJSON(w, http.StatusOK, value)
				return
			}
		}
	}
	http.Error(w, "candidate or target is outside the current Service permission", http.StatusNotFound)
}

func (store *ObservationStore) pathHistory(network string, authorization DeviceAuthorization, route RouteCandidate, target string, now time.Time) WebPathHistory {
	start := now.UTC().Truncate(time.Hour).Add(-23 * time.Hour)
	result := WebPathHistory{Schema: 3, DeviceID: authorization.ID, ServiceID: route.ServiceID, CandidateID: route.ID,
		SpecDigest: route.SpecDigest, Target: target, From: start.UnixMilli(), Until: now.UnixMilli(), Buckets: make([]WebHistoryBucket, 24)}
	for index := range result.Buckets {
		result.Buckets[index].Hour = start.Add(time.Duration(index) * time.Hour).UnixMilli()
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	type sample struct {
		report      int
		observation Observation
	}
	groups := make([][]sample, 24)
	reports := store.state.Reports
	sameSequence := func(a, b DeviceReport) bool {
		return a.NetworkID == b.NetworkID && a.DeviceID == b.DeviceID && a.ReportSequence == b.ReportSequence
	}
	for index, report := range reports {
		if report.NetworkID != network || report.DeviceID != authorization.ID {
			continue
		}
		// A fork has no chosen winner, including when one branch looks healthier.
		if index > 0 && sameSequence(reports[index-1], report) || index+1 < len(reports) && sameSequence(report, reports[index+1]) {
			continue
		}
		for _, observation := range report.Observations {
			if observation.Level != "service" || observation.ServiceID != route.ServiceID || observation.CandidateID != route.ID || observation.SpecDigest != route.SpecDigest || observation.Target != target || observation.Action != "https_request" || observation.NetworkGeneration != report.NetworkGeneration || observation.ObservedAt < result.From || observation.ObservedAt > result.Until {
				continue
			}
			hour := int((observation.ObservedAt - result.From) / time.Hour.Milliseconds())
			groups[hour] = append(groups[hour], sample{report: index, observation: observation})
		}
	}
	// Verify only potential last samples, not every report on every UI refresh.
	// This per-call memo is discarded with the response and owns no high-water mark.
	verified := map[int]bool{}
	for index, group := range groups {
		sort.SliceStable(group, func(i, j int) bool { return group[i].observation.ObservedAt > group[j].observation.ObservedAt })
		var latest int64
		var chosen string
		for _, item := range group {
			if latest != 0 && item.observation.ObservedAt < latest {
				break
			}
			valid, checked := verified[item.report]
			if !checked {
				valid = reports[item.report].Verify(authorization.DevicePublicKey) == nil
				verified[item.report] = valid
			}
			if !valid {
				continue
			}
			encoded, err := CanonicalEncode(item.observation)
			if err != nil {
				continue
			}
			if latest == 0 {
				latest, chosen = item.observation.ObservedAt, string(encoded)
				value := item.observation
				if value.DurationMS != nil {
					duration := *value.DurationMS
					value.DurationMS = &duration
				}
				result.Buckets[index].Observation = &value
			} else if string(encoded) != chosen {
				result.Buckets[index].Observation = nil
				result.Buckets[index].Ambiguous = true
			}
		}
	}
	return result
}
