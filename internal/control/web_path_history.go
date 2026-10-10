package control

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"time"

	bolt "go.etcd.io/bbolt"
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
				value, err := server.Runtime.Reports.pathHistory(r.Context(), projection.NetworkID, authorization, route, query.Get("target"), server.now())
				if err != nil {
					http.Error(w, "original report history unavailable", http.StatusServiceUnavailable)
					return
				}
				writeJSON(w, http.StatusOK, value)
				return
			}
		}
	}
	http.Error(w, "candidate or target is outside the current Service permission", http.StatusNotFound)
}

func (store *ObservationStore) pathHistory(ctx context.Context, network string, authorization DeviceAuthorization, route RouteCandidate, target string, now time.Time) (WebPathHistory, error) {
	start := now.UTC().Truncate(time.Hour).Add(-23 * time.Hour)
	result := WebPathHistory{Schema: 3, DeviceID: authorization.ID, ServiceID: route.ServiceID, CandidateID: route.ID,
		SpecDigest: route.SpecDigest, Target: target, From: start.UnixMilli(), Until: now.UnixMilli(), Buckets: make([]WebHistoryBucket, 24)}
	for index := range result.Buckets {
		result.Buckets[index].Hour = start.Add(time.Duration(index) * time.Hour).UnixMilli()
	}
	latest := [24]int64{}
	chosen := [24]string{}
	err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
		index, err := scanObservationIndex(ctx, tx, store.index.Load())
		if err != nil {
			return err
		}
		counts := map[U64]int{}
		for _, ref := range index.reports {
			if ref.NetworkID == network && ref.DeviceID == authorization.ID {
				counts[ref.ReportSequence]++
			}
		}
		cursor := tx.Bucket(observationBucket).Cursor()
		prefix := []byte(network + "\x00" + authorization.ID + "\x00")
		for key, raw := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, raw = cursor.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			var report DeviceReport
			if err := decodeStoredReport(raw, &report); err != nil {
				return err
			}
			if counts[report.ReportSequence] != 1 {
				continue
			}
			checked, valid := false, false
			for _, observation := range report.Observations {
				if observation.Level != "service" || observation.ServiceID != route.ServiceID || observation.CandidateID != route.ID || observation.SpecDigest != route.SpecDigest || observation.Target != target || observation.Action != "https_request" || observation.NetworkGeneration != report.NetworkGeneration || observation.ObservedAt < result.From || observation.ObservedAt > result.Until {
					continue
				}
				hour := int((observation.ObservedAt - result.From) / time.Hour.Milliseconds())
				if latest[hour] != 0 && observation.ObservedAt < latest[hour] {
					continue
				}
				if !checked {
					valid = report.Verify(authorization.DevicePublicKey) == nil
					checked = true
				}
				if !valid {
					continue
				}
				encoded, err := CanonicalEncode(observation)
				if err != nil {
					return err
				}
				if latest[hour] == 0 || observation.ObservedAt > latest[hour] {
					latest[hour] = observation.ObservedAt
					chosen[hour] = string(encoded)
					value := observation
					result.Buckets[hour].Observation = &value
					result.Buckets[hour].Ambiguous = false
				} else if string(encoded) != chosen[hour] {
					result.Buckets[hour].Observation = nil
					result.Buckets[hour].Ambiguous = true
				}
			}
		}
		store.index.Store(index)
		return nil
	})
	return result, err
}
