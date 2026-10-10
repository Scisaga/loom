package control

import (
	"context"
	"net/http"
	"net/url"
	"time"

	bolt "go.etcd.io/bbolt"
)

// A direction and current specification projected from original Link samples.
type WebLinkHistory struct {
	Schema     int                `json:"schema"`
	LinkID     string             `json:"link_id"`
	FromNodeID string             `json:"from_node_id"`
	ToNodeID   string             `json:"to_node_id"`
	ResourceID string             `json:"resource_id"`
	SpecDigest string             `json:"spec_digest"`
	From       int64              `json:"from"`
	Until      int64              `json:"until"`
	Buckets    []WebHistoryBucket `json:"buckets"`
}

func (server *Server) linkHistory(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["link"]) != 1 || ValidateID(query.Get("link")) != nil {
		http.Error(w, "one exact Link is required", http.StatusBadRequest)
		return
	}
	if server.Runtime == nil || server.Runtime.Authority == nil || server.Runtime.Reports == nil {
		http.Error(w, "original report history unavailable", http.StatusServiceUnavailable)
		return
	}
	projection := server.Runtime.Authority.Snapshot()
	eligible := false
	for _, link := range projectWebLinks(projection) {
		if link.ID == query.Get("link") {
			eligible = true
			break
		}
	}
	if !eligible {
		http.Error(w, "Link is outside current endpoint permissions", http.StatusNotFound)
		return
	}
	for _, link := range projection.NetworkIntent.Links {
		if link.ID != query.Get("link") {
			continue
		}
		identity, found := authorizationFor(projection, link.FromNodeID)
		if !found {
			break
		}
		// The ordinary Web Link projection above checks both endpoint roles;
		// the source View supplies its exact native probe specification.
		view, err := ProjectDeviceView(projection, identity.ID)
		if err != nil {
			http.Error(w, "current Link scope unavailable", http.StatusServiceUnavailable)
			return
		}
		if _, err := LinkSpecDigest(view, link.ID); err != nil {
			break
		}
		value, err := server.Runtime.Reports.linkHistory(r.Context(), identity, view, link, server.now())
		if err != nil {
			http.Error(w, "original report history unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, value)
		return
	}
	http.Error(w, "Link is outside current endpoint permissions", http.StatusNotFound)
}

func (store *ObservationStore) linkHistory(ctx context.Context, identity DeviceAuthorization, view DeviceView, link NetworkLink, now time.Time) (WebLinkHistory, error) {
	start := now.UTC().Truncate(time.Hour).Add(-23 * time.Hour)
	spec, err := LinkSpecDigest(view, link.ID)
	if err != nil {
		return WebLinkHistory{}, err
	}
	result := WebLinkHistory{Schema: 3, LinkID: link.ID, FromNodeID: link.FromNodeID, ToNodeID: link.ToNodeID, ResourceID: link.ResourceID, SpecDigest: spec,
		From: start.UnixMilli(), Until: now.UnixMilli(), Buckets: make([]WebHistoryBucket, 24)}
	for index := range result.Buckets {
		result.Buckets[index].Hour = start.Add(time.Duration(index) * time.Hour).UnixMilli()
	}
	latest := [24]int64{}
	chosen := [24]string{}
	possible := func(id, digest string, at int64) bool {
		return id == result.LinkID && digest == spec && at >= result.From && at <= result.Until && at >= latest[(at-result.From)/time.Hour.Milliseconds()]
	}
	err = withObservationDB(ctx, store.path, false, func(tx *bolt.Tx) error {
		return walkDeviceReportHistory(ctx, tx, store.index.Load(), view.NetworkID, identity.ID, func(_ string, ref reportReference, raw []byte) error {
			candidate := false
			for _, sample := range ref.LinkSamples {
				if possible(sample.LinkID, sample.SpecDigest, sample.ObservedAt) {
					candidate = true
					break
				}
			}
			if !candidate {
				return nil
			}
			var report DeviceReport
			if err := decodeStoredReport(raw, &report); err != nil {
				return err
			}
			if report.Verify(identity.DevicePublicKey) != nil {
				return nil
			}
			for _, sample := range report.Observations {
				if sample.Level != "link" || !possible(sample.LinkID, sample.SpecDigest, sample.ObservedAt) || sample.NetworkGeneration != report.NetworkGeneration || verifyLinkObservation(sample, view) != nil {
					continue
				}
				hour := (sample.ObservedAt - result.From) / time.Hour.Milliseconds()
				body, err := CanonicalEncode(sample)
				if err != nil {
					return err
				}
				if latest[hour] == 0 || sample.ObservedAt > latest[hour] {
					latest[hour], chosen[hour] = sample.ObservedAt, string(body)
					value := sample
					result.Buckets[hour].Observation, result.Buckets[hour].Ambiguous = &value, false
				} else if string(body) != chosen[hour] {
					result.Buckets[hour].Observation, result.Buckets[hour].Ambiguous = nil, true
				}
			}
			return nil
		})
	})
	return result, err
}
