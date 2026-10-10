package control

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
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
	RoundTrips *WebLinkRoundTrips `json:"round_trips,omitempty"`
}

// A read-only statistic of original successful probes, never a health fact.
type WebLinkRoundTrips struct {
	From              int64  `json:"from"`
	Until             int64  `json:"until"`
	NetworkGeneration string `json:"network_generation"`
	ReportSequence    U64    `json:"report_sequence"`
	CurrentUntil      int64  `json:"current_until"`
	Samples           int    `json:"samples"`
	P50MS             *int64 `json:"p50_ms,omitempty"`
	P95MS             *int64 `json:"p95_ms,omitempty"`
	SpreadMS          *int64 `json:"spread_ms,omitempty"`
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
	spec := ""
	for _, link := range projectWebLinks(projection) {
		if link.ID == query.Get("link") {
			spec = link.SpecDigest
			break
		}
	}
	if spec == "" {
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
		// The current Link projection checks endpoint roles and both native
		// resources. Unrelated program expectations cannot erase Link history.
		value, err := server.Runtime.Reports.linkHistory(r.Context(), projection.NetworkID, identity, link, spec, server.now())
		if err != nil {
			http.Error(w, "original report history unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, value)
		return
	}
	http.Error(w, "Link is outside current endpoint permissions", http.StatusNotFound)
}

func (store *ObservationStore) linkHistory(ctx context.Context, network string, identity DeviceAuthorization, link NetworkLink, spec string, now time.Time) (WebLinkHistory, error) {
	start := now.UTC().Truncate(time.Hour).Add(-23 * time.Hour)
	if ValidateID(network) != nil || identity.ID != link.FromNodeID || ValidateDigest(spec) != nil {
		return WebLinkHistory{}, errors.New("Link history scope does not match its sender")
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
	recentFrom := now.Add(-15 * time.Minute).UnixMilli()
	recentPossible := func(id, digest string, at int64) bool {
		return id == link.ID && digest == spec && at >= recentFrom && at <= result.Until
	}
	recent := map[int64]*Observation{}
	recentBodies := map[int64]string{}
	err := withObservationDB(ctx, store.path, false, func(tx *bolt.Tx) error {
		highest, err := highestDeviceReportSequence(tx, store.index.Load(), network, identity.ID)
		if err != nil {
			return err
		}
		return walkDeviceReportHistory(ctx, tx, store.index.Load(), network, identity.ID, func(_ string, ref reportReference, raw []byte) error {
			candidate := ref.ReportSequence == highest
			for _, sample := range ref.LinkSamples {
				if possible(sample.LinkID, sample.SpecDigest, sample.ObservedAt) || recentPossible(sample.LinkID, sample.SpecDigest, sample.ObservedAt) {
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
			if ref.ReportSequence == highest {
				_, until := webReportTime(report, now)
				for _, sample := range report.Observations {
					currentUntil := webObservationUntil(report, sample, until, now)
					if sample.Level == "link" && matchesNativeLinkObservation(sample, link, spec) && sample.Result == "available" && sample.RoundTripMS != nil && currentUntil > result.Until {
						result.RoundTrips = &WebLinkRoundTrips{From: recentFrom, Until: result.Until, NetworkGeneration: report.NetworkGeneration, ReportSequence: highest, CurrentUntil: currentUntil}
					}
				}
			}
			for _, sample := range report.Observations {
				if sample.Level != "link" || sample.NetworkGeneration != report.NetworkGeneration || !matchesNativeLinkObservation(sample, link, spec) {
					continue
				}
				body, err := CanonicalEncode(sample)
				if err != nil {
					return err
				}
				if scope := result.RoundTrips; scope != nil && sample.NetworkGeneration == scope.NetworkGeneration && recentPossible(sample.LinkID, sample.SpecDigest, sample.ObservedAt) &&
					report.ReportedAt <= result.Until+webClockTolerance.Milliseconds() && report.Runtime.State == "running" && report.Runtime.AppliedViewDigest == report.ViewDigest &&
					sample.ObservedAt <= report.ReportedAt+webClockTolerance.Milliseconds() && sample.ValidUntil-sample.ObservedAt <= (30*time.Second).Milliseconds() {
					// Keep failed and missing-RTT contents in conflict detection, too.
					// No equal-time contradictory sample can win by report order.
					if old, found := recentBodies[sample.ObservedAt]; !found {
						recentBodies[sample.ObservedAt] = string(body)
						value := sample
						recent[sample.ObservedAt] = &value
					} else if old != string(body) {
						recent[sample.ObservedAt] = nil
					}
				}
				if !possible(sample.LinkID, sample.SpecDigest, sample.ObservedAt) {
					continue
				}
				hour := (sample.ObservedAt - result.From) / time.Hour.Milliseconds()
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
	if scope := result.RoundTrips; scope != nil {
		values := []int64{}
		for _, sample := range recent {
			if sample != nil && sample.Result == "available" && sample.RoundTripMS != nil {
				values = append(values, *sample.RoundTripMS)
			}
		}
		sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
		scope.Samples = len(values)
		if n := len(values); n > 0 {
			scope.P50MS = new(values[(n*50+99)/100-1])
			scope.P95MS = new(values[(n*95+99)/100-1])
			if n >= 2 {
				scope.SpreadMS = new(*scope.P95MS - *scope.P50MS)
			}
		}
	}
	return result, err
}
