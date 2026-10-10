package control

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// An hourly readback of original reports, never another persisted runtime state.
type WebRuntimeHistory struct {
	Schema   int                       `json:"schema"`
	DeviceID string                    `json:"device_id"`
	From     int64                     `json:"from"`
	Until    int64                     `json:"until"`
	Buckets  []WebRuntimeHistoryBucket `json:"buckets"`
}

type WebRuntimeHistoryBucket struct {
	Hour   int64             `json:"hour"`
	Sample *WebRuntimeSample `json:"sample,omitempty"`
}

type WebRuntimeSample struct {
	ReportID          string `json:"report_id"`
	ReportSequence    U64    `json:"report_sequence"`
	ReportedAt        int64  `json:"reported_at"`
	ViewDigest        string `json:"view_digest"`
	State             string `json:"state"`
	AppliedViewDigest string `json:"applied_view_digest"`
	ErrorCode         string `json:"error_code"`
}

func (server *Server) runtimeHistory(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["device"]) != 1 || ValidateID(query.Get("device")) != nil {
		http.Error(w, "one exact device is required", http.StatusBadRequest)
		return
	}
	if server.Runtime == nil || server.Runtime.Authority == nil || server.Runtime.Reports == nil {
		http.Error(w, "original report history unavailable", http.StatusServiceUnavailable)
		return
	}
	projection := server.Runtime.Authority.Snapshot()
	identity, found := identityFor(projection, query.Get("device"))
	if !found {
		http.Error(w, "device is not authorized", http.StatusNotFound)
		return
	}
	value, err := server.Runtime.Reports.runtimeHistory(r.Context(), projection.NetworkID, identity.ID, identity.DevicePublicKey, server.now())
	if err != nil {
		http.Error(w, "original report history unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (store *ObservationStore) runtimeHistory(ctx context.Context, network, device, publicKey string, now time.Time) (WebRuntimeHistory, error) {
	start := now.UTC().Truncate(time.Hour).Add(-23 * time.Hour)
	result := WebRuntimeHistory{Schema: 3, DeviceID: device, From: start.UnixMilli(), Until: now.UnixMilli(), Buckets: make([]WebRuntimeHistoryBucket, 24)}
	for index := range result.Buckets {
		result.Buckets[index].Hour = start.Add(time.Duration(index) * time.Hour).UnixMilli()
	}
	err := store.walkDeviceHistorySnapshot(ctx, network, device, func(_ U64, pending reportReference, pendingRaw []byte) error {
		if pending.ReportedAt < result.From || pending.ReportedAt > result.Until {
			return nil
		}
		bucket := &result.Buckets[(pending.ReportedAt-result.From)/time.Hour.Milliseconds()]
		if prior := bucket.Sample; prior != nil && (prior.ReportedAt > pending.ReportedAt || prior.ReportedAt == pending.ReportedAt && prior.ReportSequence > pending.ReportSequence) {
			return nil
		}
		var report DeviceReport
		if err := decodeStoredReport(pendingRaw, &report); err != nil {
			return err
		}
		if report.Verify(publicKey) != nil {
			return nil
		}
		bucket.Sample = &WebRuntimeSample{ReportID: ReleaseDigest(pendingRaw), ReportSequence: report.ReportSequence, ReportedAt: report.ReportedAt,
			ViewDigest: report.ViewDigest, State: report.Runtime.State, AppliedViewDigest: report.Runtime.AppliedViewDigest, ErrorCode: report.Runtime.ErrorCode}
		return nil
	})
	return result, err
}
