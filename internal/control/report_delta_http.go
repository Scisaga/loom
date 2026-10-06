package control

import (
	"net/http"
	"net/url"
)

func (server *Server) internalReportRanges(w http.ResponseWriter, r *http.Request) {
	if server.Runtime.Reports == nil {
		http.Error(w, "report history unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "report index does not accept query parameters", http.StatusBadRequest)
		return
	}
	value, err := server.Runtime.Reports.reportRanges(r.Context(), server.Runtime.Authority.Snapshot())
	if err != nil {
		http.Error(w, "report index unavailable", http.StatusServiceUnavailable)
		return
	}
	writeReportIndex(w, value)
}

func (server *Server) internalReportIDs(w http.ResponseWriter, r *http.Request) {
	if server.Runtime.Reports == nil {
		http.Error(w, "report history unavailable", http.StatusServiceUnavailable)
		return
	}
	query, queryErr := url.ParseQuery(r.URL.RawQuery)
	first, err := ParseU64(query.Get("first_sequence"))
	device := query.Get("device_id")
	if queryErr != nil || err != nil || len(query) != 2 || len(query["device_id"]) != 1 || len(query["first_sequence"]) != 1 || !validReportRange(device, first) {
		http.Error(w, "invalid report range", http.StatusBadRequest)
		return
	}
	projection := server.Runtime.Authority.Snapshot()
	bodies, err := server.Runtime.Reports.reportRangeBodies(r.Context(), projection, device, first)
	if err != nil {
		http.Error(w, "report range unavailable", http.StatusServiceUnavailable)
		return
	}
	writeReportIndex(w, reportRangeIDs{3, projection.NetworkID, device, first, sortedReportIDs(bodies)})
}

func writeReportIndex(w http.ResponseWriter, value any) {
	body, err := CanonicalEncode(value)
	if err != nil || len(body) > maxControlInputBytes {
		http.Error(w, "report index exceeds its read boundary", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (server *Server) internalReports(w http.ResponseWriter, r *http.Request) {
	if server.Runtime.Reports == nil {
		http.Error(w, "report history unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "report batch does not accept query parameters", http.StatusBadRequest)
		return
	}
	var request reportBatchRequest
	if !readDeviceJSON(w, r, &request) {
		return
	}
	projection := server.Runtime.Authority.Snapshot()
	authorization, ok := authorizationFor(projection, request.DeviceID)
	if !ok {
		http.Error(w, "report device is not currently authorized", http.StatusForbidden)
		return
	}
	bodies, err := server.Runtime.Reports.reportRangeBodies(r.Context(), projection, request.DeviceID, request.FirstSequence)
	if err != nil {
		http.Error(w, "report range unavailable", http.StatusServiceUnavailable)
		return
	}
	body := []byte(`{"reports":[`)
	for i, id := range request.ReportIDs {
		raw, found := bodies[id]
		if !found {
			http.Error(w, "requested report is absent from this range", http.StatusConflict)
			return
		}
		var report DeviceReport
		if DecodeCanonical(raw, &report, ContractDecodeLimits{MaxBytes: controlHTTPBodyLimit, MaxDepth: 128, MaxItems: 1 << 20}) != nil || report.Verify(authorization.DevicePublicKey) != nil {
			http.Error(w, "stored report does not verify", http.StatusServiceUnavailable)
			return
		}
		if len(body)+len(raw)+32 > reportBatchBytes {
			break
		}
		if i > 0 {
			body = append(body, ',')
		}
		body = append(body, raw...)
	}
	body = append(body, `],"schema":3}`...)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
