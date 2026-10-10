package control

import "net/http"

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
	if r.URL.RawQuery != "" {
		http.Error(w, "report ID request does not accept query parameters", http.StatusBadRequest)
		return
	}
	var request reportRangesRequest
	if !readDeviceJSON(w, r, &request) {
		return
	}
	projection := server.Runtime.Authority.Snapshot()
	value := reportIDs{3, projection.NetworkID, []reportRangeIDs{}}
	for _, scope := range request.Ranges {
		ids, err := server.Runtime.Reports.reportIDs(r.Context(), projection, scope)
		if err != nil {
			http.Error(w, "report range unavailable", http.StatusForbidden)
			return
		}
		value.Ranges = append(value.Ranges, reportRangeIDs{scope.DeviceID, scope.FirstSequence, ids})
	}
	writeReportIndex(w, value)
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
	reports, err := server.Runtime.Reports.readReports(r.Context(), request.ReportIDs)
	if err != nil {
		http.Error(w, "report index unavailable", http.StatusServiceUnavailable)
		return
	}
	body := []byte(`{"reports":[`)
	for i, id := range request.ReportIDs {
		report, found := reports[id]
		if !found {
			break
		}
		authorization, ok := identityFor(projection, report.DeviceID)
		if !ok || report.NetworkID != projection.NetworkID {
			http.Error(w, "report device is not currently authorized", http.StatusForbidden)
			return
		}
		raw, err := CanonicalEncode(report)
		if err != nil || len(raw) > controlHTTPBodyLimit || report.Verify(authorization.DevicePublicKey) != nil {
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
