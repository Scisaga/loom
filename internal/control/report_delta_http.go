package control

import (
	"compress/gzip"
	"net/http"
	"strconv"
	"strings"
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
	writeReportIndex(w, r, value)
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
	value, err := server.Runtime.Reports.expandReportTree(r.Context(), projection, request.Ranges)
	if err != nil {
		http.Error(w, "report tree unavailable", http.StatusForbidden)
		return
	}

	writeReportIndex(w, r, value)
}
func writeReportIndex(w http.ResponseWriter, r *http.Request, value any) {
	body, err := CanonicalEncode(value)
	if err != nil || len(body) > maxControlInputBytes {
		http.Error(w, "report index exceeds its read boundary", http.StatusServiceUnavailable)
		return
	}
	writeReportBody(w, r, body)
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
	writeReportBody(w, r, body)
}

func acceptsReportGzip(header string) bool {
	for _, offer := range strings.Split(strings.ToLower(header), ",") {
		parts := strings.Split(offer, ";")
		if strings.TrimSpace(parts[0]) != "gzip" {
			continue
		}
		allowed := true
		for _, parameter := range parts[1:] {
			key, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if !ok || strings.TrimSpace(key) != "q" {
				allowed = false
				break
			}
			q, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || !(q > 0 && q <= 1) {
				allowed = false
				break
			}
		}
		if allowed {
			return true
		}
	}
	return false
}
func writeReportBody(w http.ResponseWriter, r *http.Request, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	if len(body) >= 1024 {
		w.Header().Add("Vary", "Accept-Encoding")
		if acceptsReportGzip(r.Header.Get("Accept-Encoding")) {
			w.Header().Set("Content-Encoding", "gzip")
			writer := gzip.NewWriter(w)
			_, _ = writer.Write(body)
			_ = writer.Close()
			return
		}
	}
	_, _ = w.Write(body)
}
