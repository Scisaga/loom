package control

import "net/http"

// The local, owner-only administrative socket is the explicit migration
// delivery boundary. Do not expose device execution secrets through the Web.
func (server *Server) exportDeviceView(w http.ResponseWriter, r *http.Request) {
	if !localAdmin(r) || r.URL.RawQuery != "" || ValidateID(r.PathValue("device")) != nil {
		http.NotFound(w, r)
		return
	}
	envelope, err := server.deviceEnvelope(r.PathValue("device"))
	if err != nil {
		http.Error(w, "cannot certify current device configuration", http.StatusConflict)
		return
	}
	body, err := CanonicalEncode(envelope)
	if err != nil {
		http.Error(w, "cannot encode current configuration", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}
