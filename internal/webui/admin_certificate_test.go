package webui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestPasswordLoginRoutesAreRemoved(t *testing.T) {
	d := misakaDeps()
	for _, target := range []string{"/login", "/logout"} {
		response := misakaRequest(t, d, http.MethodGet, target, nil, false)
		if response.Code != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404", target, response.Code)
		}
	}
	response := misakaRequest(t, d, http.MethodPost, "/login", url.Values{"password": {"legacy"}}, false)
	if response.Code != http.StatusNotFound || response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("legacy password POST = %d headers=%v", response.Code, response.Header())
	}
}

func TestControlHeaderReflectsCertificateBoundary(t *testing.T) {
	d := misakaDeps()
	readOnly := shell(d, "总览", "", false)
	if !strings.Contains(readOnly, "Read-only · admin.p12 required for changes") ||
		strings.Contains(readOnly, "Operator sign in") || strings.Contains(readOnly, "type=password") {
		t.Fatalf("read-only header does not describe certificate boundary: %s", readOnly)
	}
	admin := shell(d, "总览", "", true)
	if !strings.Contains(admin, "Admin certificate · configuration enabled") ||
		strings.Contains(admin, "Sign out") {
		t.Fatalf("admin header does not describe mTLS identity: %s", admin)
	}
}

func TestSettingsNeverExposeSSOTWithoutAdminCertificate(t *testing.T) {
	d := misakaDeps()
	readOnly := misakaRequest(t, d, http.MethodGet, "/settings", nil, false)
	if readOnly.Code != http.StatusOK || !strings.Contains(readOnly.Body.String(), "admin.p12") ||
		strings.Contains(readOnly.Body.String(), "schema: 1") {
		t.Fatalf("read-only settings leaked SSOT or hid certificate guidance: %d %s", readOnly.Code, readOnly.Body.String())
	}
	admin := misakaRequest(t, d, http.MethodGet, "/settings", nil, true)
	if admin.Code != http.StatusOK || !strings.Contains(admin.Body.String(), "schema: 1") {
		t.Fatalf("certificate-authenticated settings did not expose editor: %d %s", admin.Code, admin.Body.String())
	}
}
