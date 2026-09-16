package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRemovedEnrollmentRoutesAreAbsent(t *testing.T) {
	handler := Handler(Deps{Admin: true, Snapshot: func() View { return View{} }, Control: &ControlDeps{}})
	for _, path := range []string{"/api/client/enroll", "/api/device/enroll"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			missing := httptest.NewRecorder()
			handler.ServeHTTP(missing, httptest.NewRequest(method, "/api/demo-missing", nil))
			request := httptest.NewRequest(method, path, strings.NewReader(`{"token":"demo-retired"}`))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != missing.Code || response.Body.String() != missing.Body.String() ||
				response.Header().Get("Allow") != missing.Header().Get("Allow") {
				t.Errorf("旧入网路径 %s %s 没有落到普通未注册路径", method, path)
			}
		}
	}
}

// A persisted online label must not survive without trusted evidence.

func TestDeviceAPIIsCanonicalAndDoesNotRequireCompatibilityAlias(t *testing.T) {
	d := Deps{
		Admin:    true,
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
		Snapshot: func() View { return View{} },
		Control: &ControlDeps{Devices: &ClientControlDeps{List: func() (ClientInventory, error) {
			return ClientInventory{Clients: []ClientView{{
				ID: "device-one", Name: "Device one", Status: "ready", Membership: "member",
			}}}, nil
		}}},
	}

	request := authenticatedJSONRequest(t, d, http.MethodGet, "/api/control/devices", "")
	Handler(d).ServeHTTP(request.recorder, request.request)
	if request.recorder.Code != http.StatusOK ||
		!strings.Contains(request.recorder.Body.String(), `"devices":[{"id":"device-one"`) ||
		strings.Contains(request.recorder.Body.String(), `"clients"`) {
		t.Fatalf("canonical device API = %d body=%s", request.recorder.Code, request.recorder.Body.String())
	}
}

func TestClientInviteArtifactsAreAuthenticatedNoStoreAndScannable(t *testing.T) {
	d := Deps{
		Admin: true, Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
		Snapshot: func() View { return View{} }, Control: &ControlDeps{Clients: &ClientControlDeps{
			InviteArtifact: func(id string) (ClientInviteArtifact, error) {
				return ClientInviteArtifact{InviteURI: "loom://enroll#" + id}, nil
			},
		}},
	}
	handler := Handler(d)

	unauthorized := httptest.NewRecorder()
	readOnly := d
	readOnly.Admin = false
	Handler(readOnly).ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/control/client-invites/i1/qr.png", nil))
	if unauthorized.Code != http.StatusForbidden {
		t.Fatalf("unauthorized qr=%d", unauthorized.Code)
	}

	qr := authenticatedJSONRequest(t, d, http.MethodGet, "/api/control/client-invites/i1/qr.png", "")
	handler.ServeHTTP(qr.recorder, qr.request)
	if qr.recorder.Code != http.StatusOK || qr.recorder.Header().Get("Content-Type") != "image/png" ||
		qr.recorder.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(qr.recorder.Header().Get("Content-Disposition"), "device-join.png") ||
		!strings.HasPrefix(qr.recorder.Body.String(), "\x89PNG") {
		t.Fatalf("qr=%d headers=%v body-prefix=%q", qr.recorder.Code, qr.recorder.Header(), qr.recorder.Body.String()[:min(8, qr.recorder.Body.Len())])
	}

	download := authenticatedJSONRequest(t, d, http.MethodGet, "/api/control/client-invites/i1/download", "")
	handler.ServeHTTP(download.recorder, download.request)
	if download.recorder.Code != http.StatusOK || download.recorder.Body.String() != "loom://enroll#i1\n" ||
		!strings.Contains(download.recorder.Header().Get("Content-Disposition"), "client.loom-invite") {
		t.Fatalf("download=%d headers=%v body=%q", download.recorder.Code, download.recorder.Header(), download.recorder.Body.String())
	}

	d.Control.Clients.InviteArtifact = func(id string) (ClientInviteArtifact, error) {
		return ClientInviteArtifact{InviteURI: "loom://enroll#" + id, Responsibilities: []string{"forward"}}, nil
	}
	forwardHandler := Handler(d)
	for _, action := range []string{"qr.png", "download"} {
		request := authenticatedJSONRequest(t, d, http.MethodGet, "/api/control/device-invites/server/"+action, "")
		forwardHandler.ServeHTTP(request.recorder, request.request)
		if request.recorder.Code != http.StatusConflict {
			t.Errorf("forward invitation %s status=%d body=%s", action, request.recorder.Code, request.recorder.Body.String())
		}
	}
}
