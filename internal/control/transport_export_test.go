package control

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalTransportDeliveryUsesPersistedCertifiedViewAndIsNotPublic(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite))
	if response.Code != http.StatusOK {
		t.Fatal("enrollment failed", response.Code)
	}
	root := server.Runtime.Authority.root
	server.Runtime.Close()
	reopened, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	server.Runtime = reopened
	path := "/api/control/devices/" + invite.DeviceID + "/view"
	get := func(handler http.Handler, path string) *httptest.ResponseRecorder {
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, httptest.NewRequest(http.MethodGet, path, nil))
		return out
	}
	value := get(server.AdminHandler(), path)
	if value.Code != http.StatusOK || value.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("local configuration export failed", value.Code)
	}
	var envelope DeviceViewEnvelope
	if err := DecodeCanonical(value.Body.Bytes(), &envelope, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if envelope.Validate() != nil || envelope.View.DeviceID != invite.DeviceID || envelope.View.DevicePublicKey != claim.DevicePublicKey {
		t.Fatal("export changed certified identity")
	}
	if get(server.Handler(), path).Code == http.StatusOK || get(server.DeviceHandler(), path).Code == http.StatusOK || get(server.AdminHandler(), path+"?extra=true").Code == http.StatusOK {
		t.Fatal("private delivery escaped its exact local administrative boundary")
	}
}
