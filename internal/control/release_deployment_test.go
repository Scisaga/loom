package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReleaseInputsFollowAuthorityWithoutExportingRuntimeKey(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("fixture join failed")
	}
	read := func() (ReleaseDeploymentInputs, []byte) {
		response := httptest.NewRecorder()
		server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/control/releases/inputs", nil))
		var value ReleaseDeploymentInputs
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &value) != nil {
			t.Fatal("private publication input read failed")
		}
		return value, response.Body.Bytes()
	}
	value, body := read()
	authorization := server.Runtime.Authority.Snapshot().DeviceAuthorizations[0]
	if value.GenesisDigest != server.Config.GenesisID || len(value.Nodes) != 1 || value.Nodes[0].PublicKey != authorization.DevicePublicKey || bytes.Contains(body, []byte(authorization.RuntimeKey)) {
		t.Fatal("deployment projection changed authority or exported a secret")
	}
	target, _ := server.Runtime.Authority.Snapshot().CurrentTarget("device", invite.DeviceID)
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-release-revoke", Operation: "device.revoke", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: target.MaterialIDs, Payload: DeleteTarget{ID: invite.DeviceID}})
	value, _ = read()
	if len(value.Nodes) != 0 || len(value.DistributionURLs) != 0 {
		t.Fatal("revoked device retained deployment eligibility")
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/control/releases/inputs", nil))
	if response.Code == http.StatusOK {
		t.Fatal("public request read private deployment inputs")
	}
}
