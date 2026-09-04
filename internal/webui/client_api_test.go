package webui

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientAPIUsesSameTrustedRuntimeMergeAsHTML(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	d := Deps{
		Operator: "operator-secret",
		Now:      func() time.Time { return now },
		Snapshot: func() View {
			return View{Nodes: []NodeView{
				{
					ID: "trusted", Declared: true, Health: "healthy", Source: "签名健康转述",
					ObservedAt: now.Add(-20 * time.Second).Format(time.RFC3339), AgeSec: 20,
					Applied: "snapshot-trusted-0123456789",
				},
				{
					ID: "unsigned", Declared: true, Health: "healthy", Source: "未签名转述",
					ObservedAt: now.Add(-10 * time.Second).Format(time.RFC3339),
					Applied:    "snapshot-untrusted",
				},
			}}
		},
		Control: &ControlDeps{Clients: &ClientControlDeps{List: func() (ClientInventory, error) {
			return ClientInventory{Clients: []ClientView{
				{ID: "trusted", Name: "Trusted", Status: "ready"},
				// A persisted online label must not survive without trusted evidence.
				{ID: "unsigned", Name: "Unsigned", Status: "online", LastSeenAt: now.Format(time.RFC3339)},
			}}, nil
		}}},
	}

	handler := Handler(d)
	request := authenticatedJSONRequest(t, d, http.MethodGet, "/api/control/clients", "")
	handler.ServeHTTP(request.recorder, request.request)
	if request.recorder.Code != http.StatusOK {
		t.Fatalf("GET clients status=%d body=%s", request.recorder.Code, request.recorder.Body.String())
	}
	var inventory ClientInventory
	if err := json.Unmarshal(request.recorder.Body.Bytes(), &inventory); err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]ClientView, len(inventory.Clients))
	for _, client := range inventory.Clients {
		byID[client.ID] = client
	}
	trusted := byID["trusted"]
	if trusted.Status != "online" || trusted.DataPlaneStatus != "online" || trusted.LastSeenAt == "" ||
		!strings.HasPrefix(trusted.ConfigState, "applied snapshot-tru") {
		t.Fatalf("trusted ready client was not promoted by API runtime merge: %+v", trusted)
	}
	unsigned := byID["unsigned"]
	if unsigned.Status == "online" || unsigned.DataPlaneStatus != "untrusted observation" ||
		unsigned.LastSeenAt != "" || unsigned.ConfigState != "not reported" {
		t.Fatalf("unsigned observation was trusted by API runtime merge: %+v", unsigned)
	}

	page := pageClients(d, clientPageState{}, true)
	for _, want := range []string{"Trusted", "Online", "Unsigned", "untrusted observation"} {
		if !strings.Contains(page, want) {
			t.Errorf("HTML client inventory missing merged value %q", want)
		}
	}
}

func TestDeviceAPIIsCanonicalAndDoesNotRequireCompatibilityAlias(t *testing.T) {
	d := Deps{
		Operator: "operator-secret",
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

func TestClientAPIBoundsOperatorAndPublicClaimSurfaces(t *testing.T) {
	d := Deps{
		Operator: "operator-secret",
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
		Snapshot: func() View { return View{} },
		Control:  &ControlDeps{},
	}
	var createdName string
	var createdProfile string
	var claimed ClientClaimInput
	d.Control.Clients = &ClientControlDeps{
		List: func() (ClientInventory, error) {
			return ClientInventory{Clients: []ClientView{{ID: "client-one", Status: "provisioning"}}}, nil
		},
		CreateInvite: func(input ClientInviteInput) (ClientInviteView, error) {
			createdName = input.Name
			createdProfile = input.ProfileVersion
			return ClientInviteView{
				InviteID: "invite-one", ClientID: "client-one", ClientName: input.Name,
				InviteURI: "loom://enroll#opaque", EnrollmentURL: "https://control.example/api/client/enroll",
				ExpiresAt: "2026-08-31T12:15:00Z",
			}, nil
		},
		Claim: func(input ClientClaimInput) (ClientClaimResult, error) {
			claimed = input
			return ClientClaimResult{
				Schema: 1, ClientID: "client-one", Status: "provisioning",
				EnrolledAt: "2026-08-31T12:01:00Z", Next: "wait_for_configuration",
				Configuration: "pending",
			}, nil
		},
		InviteArtifact: func(string) (ClientInviteArtifact, error) {
			return ClientInviteArtifact{InviteURI: "loom://enroll#opaque", ExpiresAt: "2026-08-31T12:15:00Z"}, nil
		},
	}
	handler := Handler(d)
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/control/clients", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized clients status=%d", unauthorized.Code)
	}

	create := authenticatedJSONRequest(t, d, http.MethodPost, "/api/control/client-invites", `{"name":"build server","profile_version":"server-device@v1"}`)
	handler.ServeHTTP(create.recorder, create.request)
	if create.recorder.Code != http.StatusCreated || createdName != "build server" || createdProfile != "server-device@v1" ||
		!strings.Contains(create.recorder.Body.String(), `"invite_uri":"loom://enroll#opaque"`) ||
		create.recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create=%d name=%q body=%s headers=%v", create.recorder.Code, createdName, create.recorder.Body.String(), create.recorder.Header())
	}

	// Claim is intentionally not operator-session authenticated. Its random
	// invitation token is the one-use credential.
	claim := httptest.NewRequest(http.MethodPost, "/api/client/enroll", strings.NewReader(
		`{"token":"opaque-token","platform":"linux-server","csr_pem":"CSR","request_id":"install-1","server":{"public_endpoint":"edge.example.net","inbound_port":61698,"direction":"bidirectional","wg_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","country":"CN","city":"Beijing","provider":"example"}}`))
	claim.Header.Set("Content-Type", "application/json")
	claimResult := httptest.NewRecorder()
	handler.ServeHTTP(claimResult, claim)
	if claimResult.Code != http.StatusAccepted || claimed.Token != "opaque-token" ||
		claimed.CSRPEM != "CSR" || claimed.Server == nil || claimed.Server.PublicEndpoint != "edge.example.net" ||
		claimed.Server.InboundPort != 61698 || claimed.Server.Direction != "bidirectional" ||
		!strings.Contains(claimResult.Body.String(), `"configuration":"pending"`) {
		t.Fatalf("claim=%d input=%+v body=%s", claimResult.Code, claimed, claimResult.Body.String())
	}
	d.Control.Clients.Claim = func(ClientClaimInput) (ClientClaimResult, error) {
		return ClientClaimResult{}, errors.New("SSH failed at private-control-path")
	}
	failedClaim := httptest.NewRequest(http.MethodPost, "/api/client/enroll", strings.NewReader(
		`{"token":"opaque-token","platform":"linux-server","csr_pem":"CSR","request_id":"install-1"}`))
	failedClaim.Header.Set("Content-Type", "application/json")
	failedResult := httptest.NewRecorder()
	handler.ServeHTTP(failedResult, failedClaim)
	if failedResult.Code != http.StatusInternalServerError ||
		strings.Contains(failedResult.Body.String(), "private-control-path") ||
		!strings.Contains(failedResult.Body.String(), "temporarily unavailable") {
		t.Fatalf("failed claim leaked internal detail: status=%d body=%s", failedResult.Code, failedResult.Body.String())
	}

	unknown := httptest.NewRequest(http.MethodPost, "/api/client/enroll", strings.NewReader(
		`{"token":"x","platform":"linux-server","csr_pem":"x","request_id":"r","private_key":"must-not-pass"}`))
	unknown.Header.Set("Content-Type", "application/json")
	unknownResult := httptest.NewRecorder()
	handler.ServeHTTP(unknownResult, unknown)
	if unknownResult.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d body=%s", unknownResult.Code, unknownResult.Body.String())
	}
}

func TestClientInviteArtifactsAreAuthenticatedNoStoreAndScannable(t *testing.T) {
	d := Deps{
		Operator: "operator-secret", Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
		Snapshot: func() View { return View{} }, Control: &ControlDeps{Clients: &ClientControlDeps{
			InviteArtifact: func(id string) (ClientInviteArtifact, error) {
				return ClientInviteArtifact{InviteURI: "loom://enroll#" + id}, nil
			},
		}},
	}
	handler := Handler(d)

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/control/client-invites/i1/qr.png", nil))
	if unauthorized.Code != http.StatusUnauthorized {
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
}
