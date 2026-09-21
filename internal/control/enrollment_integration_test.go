package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/clientmodel"
)

func tunnelPost(t *testing.T, connection net.Conn, path string, requestValue, responseValue any) int {
	t.Helper()
	used := false
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: func(context.Context, string, string) (net.Conn, error) {
		if used {
			return nil, errors.New("connection reused")
		}
		used = true
		return connection, nil
	}}}
	body, err := json.Marshal(requestValue)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, "http://loom.private"+path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if responseValue != nil && (response.StatusCode == http.StatusOK || response.StatusCode == http.StatusAccepted) {
		decoder := json.NewDecoder(bytes.NewReader(responseBody))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(responseValue); err != nil {
			t.Fatal(err)
		}
	}
	return response.StatusCode
}

func postAdminOperation(t *testing.T, server *Server, kind, requestID, baseHead string, payload, responseValue any) (int, string) {
	t.Helper()
	payloadBody, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(operationEnvelope{Schema: 2, Kind: kind, RequestID: requestID,
		BaseHead: baseHead, Payload: payloadBody})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/control/operations", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, request)
	if responseValue != nil && response.Code == http.StatusOK {
		decoder := json.NewDecoder(response.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(responseValue); err != nil {
			t.Fatal(err)
		}
	}
	return response.Code, response.Body.String()
}

func waitEndpointReady(t *testing.T, runtime *EndpointRuntime, generation EndpointGeneration) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime != nil && runtime.Ready(generation) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("endpoint generation did not become ready")
}

func currentHead(runtime *Runtime) string {
	_, _, certified := runtime.Authority.Snapshot()
	return HeadID(certified.Head)
}

func TestPrivateEnrollmentDeviceChannelAndGenerationRotation(t *testing.T) {
	now := time.Date(2026, 9, 18, 3, 0, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	root := t.TempDir()
	privateAddress := freeAddress(t, "127.0.0.1")
	state := testState()
	state.BrowserTLS = testTLS(t)
	config, err := ActivateLegacy(root, state, "demo-control", "demo-control-node", []string{privateAddress})
	if err != nil {
		t.Fatal(err)
	}
	channel, err := OpenPrivateChannel(PrivateChannelConfig{Node: config.Node, Listen: []string{privateAddress}, Peers: map[string][]string{}}, config)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, channel)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	reports, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Runtime: runtime, Channel: channel, Config: config, ReleaseRoot: t.TempDir(),
		ReleaseKey: filepath.Join(t.TempDir(), "missing"), AdminSocket: filepath.Join(t.TempDir(), "admin.sock"),
		Reports: reports, Now: func() time.Time { return time.Unix(0, clock.Load()).UTC() }}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx, http.NotFoundHandler()) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
		_ = runtime.Close()
	})
	waitLeader(t, []*Runtime{runtime})
	deadline := time.Now().Add(5 * time.Second)
	for server.endpointRuntime() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if server.endpointRuntime() == nil {
		t.Fatal("endpoint runtime did not start")
	}
	endpointRuntime := server.endpointRuntime()

	certificatePath := filepath.Join(t.TempDir(), "endpoint.crt")
	keyPath := filepath.Join(t.TempDir(), "endpoint.key")
	if err := os.WriteFile(certificatePath, []byte(config.BrowserTLS.CertificateChainPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(config.BrowserTLS.PrivateKeyPKCS8PEM), 0o600); err != nil {
		t.Fatal(err)
	}
	spki, err := certificateSPKI(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicAddress := freeAddress(t, "127.0.0.1")
	generation1 := EndpointGeneration{Schema: 1, EndpointID: "demo-entry", Generation: 1, Node: config.Node,
		Transport: "tls_tunnel", Listen: publicAddress, Address: publicAddress, ServerName: "127.0.0.1",
		TLSCertificateFile: certificatePath, TLSPrivateKeyFile: keyPath, SPKISHA256: spki, State: "prepared", Preference: 0}
	if _, err := server.putEndpoint(ctx, "endpoint-1-prepared", currentHead(runtime), generation1); err != nil {
		t.Fatal(err)
	}
	waitEndpointReady(t, endpointRuntime, generation1)
	generation1.State = "serving"
	if _, err := server.putEndpoint(ctx, "endpoint-1-serving", currentHead(runtime), generation1); err != nil {
		t.Fatal(err)
	}

	routes := []RouteCandidate{
		{ID: "one-hop", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "internet"},
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-relay", "demo-exit"}, Scope: "internet"},
	}
	runtimeConfig, err := clientmodel.CanonicalizeRuntimeConfig([]byte(`{"inbounds":[{"type":"tun","tag":"tun-in","auto_route":true}],"outbounds":[{"type":"hysteria2","tag":"one-hop"},{"type":"hysteria2","tag":"relay"},{"type":"selector","tag":"internet","outbounds":["one-hop","relay"]}],"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-secret"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	runtimeProfile := &RuntimeProfile{Kind: "sing_box", Config: runtimeConfig}
	created, inviteText, err := server.createEnrollment(ctx, "invite-create", currentHead(runtime), enrollmentCreatePayload{
		TransactionID: "demo-transaction", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), DeviceID: "demo-device",
		Name: "Demo device", Platform: "linux", Roles: []string{"access"}, Routes: routes, Runtime: runtimeProfile})
	if err != nil || created.Head.Index == 0 {
		t.Fatalf("create enrollment: %v", err)
	}
	invite, err := DecodeInvite(inviteText)
	if err != nil {
		t.Fatal(err)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	claim, err := SignEnrollmentClaim(EnrollmentClaimRequest{Schema: 1, Capability: invite.Capability,
		RequestID: "demo-claim", DevicePublicKey: base64.RawURLEncoding.EncodeToString(public)}, private)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := invite.Capability.Endpoints[0]
	connection, err := DialEndpoint(ctx, endpoint, TunnelHello{Schema: 1, Mode: "bootstrap", EndpointID: endpoint.EndpointID,
		Generation: endpoint.Generation, Capability: &invite.Capability}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var bound EnrollmentResponse
	if status := tunnelPost(t, connection, "/v2/enrollment/claim", claim, &bound); status != http.StatusAccepted || bound.Transaction.State != "bound" {
		t.Fatalf("claim status=%d response=%+v", status, bound)
	}
	_ = connection.Close()

	otherPublic, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	otherClaim, _ := SignEnrollmentClaim(EnrollmentClaimRequest{Schema: 1, Capability: invite.Capability,
		RequestID: "other-claim", DevicePublicKey: base64.RawURLEncoding.EncodeToString(otherPublic)}, otherPrivate)
	connection, err = DialEndpoint(ctx, endpoint, TunnelHello{Schema: 1, Mode: "bootstrap", EndpointID: endpoint.EndpointID,
		Generation: endpoint.Generation, Capability: &invite.Capability}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status := tunnelPost(t, connection, "/v2/enrollment/claim", otherClaim, nil); status != http.StatusConflict {
		t.Fatalf("different-key replay status=%d", status)
	}
	_ = connection.Close()

	now = now.Add(2 * time.Hour)
	clock.Store(now.UnixNano())
	if _, err := server.approveEnrollment(ctx, "approve", currentHead(runtime), "demo-transaction"); err != nil {
		t.Fatal(err)
	}
	resume, _ := SignEnrollmentResume(EnrollmentResumeRequest{Schema: 1, TransactionID: "demo-transaction",
		RequestID: "demo-resume", DevicePublicKey: base64.RawURLEncoding.EncodeToString(public)}, private)
	connection, err = DialEndpoint(ctx, endpoint, TunnelHello{Schema: 1, Mode: "bootstrap", EndpointID: endpoint.EndpointID,
		Generation: endpoint.Generation, Capability: &invite.Capability}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var completed EnrollmentResponse
	if status := tunnelPost(t, connection, "/v2/enrollment/resume", resume, &completed); status != http.StatusOK || completed.DeviceView == nil {
		t.Fatalf("resume status=%d response=%+v", status, completed)
	}
	_ = connection.Close()
	if err := VerifyDeviceViewEnvelope(*completed.DeviceView, invite.Capability); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenAuthority(root); err != nil {
		t.Fatal(err)
	} else if response, err := (&Server{Runtime: &Runtime{Authority: reopened}}).enrollmentResponse("demo-transaction"); err != nil ||
		response.Transaction.ResultDigest != completed.Transaction.ResultDigest {
		t.Fatalf("restart changed enrollment result: %v", err)
	}

	viewDigest, _ := DeviceViewDigest(completed.DeviceView.View)
	report := DeviceReport{Schema: 1, DeviceID: "demo-device", ViewDigest: viewDigest, Selection: "relay",
		ReportedAt: now.Add(time.Minute).Format(time.RFC3339), Observations: []Observation{
			{CandidateID: "one-hop", NetworkGeneration: "demo-network", Scope: "transport", Result: "unavailable", Action: "tls", ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Hour).Format(time.RFC3339)},
			{CandidateID: "relay", NetworkGeneration: "demo-network", Scope: "business", Result: "available", Action: "https", ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Hour).Format(time.RFC3339)},
		}}
	report, _ = SignDeviceReport(report, private)
	connection, err = DialEndpoint(ctx, endpoint, TunnelHello{Schema: 1, Mode: "device", EndpointID: endpoint.EndpointID,
		Generation: endpoint.Generation, DeviceID: "demo-device"}, private)
	if err != nil {
		t.Fatal(err)
	}
	if status := tunnelPost(t, connection, "/v2/device/report", report, &struct {
		DeviceID   string `json:"device_id"`
		ReportedAt string `json:"reported_at"`
	}{}); status != http.StatusOK {
		t.Fatalf("report status=%d", status)
	}
	_ = connection.Close()
	if len(reports.All()) != 1 {
		t.Fatal("signed report was not persisted")
	}
	now = now.Add(2 * time.Minute)
	clock.Store(now.UnixNano())
	readback := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(readback, httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil))
	if readback.Code != http.StatusOK || !bytes.Contains(readback.Body.Bytes(), []byte(`"enrollment":"completed"`)) ||
		!bytes.Contains(readback.Body.Bytes(), []byte(`"last_report_at":"`)) ||
		!bytes.Contains(readback.Body.Bytes(), []byte(`"evidence":{`)) || bytes.Contains(readback.Body.Bytes(), []byte(`"signature":"`)) {
		t.Fatalf("authenticated UI/API did not read back enrollment and report: status=%d", readback.Code)
	}
	selected, err := SelectRoute(routes, report.Observations, "demo-exit", "one-hop", now.Add(time.Minute))
	if err != nil || selected != "relay" {
		t.Fatalf("same-exit fallback=%q err=%v", selected, err)
	}

	// Exercise the product schema-2 flow over the real private bootstrap and
	// device transports. The legacy flow above remains a replay/compatibility
	// assertion; every newly created transaction below uses the v2 signing
	// domain and a single atomic completion material.
	importValue := NetworkImport{Intent: testNetworkIntent(t), RecoveryEvidenceHash: "sha256:" + strings.Repeat("7", 64)}
	importMaterial := Material{Schema: MaterialSchema, Kind: "network.import", RequestID: "demo-network-import",
		BaseHead: currentHead(runtime), NetworkImport: &importValue}
	importBody, _, err := EncodeMaterial(importMaterial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Submit(ctx, importBody); err != nil {
		t.Fatal(err)
	}
	productPayload := productEnrollmentCreatePayload{Name: "Demo Windows", Platform: "windows",
		Responsibilities: []string{"use_loom"}, DestinationGrants: []string{"demo-policy"}}
	var productCreated struct {
		Head          GovernanceHead `json:"head"`
		Projection    WebProjection  `json:"projection"`
		Invite        string         `json:"invite"`
		TransactionID string         `json:"transaction_id"`
	}
	if status, body := postAdminOperation(t, server, "enrollment.create", "product-enrollment", currentHead(runtime),
		productPayload, &productCreated); status != http.StatusOK {
		t.Fatalf("schema-2 product create status=%d body=%s", status, body)
	}
	productInviteText := productCreated.Invite
	productOpenHead := currentHead(runtime)
	var productRetried struct {
		Head          GovernanceHead `json:"head"`
		Projection    WebProjection  `json:"projection"`
		Invite        string         `json:"invite"`
		TransactionID string         `json:"transaction_id"`
	}
	status, body := postAdminOperation(t, server, "enrollment.create", "product-enrollment", productOpenHead,
		productPayload, &productRetried)
	if status != http.StatusOK || productRetried.Invite != productInviteText || currentHead(runtime) != productOpenHead {
		t.Fatalf("schema-2 create retry was not idempotent: same_invite=%t same_head=%t err=%v",
			productRetried.Invite == productInviteText, currentHead(runtime) == productOpenHead, body)
	}
	conflictingPayload := productPayload
	conflictingPayload.Name = "Different Windows"
	if status, _ := postAdminOperation(t, server, "enrollment.create", "product-enrollment", productOpenHead,
		conflictingPayload, nil); status != http.StatusConflict {
		t.Fatalf("schema-2 create request ID conflict status=%d", status)
	}
	productInvite, err := DecodeInvite(productInviteText)
	if err != nil {
		t.Fatal(err)
	}
	productPublic, productPrivate, _ := ed25519.GenerateKey(rand.Reader)
	productClaim, err := SignEnrollmentClaim(EnrollmentClaimRequest{Schema: 2, Capability: productInvite.Capability,
		RequestID: "product-claim", DevicePublicKey: base64.RawURLEncoding.EncodeToString(productPublic)}, productPrivate)
	if err != nil {
		t.Fatal(err)
	}
	productEndpoint := productInvite.Capability.Endpoints[0]
	connection, err = DialEndpoint(ctx, productEndpoint, TunnelHello{Schema: 1, Mode: "bootstrap",
		EndpointID: productEndpoint.EndpointID, Generation: productEndpoint.Generation, Capability: &productInvite.Capability}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var productBound EnrollmentResponse
	if status := tunnelPost(t, connection, "/v2/enrollment/claim", productClaim, &productBound); status != http.StatusAccepted ||
		productBound.Schema != 2 || productBound.Transaction.State != "bound" {
		t.Fatalf("schema-2 claim status=%d response=%+v", status, productBound)
	}
	_ = connection.Close()
	beforeApproval := productBound.Transaction
	_, _, certifiedBeforeApproval := runtime.Authority.Snapshot()
	if status, body := postAdminOperation(t, server, "enrollment.approve", "product-approve", currentHead(runtime),
		map[string]string{"transaction_id": beforeApproval.ID}, &struct {
			Head       GovernanceHead `json:"head"`
			Projection WebProjection  `json:"projection"`
		}{}); status != http.StatusOK {
		t.Fatalf("schema-2 approval status=%d body=%s", status, body)
	}
	_, _, certifiedAfterApproval := runtime.Authority.Snapshot()
	if certifiedAfterApproval.Head.Index != certifiedBeforeApproval.Head.Index+1 {
		t.Fatalf("schema-2 approval used more than one material: before=%d after=%d",
			certifiedBeforeApproval.Head.Index, certifiedAfterApproval.Head.Index)
	}
	productResume, err := SignEnrollmentResume(EnrollmentResumeRequest{Schema: 2, TransactionID: beforeApproval.ID,
		RequestID: "product-resume", DevicePublicKey: base64.RawURLEncoding.EncodeToString(productPublic)}, productPrivate)
	if err != nil {
		t.Fatal(err)
	}
	connection, err = DialEndpoint(ctx, productEndpoint, TunnelHello{Schema: 1, Mode: "bootstrap",
		EndpointID: productEndpoint.EndpointID, Generation: productEndpoint.Generation, Capability: &productInvite.Capability}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var productCompleted EnrollmentResponse
	if status := tunnelPost(t, connection, "/v2/enrollment/resume", productResume, &productCompleted); status != http.StatusOK ||
		productCompleted.Schema != 2 || productCompleted.Transaction.State != "completed" || productCompleted.DeviceView == nil ||
		productCompleted.DeviceView.View.Schema != 2 {
		t.Fatalf("schema-2 resume status=%d response=%+v", status, productCompleted)
	}
	_ = connection.Close()
	encodedProductResponse, _ := json.Marshal(productCompleted)
	if bytes.Contains(encodedProductResponse, []byte("runtime_key")) || bytes.Contains(encodedProductResponse, []byte("local-api")) {
		t.Fatal("schema-2 enrollment response leaked a runtime secret")
	}
	if len(productCompleted.DeviceView.View.Routes) < 2 {
		t.Fatalf("schema-2 enrollment did not derive direct and server candidates: %+v", productCompleted.DeviceView.View.Routes)
	}
	productViewDigest, err := DeviceViewDigest(productCompleted.DeviceView.View)
	if err != nil {
		t.Fatal(err)
	}
	productRoute := productCompleted.DeviceView.View.Routes[0]
	productReport := DeviceReport{Schema: 2, DeviceID: productCompleted.DeviceView.View.DeviceID,
		ViewDigest: productViewDigest, ReportedAt: now.Format(time.RFC3339),
		Selections: []ReportSelection{{Scope: productRoute.Scope, CandidateID: productRoute.ID}},
		Runtime:    &RuntimeReadback{State: "running", AppliedViewDigest: productViewDigest, Exact: true}}
	productReport, err = SignDeviceReport(productReport, productPrivate)
	if err != nil {
		t.Fatal(err)
	}
	connection, err = DialEndpoint(ctx, productEndpoint, TunnelHello{Schema: 1, Mode: "device",
		EndpointID: productEndpoint.EndpointID, Generation: productEndpoint.Generation,
		DeviceID: productCompleted.DeviceView.View.DeviceID}, productPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if status := tunnelPost(t, connection, "/v2/device/report", productReport, &struct {
		DeviceID   string `json:"device_id"`
		ReportedAt string `json:"reported_at"`
	}{}); status != http.StatusOK {
		t.Fatalf("schema-2 report status=%d", status)
	}
	_ = connection.Close()
	if len(reports.All()) != 2 {
		t.Fatal("schema-2 signed report was not persisted beside schema-1 history")
	}

	generation2 := generation1
	generation2.Generation, generation2.State, generation2.Preference = 2, "prepared", 1
	if _, err := server.putEndpoint(ctx, "endpoint-2-prepared", currentHead(runtime), generation2); err != nil {
		t.Fatal(err)
	}
	waitEndpointReady(t, endpointRuntime, generation2)
	generation2.State = "serving"
	if _, err := server.putEndpoint(ctx, "endpoint-2-serving", currentHead(runtime), generation2); err != nil {
		t.Fatal(err)
	}
	_, _, err = server.createEnrollment(ctx, "protected-invite", currentHead(runtime), enrollmentCreatePayload{
		TransactionID: "protected-transaction", ExpiresAt: now.Add(time.Minute).Format(time.RFC3339), DeviceID: "protected-device",
		Name: "Protected device", Platform: "linux", Roles: []string{"access"}, Routes: routes, Runtime: runtimeProfile})
	if err != nil {
		t.Fatal(err)
	}
	connection, err = DialEndpoint(ctx, generation2.Reference(), TunnelHello{Schema: 1, Mode: "device", EndpointID: generation2.EndpointID,
		Generation: generation2.Generation, DeviceID: "demo-device"}, private)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	generation1.Preference = 1
	if _, err := server.putEndpoint(ctx, "endpoint-1-demote", currentHead(runtime), generation1); err != nil {
		t.Fatal(err)
	}
	generation2.Preference = 0
	if _, err := server.putEndpoint(ctx, "endpoint-2-prefer", currentHead(runtime), generation2); err != nil {
		t.Fatal(err)
	}
	generation1.State = "draining"
	if _, err := server.putEndpoint(ctx, "endpoint-1-drain-too-soon", currentHead(runtime), generation1); err == nil {
		t.Fatal("generation with an active bootstrap capability began draining")
	}
	now = now.Add(2 * time.Minute)
	clock.Store(now.UnixNano())
	if _, err := server.putEndpoint(ctx, "endpoint-1-drain", currentHead(runtime), generation1); err != nil {
		t.Fatal(err)
	}
	generation1.State = "retired"
	if _, err := server.putEndpoint(ctx, "endpoint-1-retire", currentHead(runtime), generation1); err != nil {
		t.Fatal(err)
	}
	_, projection, _ := runtime.Authority.Snapshot()
	if projection.EndpointGenerations[0].State != "retired" || projection.EndpointGenerations[1].State != "serving" {
		t.Fatalf("generation rotation did not persist: %+v", projection.EndpointGenerations)
	}

	mismatch := generation2
	mismatch.Generation, mismatch.State, mismatch.Listen, mismatch.Address = 3, "prepared", freeAddress(t, "127.0.0.1"), freeAddress(t, "127.0.0.1")
	mismatch.SPKISHA256 = strings.Repeat("0", 64)
	if _, err := server.putEndpoint(ctx, "endpoint-3-prepared", currentHead(runtime), mismatch); err != nil {
		t.Fatal(err)
	}
	mismatch.State = "serving"
	if _, err := server.putEndpoint(ctx, "endpoint-3-serving", currentHead(runtime), mismatch); err == nil {
		t.Fatal("SPKI-mismatched generation entered serving")
	}

	// Revocation is one control Material removing the existing authorization.
	// The already-verified LKG remains locally verifiable for the documented
	// offline boundary, but it cannot open a new private device connection or
	// submit another report.
	if _, err := server.revokeDevice(ctx, "device-revoke", currentHead(runtime), "demo-device"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDeviceViewEnvelope(*completed.DeviceView, invite.Capability); err != nil {
		t.Fatalf("revocation rewrote the existing LKG: %v", err)
	}
	if connection, err = DialEndpoint(ctx, generation2.Reference(), TunnelHello{Schema: 1, Mode: "device",
		EndpointID: generation2.EndpointID, Generation: generation2.Generation, DeviceID: "demo-device"}, private); err == nil {
		_ = connection.Close()
		t.Fatal("revoked device opened a new private connection")
	}
	_, revokedProjection, _ := runtime.Authority.Snapshot()
	if _, found := authorizationFor(revokedProjection, "demo-device"); found || len(reports.Verified(revokedProjection)) != 0 {
		t.Fatal("revoked authorization or report remained externally consumable")
	}
	for _, device := range revokedProjection.Web.Devices {
		if device.ID == "demo-device" && device.Authorized {
			t.Fatal("Web projection still presents the revoked device as authorized")
		}
	}
	for _, path := range revokedProjection.Web.Paths {
		if path.Device == "demo-device" {
			t.Fatal("Web projection retained revoked route candidates")
		}
	}

	clock.Store(time.Unix(4102444800, 0).UnixNano())
	expired := generation2
	expired.Generation, expired.State, expired.Listen, expired.Address = 4, "prepared", freeAddress(t, "127.0.0.1"), freeAddress(t, "127.0.0.1")
	if _, err := server.putEndpoint(ctx, "endpoint-4-prepared", currentHead(runtime), expired); err != nil {
		t.Fatal(err)
	}
	expired.State = "serving"
	if _, err := server.putEndpoint(ctx, "endpoint-4-serving", currentHead(runtime), expired); err == nil {
		t.Fatal("expired certificate generation entered serving")
	}
}
