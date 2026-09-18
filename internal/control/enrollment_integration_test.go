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
	"testing"
	"time"
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
		Reports: reports, Now: func() time.Time { return now }}
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
	for server.Endpoints == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if server.Endpoints == nil {
		t.Fatal("endpoint runtime did not start")
	}

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
	waitEndpointReady(t, server.Endpoints, generation1)
	generation1.State = "serving"
	if _, err := server.putEndpoint(ctx, "endpoint-1-serving", currentHead(runtime), generation1); err != nil {
		t.Fatal(err)
	}

	routes := []RouteCandidate{
		{ID: "one-hop", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "internet"},
		{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-relay", "demo-exit"}, Scope: "internet"},
	}
	created, inviteText, err := server.createEnrollment(ctx, "invite-create", currentHead(runtime), enrollmentCreatePayload{
		TransactionID: "demo-transaction", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), DeviceID: "demo-device",
		Name: "Demo device", Platform: "linux", Roles: []string{"access"}, Routes: routes})
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
	readback := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(readback, httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil))
	if readback.Code != http.StatusOK || !bytes.Contains(readback.Body.Bytes(), []byte(`"enrollment":"completed"`)) ||
		!bytes.Contains(readback.Body.Bytes(), []byte(`"reports":[`)) {
		t.Fatalf("authenticated UI/API did not read back enrollment and report: status=%d", readback.Code)
	}
	selected, err := SelectRoute(routes, report.Observations, "demo-exit", "one-hop", now.Add(time.Minute))
	if err != nil || selected != "relay" {
		t.Fatalf("same-exit fallback=%q err=%v", selected, err)
	}

	generation2 := generation1
	generation2.Generation, generation2.State, generation2.Preference = 2, "prepared", 1
	if _, err := server.putEndpoint(ctx, "endpoint-2-prepared", currentHead(runtime), generation2); err != nil {
		t.Fatal(err)
	}
	waitEndpointReady(t, server.Endpoints, generation2)
	generation2.State = "serving"
	if _, err := server.putEndpoint(ctx, "endpoint-2-serving", currentHead(runtime), generation2); err != nil {
		t.Fatal(err)
	}
	_, _, err = server.createEnrollment(ctx, "protected-invite", currentHead(runtime), enrollmentCreatePayload{
		TransactionID: "protected-transaction", ExpiresAt: now.Add(time.Minute).Format(time.RFC3339), DeviceID: "protected-device",
		Name: "Protected device", Platform: "linux", Roles: []string{"access"}, Routes: routes})
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

	now = time.Unix(4102444800, 0).UTC()
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
