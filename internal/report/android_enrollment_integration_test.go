package report

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"loom/internal/attest"
	"loom/internal/clientregistry"
	"loom/internal/model"
	"loom/internal/secret"
	"loom/internal/webui"
)

// TestAndroidEnrollmentServerVerticalSlice keeps the public Web UI/enrollment
// boundary, provisioning transaction and trusted report receiver in one test.
// The renderer has a separate cross-contract test which compares
// AndroidBundleSecretRefs with the actual signed bundle payload.
func TestAndroidEnrollmentServerVerticalSlice(t *testing.T) {
	control, paths := clientProvisionFixture(t)
	control.ClientRegistryPath = filepath.Join(filepath.Dir(control.SSOTPath), "registry.json")
	control.ClientEnrollmentURL = "https://control.example/loom-client/enroll"
	now := time.Now().UTC().Truncate(time.Second)
	healthPath := filepath.Join(t.TempDir(), "publisher.json")

	// Seed the same platform trust root and CA which will be returned at ready.
	// Publisher evidence initially covers the pre-enrollment SSOT, so an exact
	// claim replay must remain pending until evidence advances to the new SSOT.
	initialSSOT, err := os.ReadFile(control.SSOTPath)
	if err != nil {
		t.Fatal(err)
	}
	prepareClientReadyFiles(t, paths, healthPath, initialSSOT, now)

	var saveMu sync.Mutex
	provisioner := newClientProvisioner(control, &saveMu)
	provisioner.now = func() time.Time { return now }
	provisioner.health = healthPath
	provisioner.install = func(context.Context, string, []byte) error { return nil }
	provision := func(client clientregistry.Client, csrPEM string) (*webui.ClientBootstrap, error) {
		result, err := provisioner.provision(client, csrPEM)
		if err != nil || !result.Ready {
			return nil, err
		}
		bootstrap := result.Bootstrap
		return &webui.ClientBootstrap{
			NodeID: bootstrap.NodeID, DistributionURLs: bootstrap.DistributionURLs,
			DNS: bootstrap.DNS, SecretsEnv: bootstrap.SecretsEnv,
			PlatformPublicKey: bootstrap.PlatformPublicKey, ReleaseAuthority: bootstrap.ReleaseAuthority,
			CACertPEM: bootstrap.CACertPEM, NodeCertPEM: bootstrap.NodeCertPEM,
		}, nil
	}
	deviceControl := newClientControlDeps(control, provision)
	ui := webui.Deps{
		Node: "cn-bj", Operator: "operator-secret", Now: func() time.Time { return now },
		Snapshot: func() webui.View { return webui.View{} },
		Control:  &webui.ControlDeps{Devices: deviceControl},
	}
	handler := webui.Handler(ui)

	login := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{
		"password": {ui.Operator}, "next": {"/devices?new=1"},
	}.Encode()))
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResponse := httptest.NewRecorder()
	handler.ServeHTTP(loginResponse, login)
	loginResult := loginResponse.Result()
	if loginResponse.Code != http.StatusSeeOther || len(loginResult.Cookies()) != 1 {
		t.Fatalf("operator login=%d headers=%v", loginResponse.Code, loginResponse.Header())
	}
	session := loginResult.Cookies()[0]

	create := httptest.NewRequest(http.MethodPost, "/devices/create", strings.NewReader(url.Values{
		"name":              {"Android integration phone"},
		"platform":          {string(model.Android)},
		"responsibility":    {"use_loom"},
		"destination_grant": {"best-egress"},
	}.Encode()))
	create.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	create.AddCookie(session)
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, create)
	location := createResponse.Header().Get("Location")
	if createResponse.Code != http.StatusSeeOther || !strings.HasPrefix(location, "/devices/invites/") {
		t.Fatalf("Android UI create=%d location=%q body=%s", createResponse.Code, location, createResponse.Body.String())
	}
	inviteID := strings.TrimPrefix(location, "/devices/invites/")
	artifact, err := deviceControl.InviteArtifact(inviteID)
	if err != nil || artifact.Platform != string(model.Android) ||
		!slices.Equal(artifact.Responsibilities, []string{"use_loom"}) {
		t.Fatalf("Android invitation=%+v err=%v", artifact, err)
	}
	invitePage := httptest.NewRequest(http.MethodGet, location, nil)
	invitePage.AddCookie(session)
	invitePageResponse := httptest.NewRecorder()
	handler.ServeHTTP(invitePageResponse, invitePage)
	if invitePageResponse.Code != http.StatusOK ||
		!strings.Contains(invitePageResponse.Body.String(), "Open Loom, then scan the QR code") ||
		strings.Contains(invitePageResponse.Body.String(), "Local or SSH-assisted bootstrap") ||
		strings.Contains(invitePageResponse.Body.String(), "Download Linux package") {
		t.Fatalf("Android invitation page crossed Linux package gate: status=%d body=%s",
			invitePageResponse.Code, invitePageResponse.Body.String())
	}

	const requestID = "android-integration-request"
	csrPEM, deviceKeyPEM := androidIntegrationCSR(t, requestID)
	claimBody, err := json.Marshal(map[string]string{
		"token": recoveryInviteToken(t, artifact.InviteURI), "platform": string(model.Android),
		"csr_pem": csrPEM, "request_id": requestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	postClaim := func() (int, webui.ClientClaimResult) {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/api/client/enroll", bytes.NewReader(claimBody))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var result webui.ClientClaimResult
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatalf("decode claim response %d %q: %v", response.Code, response.Body.String(), err)
		}
		return response.Code, result
	}
	if status, first := postClaim(); status != http.StatusAccepted || first.Configuration != "pending" || first.Replay {
		t.Fatalf("first Android claim status=%d result=%+v", status, first)
	}
	status, replay := postClaim()
	if status != http.StatusAccepted || replay.Configuration != "pending" || !replay.Replay {
		t.Fatalf("exact pending replay status=%d result=%+v", status, replay)
	}

	provisionedSSOT, err := os.ReadFile(control.SSOTPath)
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load(provisionedSSOT)
	if err != nil {
		t.Fatal(err)
	}
	node := ssot.NodeByID()[replay.ClientID]
	if node == nil || node.Server != nil || node.Access == nil || node.Access.Platform != model.Android ||
		len(node.Access.MixedPorts) != 0 || node.Access.DefaultDeclaration != "best-egress" {
		t.Fatalf("provisioned Android TUN-only node=%+v", node)
	}

	// Simulate harmless stale central entries and then advance exact publisher
	// evidence. Only placeholders in this Android bundle may cross bootstrap.
	all, err := secret.Load(paths.masterSecrets)
	if err != nil {
		t.Fatal(err)
	}
	all["telemetry/"+node.ID] = "stale-telemetry"
	all["unused/"+node.ID] = "stale-owner-local"
	if err := os.WriteFile(paths.masterSecrets, secret.Encode(all, masterSecretsHeader()), 0o600); err != nil {
		t.Fatal(err)
	}
	advanceAndroidIntegrationPublisher(t, healthPath, provisionedSSOT, now)
	status, ready := postClaim()
	if status != http.StatusOK || ready.Configuration != "ready" || !ready.Replay || ready.Bootstrap == nil {
		t.Fatalf("ready Android replay status=%d result=%+v", status, ready)
	}
	secretPath := filepath.Join(t.TempDir(), "bootstrap.env")
	if err := os.WriteFile(secretPath, []byte(ready.Bootstrap.SecretsEnv), 0o600); err != nil {
		t.Fatal(err)
	}
	delivered, err := secret.Load(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	var deliveredRefs []string
	for ref := range delivered {
		deliveredRefs = append(deliveredRefs, ref)
	}
	sort.Strings(deliveredRefs)
	wantRefs := AndroidBundleSecretRefs(ssot, node)
	if !slices.Equal(deliveredRefs, wantRefs) || len(wantRefs) != 3 ||
		wantRefs[0] != "api/"+node.ID || wantRefs[2] != "probe/"+node.ID {
		t.Fatalf("Android bootstrap refs=%v, exact bundle refs=%v", deliveredRefs, wantRefs)
	}

	var authority clientReleaseAuthority
	if err := json.Unmarshal([]byte(ready.Bootstrap.ReleaseAuthority), &authority); err != nil {
		t.Fatal(err)
	}
	observation := Observation{
		Node: node.ID, TS: now.Format(time.RFC3339), Applied: authority.Snapshot,
	}
	_, currentClaim := claimsForObservation(&observation, 5)
	observation.Attest, err = attest.Sign(currentClaim, deviceKeyPEM, []byte(ready.Bootstrap.NodeCertPEM))
	if err != nil {
		t.Fatal(err)
	}
	observation.SelfCheck, err = attest.SignSelfCheck(attest.SelfCheckClaim{
		Version: attest.SelfCheckClaimVersion, Node: node.ID, TS: observation.TS, Healthy: true,
	}, deviceKeyPEM, []byte(ready.Bootstrap.NodeCertPEM))
	if err != nil {
		t.Fatal(err)
	}
	ca := []byte(ready.Bootstrap.CACertPEM)
	table := newTable(5)
	table.verify = func(got *Observation, at time.Time, maxAge time.Duration) error {
		_, err := VerifyObservationAtLeast(got, ca, at, maxAge, 5)
		return err
	}
	table.verifySelfCheck = func(got *Observation, at time.Time, maxAge time.Duration) error {
		_, err := verifySelfCheckAttachment(got, ca, at, maxAge)
		return err
	}
	receiver := newClientReportReceiver(table, control, func() time.Time { return now }, 10*time.Minute, nil)
	receiver.readCA = func(string) ([]byte, error) { return ca, nil }
	reportResponse := postClientReport(t, receiver, &observation)
	if reportResponse.Code != http.StatusNoContent || reportResponse.Body.Len() != 0 {
		t.Fatalf("trusted Android report=%d %q", reportResponse.Code, reportResponse.Body.String())
	}
	learned := table.snapshot("cn-bj", now, 10*time.Minute)
	if len(learned) != 1 || learned[0].Node != node.ID || learned[0].Applied != authority.Snapshot {
		t.Fatalf("trusted Android report missing from table: %+v", learned)
	}
}

func androidIntegrationCSR(t *testing.T, requestID string) (string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		// Android's external-signer core binds the sole subject CN to the
		// idempotency key before it ever sends the CSR.
		Subject: pkix.Name{CommonName: requestID},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER})),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func advanceAndroidIntegrationPublisher(t *testing.T, healthPath string, ssotBody []byte, now time.Time) {
	t.Helper()
	health, err := readPublisherState(healthPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(ssotBody)
	health.LastSSOT = hex.EncodeToString(digest[:])
	health.UpdatedAt = now.Format(time.RFC3339Nano)
	health.LastSuccess = now.Format(time.RFC3339Nano)
	for i := range health.DistributionChecks {
		health.DistributionChecks[i].SSOT = health.LastSSOT
		health.DistributionChecks[i].CheckedAt = now.Format(time.RFC3339Nano)
	}
	body, err := json.Marshal(health)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(healthPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
