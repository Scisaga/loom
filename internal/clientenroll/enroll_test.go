package clientenroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"loom/internal/publish"
)

func TestParseInviteUsesFragmentAndRejectsTokenInQuery(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))
	payload, _ := json.Marshal(invitePayload{
		Schema: 1, Endpoint: "https://control.example/api/client/enroll",
		Token: token, ExpiresAt: "2026-09-01T00:00:00Z",
		PlatformKeySHA256: strings.Repeat("a", sha256.Size*2),
	})
	raw := "loom://enroll#" + base64.RawURLEncoding.EncodeToString(payload)
	invite, err := ParseInvite(raw)
	if err != nil || invite.Token != token || invite.Endpoint != "https://control.example/api/client/enroll" ||
		invite.PlatformKeySHA256 != strings.Repeat("a", sha256.Size*2) {
		t.Fatalf("invite=%+v err=%v", invite, err)
	}
	_, err = ParseInvite("loom://enroll?token=" + token)
	if err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("query token error=%v", err)
	}
}

func TestClaimPersistsIdentityBeforePOSTAndReusesCSR(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 32))
	var requests []claimRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request claimRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		requests = append(requests, request)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"schema":1,"client_id":"client-a","status":"provisioning","claimed_at":"2026-08-31T12:00:00Z","replay":true,"next":"wait_for_configuration","configuration":"pending"}`)
	}))
	defer server.Close()
	stateDir := filepath.Join(t.TempDir(), "identity")
	invite := Invite{Endpoint: server.URL + "/api/client/enroll", Token: token, ExpiresAt: "2026-09-01T00:00:00Z"}
	for i := 0; i < 2; i++ {
		response, err := Claim(context.Background(), server.Client(), invite, stateDir, nil)
		if err != nil || response.Configuration != "pending" {
			t.Fatalf("claim %d response=%+v err=%v", i, response, err)
		}
	}
	if len(requests) != 2 || requests[0].CSRPEM != requests[1].CSRPEM || requests[0].RequestID != requests[1].RequestID {
		t.Fatalf("idempotent claim changed identity: %+v", requests)
	}
	if requests[0].Token != token || requests[0].Platform != Platform {
		t.Fatalf("claim request=%+v", requests[0])
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("state file %s mode=%04o", entry.Name(), info.Mode().Perm())
		}
		if !entry.IsDir() {
			body, err := os.ReadFile(filepath.Join(stateDir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(body, []byte(token)) {
				t.Fatalf("bearer token persisted in %s", entry.Name())
			}
		}
	}
}

func TestClaimWithServerSendsOnlyPublicServerFacts(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, 32))
	var request claimRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"schema":1,"client_id":"server-a","status":"provisioning","claimed_at":"2026-09-01T19:00:00Z","next":"wait_for_configuration","configuration":"pending"}`)
	}))
	defer server.Close()
	facts := &ServerEnrollment{
		PublicEndpoint: "edge.example.net", InboundPort: 61698, Direction: "bidirectional",
		WGPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Country: "CN", City: "Beijing",
	}
	_, err := ClaimWithServer(context.Background(), server.Client(), Invite{
		Endpoint: server.URL, Token: token,
	}, filepath.Join(t.TempDir(), "state"), facts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if request.Server == nil || *request.Server != *facts || request.Token != token || request.CSRPEM == "" {
		t.Fatalf("claim request = %+v", request)
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "private_key") || strings.Contains(string(body), "node.key") {
		t.Fatalf("claim leaked local WireGuard key material: %s", body)
	}
}

func TestPreparedWindowsIdentityClaimsWithoutFileBackedLinuxState(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x54}, 32))
	var request claimRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"schema":1,"client_id":"windows-a","status":"provisioning","claimed_at":"2026-09-03T12:00:00Z","next":"wait_for_configuration","configuration":"pending"}`)
	}))
	defer server.Close()
	identity, err := GeneratePreparedIdentity(PlatformWindowsDesktop, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := ClaimPrepared(context.Background(), server.Client(), Invite{
		Endpoint: server.URL, Token: token, ExpiresAt: "2026-09-03T12:15:00Z",
	}, identity, nil)
	if err != nil || response.Configuration != "pending" {
		t.Fatalf("prepared Windows claim=%+v err=%v", response, err)
	}
	if request.Platform != PlatformWindowsDesktop || request.RequestID != identity.RequestID ||
		request.CSRPEM != string(identity.CSRPEM) || request.Token != token {
		t.Fatalf("prepared Windows request=%+v", request)
	}
	tampered := identity
	tampered.RequestID = "another-request"
	if err := ValidatePreparedIdentity(tampered); err == nil {
		t.Fatal("prepared identity accepted a request_id not bound by its CSR")
	}
}

func TestClaimDoesNotFollowRedirectWithBearerBody(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32))
	received := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { received = true }))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client := source.Client()
	client.Transport = trustBothServers(t, source, target)
	_, err := Claim(context.Background(), client, Invite{Endpoint: source.URL, Token: token}, filepath.Join(t.TempDir(), "state"), nil)
	if err == nil || IsTransient(err) || received || strings.Contains(err.Error(), token) {
		t.Fatalf("redirect err=%v transient=%v received=%v", err, IsTransient(err), received)
	}
}

func TestClaimClassifiesStatusAndReportsSafeControlDetail(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x62}, 32))
	status := http.StatusServiceUnavailable
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"error":"do not expose body"}`)
	}))
	defer server.Close()
	stateDir := filepath.Join(t.TempDir(), "state")
	invite := Invite{Endpoint: server.URL, Token: token}
	_, err := Claim(context.Background(), server.Client(), invite, stateDir, nil)
	if !IsTransient(err) || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "do not expose body") {
		t.Fatalf("503 error=%v transient=%v", err, IsTransient(err))
	}
	status = http.StatusConflict
	_, err = Claim(context.Background(), server.Client(), invite, stateDir, nil)
	if err == nil || IsTransient(err) || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "do not expose body") {
		t.Fatalf("409 error=%v transient=%v", err, IsTransient(err))
	}
}

func TestClaimNeverReportsBearerFromControlError(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x63}, 32))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token " + token})
	}))
	defer server.Close()
	_, err := Claim(context.Background(), server.Client(), Invite{
		Endpoint: server.URL, Token: token,
	}, filepath.Join(t.TempDir(), "state"), nil)
	if err == nil || strings.Contains(err.Error(), token) || err.Error() != "[§9.2 加入流程] 控制中心返回 HTTP 400" {
		t.Fatalf("unsafe status error=%v", err)
	}
}

func TestInstallReadyValidatesAndLandsBootstrap(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	endpoint := "https://control.example/api/client/enroll"
	// Creating the identity does not require a live control plane: the handler
	// returns pending after capturing the CSR.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"schema":1,"client_id":"client-a","status":"provisioning","claimed_at":"2026-08-31T12:00:00Z","replay":false,"next":"wait_for_configuration","configuration":"pending"}`)
	}))
	defer server.Close()
	endpoint = server.URL
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32))
	if _, err := Claim(context.Background(), server.Client(), Invite{Endpoint: endpoint, Token: token}, stateDir, nil); err != nil {
		t.Fatal(err)
	}
	keyPEM, _, err := loadIdentity(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := parsePrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, certPEM := issueTestCertificate(t, deviceKey)
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	current := publish.DeploymentCurrent{
		Schema: 1, Generation: 1, Snapshot: "0123456789ab", PublishedAt: "2026-08-31T12:00:00Z",
	}
	if err := current.Sign(signingKey); err != nil {
		t.Fatal(err)
	}
	authority, err := current.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := &Bootstrap{
		NodeID: "client-a", DistributionURLs: []string{"https://dist.example/loom/"},
		DNS: []string{"223.5.5.5"}, SecretsEnv: "cred/client-a=test-secret\n",
		PlatformPublicKey: base64.StdEncoding.EncodeToString(signingKey.Public().(ed25519.PublicKey)),
		ReleaseAuthority:  string(authority), CACertPEM: caPEM, NodeCertPEM: certPEM,
	}
	root := t.TempDir()
	paths := Paths{
		StateDir: stateDir, TLSKey: filepath.Join(root, "etc/loom/tls/node.key"),
		TLSCert: filepath.Join(root, "etc/loom/tls/node.crt"), CACert: filepath.Join(root, "etc/loom/tls/ca.crt"),
		PlatformPublicKey: filepath.Join(root, "etc/loom/trust/platform.pub"),
		Secrets:           filepath.Join(root, "etc/loom/secrets/node.env"), NodeID: filepath.Join(root, "etc/loom/node-id"),
		ExpectedCurrent: filepath.Join(stateDir, "expected-current.json"),
	}
	response := Response{
		Schema: 1, ClientID: "client-a", Status: "ready", ClaimedAt: "2026-08-31T12:00:00Z",
		Next: "pull", Configuration: "ready", Bootstrap: bootstrap,
	}
	_, meta, err := loadIdentity(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := os.ReadFile(filepath.Join(stateDir, identityCSRFile))
	if err != nil {
		t.Fatal(err)
	}
	material, err := ValidateReady(response, PreparedIdentity{
		Schema: Schema, Platform: PlatformLinuxServer, Endpoint: endpoint, RequestID: meta.RequestID,
		PrivateKeyPEM: keyPEM, CSRPEM: csrPEM,
	})
	if err != nil || material.NodeID != "client-a" {
		t.Fatalf("validated ready material=%+v err=%v", material, err)
	}
	if err := InstallReady(paths, response); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		path string
		mode os.FileMode
	}{
		{paths.TLSKey, 0o600}, {paths.TLSCert, 0o644}, {paths.CACert, 0o644},
		{paths.PlatformPublicKey, 0o644}, {paths.Secrets, 0o600}, {paths.NodeID, 0o644},
		{paths.ExpectedCurrent, 0o600},
	} {
		info, err := os.Stat(check.path)
		if err != nil {
			t.Fatalf("stat %s: %v", check.path, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != check.mode {
			t.Fatalf("%s mode=%v", check.path, info.Mode())
		}
	}
	if got, _ := os.ReadFile(paths.TLSKey); !bytes.Equal(got, keyPEM) {
		t.Fatal("installed TLS key is not the locally generated identity key")
	}
}

func issueTestCertificate(t *testing.T, deviceKey *ecdsa.PrivateKey) (string, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: now, NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "client-a.node.internal"},
		DNSNames:  []string{"client-a.node.internal"},
		NotBefore: now, NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, ca, &deviceKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return string(caPEM), string(certPEM)
}

func trustBothServers(t *testing.T, servers ...*httptest.Server) http.RoundTripper {
	t.Helper()
	pool := x509.NewCertPool()
	for _, server := range servers {
		certificate := server.Certificate()
		if certificate == nil {
			t.Fatal("TLS test server has no certificate")
		}
		pool.AddCert(certificate)
	}
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
}
