package report

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/clientregistry"
	"loom/internal/webui"
)

func TestClientInviteUsesOpaqueFragmentAndClaimKeepsProvisioningExplicit(t *testing.T) {
	dir := t.TempDir()
	ssotPath := filepath.Join(dir, "ssot.yaml")
	writeClientTestSSOT(t, ssotPath)
	deps := newClientControlDeps(&Control{
		SSOTPath: ssotPath, ClientRegistryPath: filepath.Join(dir, "registry.json"),
		ClientEnrollmentURL: "https://control.example/api/client/enroll",
	}, nil)
	invite, err := deps.CreateInvite(webui.ClientInviteInput{Name: "build server"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(invite.InviteURI)
	if err != nil || u.Scheme != "loom" || u.Host != "enroll" || u.RawQuery != "" || u.Fragment == "" {
		t.Fatalf("invite URI=%q parsed=%+v err=%v", invite.InviteURI, u, err)
	}
	payloadBody, err := base64.RawURLEncoding.DecodeString(u.Fragment)
	if err != nil {
		t.Fatal(err)
	}
	var payload clientInvitePayload
	if err := json.Unmarshal(payloadBody, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Endpoint != invite.EnrollmentURL || payload.Token == "" || payload.ExpiresAt != invite.ExpiresAt ||
		strings.Contains(invite.EnrollmentURL, payload.Token) {
		t.Fatalf("payload=%+v invite=%+v", payload, invite)
	}
	artifact, err := deps.InviteArtifact(invite.InviteID)
	if err != nil || artifact.ClientID != invite.ClientID || artifact.ClientName != "build server" ||
		artifact.InviteURI != invite.InviteURI || artifact.ExpiresAt != invite.ExpiresAt {
		t.Fatalf("artifact=%+v invite=%+v err=%v", artifact, invite, err)
	}

	claim, err := deps.Claim(webui.ClientClaimInput{
		Token: payload.Token, Platform: "linux-server", CSRPEM: clientCSR(t), RequestID: "install-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if claim.Status != "provisioning" || claim.Configuration != "pending" || claim.Next != "wait_for_configuration" {
		t.Fatalf("claim=%+v", claim)
	}
	inventory, err := deps.List()
	var enrolled *webui.ClientView
	for i := range inventory.Clients {
		if inventory.Clients[i].ID == invite.ClientID {
			enrolled = &inventory.Clients[i]
		}
	}
	if err != nil || enrolled == nil || enrolled.Status != "provisioning" ||
		enrolled.DataPlaneStatus != "pending" || enrolled.ProfileVersion != "standard-device@v1" {
		t.Fatalf("inventory=%+v err=%v", inventory, err)
	}
}

func TestInvalidEnrollmentURLDoesNotCreateInvitationState(t *testing.T) {
	dir := t.TempDir()
	ssotPath := filepath.Join(dir, "ssot.yaml")
	if err := os.WriteFile(ssotPath, []byte("nodes: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(dir, "registry.json")
	deps := newClientControlDeps(&Control{
		SSOTPath: ssotPath, ClientRegistryPath: registryPath,
		ClientEnrollmentURL: "http://control.example/api/client/enroll?token=bad",
	}, nil)
	if _, err := deps.CreateInvite(webui.ClientInviteInput{Name: "device"}); err == nil {
		t.Fatal("insecure enrollment URL was accepted")
	}
	if _, err := os.Stat(registryPath); !os.IsNotExist(err) {
		t.Fatalf("invalid URL left registry state: %v", err)
	}
}

func TestClientProvisionHookMarksReadyOnlyWithCompleteBootstrap(t *testing.T) {
	dir := t.TempDir()
	ssotPath := filepath.Join(dir, "ssot.yaml")
	writeClientTestSSOT(t, ssotPath)
	var provisionedID string
	deps := newClientControlDeps(&Control{
		SSOTPath: ssotPath, ClientRegistryPath: filepath.Join(dir, "registry.json"),
		ClientEnrollmentURL: "https://control.example/api/client/enroll",
	}, func(client clientregistry.Client, csrPEM string) (*webui.ClientBootstrap, error) {
		provisionedID = client.ID
		return &webui.ClientBootstrap{
			NodeID: client.ID, DistributionURLs: []string{"https://dist.example/loom/"},
			SecretsEnv: "cred/client=value\n", PlatformPublicKey: "platform-public",
			ReleaseAuthority: `{"schema":1}`, CACertPEM: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
			NodeCertPEM: "-----BEGIN CERTIFICATE-----\nnode\n-----END CERTIFICATE-----",
		}, nil
	})
	invite, err := deps.CreateInvite(webui.ClientInviteInput{Name: "ready device"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(invite.InviteURI)
	body, _ := base64.RawURLEncoding.DecodeString(u.Fragment)
	var payload clientInvitePayload
	_ = json.Unmarshal(body, &payload)
	result, err := deps.Claim(webui.ClientClaimInput{
		Token: payload.Token, Platform: "linux-server", CSRPEM: clientCSR(t), RequestID: "install-ready",
	})
	if err != nil || result.Status != "ready" || result.Configuration != "ready" ||
		result.Next != "pull" || result.Bootstrap == nil || provisionedID != result.ClientID {
		t.Fatalf("result=%+v provisioned=%q err=%v", result, provisionedID, err)
	}
	inventory, err := deps.List()
	ready := false
	for i := range inventory.Clients {
		ready = ready || inventory.Clients[i].ID == result.ClientID && inventory.Clients[i].Status == "ready"
	}
	if err != nil || !ready {
		t.Fatalf("inventory=%+v err=%v", inventory, err)
	}
}

func TestPublicClientBaseAndInstallerAreDeploymentConfigured(t *testing.T) {
	base, err := validClientPublicBaseURL(" https://download.example/loom/device-dist ")
	if err != nil || base != "https://download.example/loom/device-dist/" {
		t.Fatalf("public base=%q err=%v", base, err)
	}
	for _, invalid := range []string{"", "http://download.example/", "https://user@download.example/", "https://download.example/?token=x"} {
		if _, err := validClientPublicBaseURL(invalid); err == nil {
			t.Errorf("invalid public base %q accepted", invalid)
		}
	}
	script := string(linuxPublicInstallScript(webui.LinuxClientPackageView{
		Filename:  "loom-client-linux-amd64.tar.gz",
		PublicURL: "https://download.example/loom/device-dist/loom-client-linux-amd64.tar.gz",
	}))
	for _, want := range []string{"--proto '=https'", "sha256sum -c", "install.sh\" --no-enroll", "loom client enroll -stdin"} {
		if !strings.Contains(script, want) {
			t.Errorf("public installer missing %q", want)
		}
	}
	for _, forbidden := range []string{"loom://", "invite-file", "client_id", "10.99."} {
		if strings.Contains(script, forbidden) {
			t.Errorf("public installer contains private/enrollment material %q", forbidden)
		}
	}
}

func writeClientTestSSOT(t *testing.T, path string) {
	t.Helper()
	body, err := os.ReadFile("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	body = bytes.Replace(body, []byte("declarations:\n"), []byte(`enrollment_profiles:
  - id: standard-device
    version: 1
    default: true
    responsibilities: [use_loom]
    destination_grants: [best-egress]
declarations:
`), 1)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func clientCSR(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "install-1"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
