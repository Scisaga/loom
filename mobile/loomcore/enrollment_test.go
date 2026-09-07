package loomcore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testInvite(t *testing.T, platformKey ed25519.PublicKey) (string, []byte) {
	t.Helper()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32))
	digest := sha256.Sum256(platformKey)
	payload, err := json.Marshal(&enrollmentInvite{
		Schema: 1, Endpoint: "https://control.example/loom-client/enroll", Token: token,
		ExpiresAt: "2026-09-07T13:00:00Z", PlatformKeySHA256: hex.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := "loom://enroll#" + base64.RawURLEncoding.EncodeToString(payload)
	canonical, err := ParseEnrollmentInvite(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, canonical
}

func testP256Identity(t *testing.T, nodeID string) (*ecdsa.PrivateKey, []byte, []byte, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "loom test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: nodeID + ".node.internal"},
		DNSNames: []string{nodeID + ".node.internal"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, certificateTemplate, ca, &deviceKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&deviceKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return deviceKey, spki,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
}

func signedCurrentFixture(t *testing.T, privateKey ed25519.PrivateKey, generation uint64, snapshot, nodeID string) []byte {
	t.Helper()
	current := &deploymentCurrent{
		Schema: 1, Generation: generation, Snapshot: snapshot,
		PublishedAt: "2026-09-07T12:00:00Z",
	}
	if nodeID != "" {
		current.Assignments = []deploymentAssignment{{Node: nodeID, Snapshot: snapshot}}
	}
	message, err := current.signingBytes()
	if err != nil {
		t.Fatal(err)
	}
	current.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	body, err := marshalCanonical(current)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestEnrollmentInviteIsStrictAndNeverLeaksTokenInErrors(t *testing.T) {
	platformPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, inviteJSON := testInvite(t, platformPublic)
	endpoint, err := EnrollmentEndpoint(inviteJSON)
	if err != nil || endpoint != "https://control.example/loom-client/enroll" {
		t.Fatalf("endpoint=%q err=%v", endpoint, err)
	}
	if report, err := ReportEndpoint(endpoint); err != nil || report != "https://control.example/loom-client/report" {
		t.Fatalf("report=%q err=%v", report, err)
	}
	if err := ValidateEnrollmentInvitePlatformKey(inviteJSON, platformPublic); err != nil {
		t.Fatal(err)
	}
	wrongPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := ValidateEnrollmentInvitePlatformKey(inviteJSON, wrongPublic); err == nil {
		t.Fatal("wrong platform trust root was accepted")
	}

	var invite enrollmentInvite
	if err := json.Unmarshal(inviteJSON, &invite); err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{
		"loom://enroll?token=" + invite.Token,
		raw + "=",
		"loom://enroll#" + base64.RawURLEncoding.EncodeToString([]byte(`{"schema":1,"schema":1}`)),
	} {
		_, err := ParseEnrollmentInvite(malformed)
		if err == nil || strings.Contains(err.Error(), invite.Token) || strings.Contains(err.Error(), malformed) {
			t.Fatalf("unsafe malformed invite error=%v", err)
		}
	}
}

func TestBuildAndroidClaimBindsCSRAndNeverExportsAKey(t *testing.T) {
	platformPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	_, inviteJSON := testInvite(t, platformPublic)
	deviceKey, publicSPKI, _, _ := testP256Identity(t, "android-a")
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "request-a"},
	}, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	body, err := BuildAndroidClaim(inviteJSON, csrPEM, publicSPKI, "request-a")
	if err != nil {
		t.Fatal(err)
	}
	var claim enrollmentClaim
	if err := decodeStrictJSON(body, maxInviteBytes, &claim); err != nil {
		t.Fatal(err)
	}
	if claim.Platform != PlatformAndroid || claim.RequestID != "request-a" || claim.CSRPEM != string(csrPEM) || claim.Token == "" {
		t.Fatalf("claim=%+v", claim)
	}
	if bytes.Contains(body, []byte("private_key")) {
		t.Fatal("claim includes private key material")
	}
	if _, err := BuildAndroidClaim(inviteJSON, csrPEM, publicSPKI, "request-b"); err == nil {
		t.Fatal("CSR was accepted for a different request id")
	}
	_, otherSPKI, _, _ := testP256Identity(t, "android-a")
	if _, err := BuildAndroidClaim(inviteJSON, csrPEM, otherSPKI, "request-a"); err == nil {
		t.Fatal("CSR was accepted for a different Keystore public key")
	}
}

func TestValidateAndroidEnrollmentReadyBindsAllTrustRoots(t *testing.T) {
	platformPublic, platformPrivate, _ := ed25519.GenerateKey(rand.Reader)
	_, inviteJSON := testInvite(t, platformPublic)
	_, publicSPKI, caPEM, certificatePEM := testP256Identity(t, "android-a")
	authority := signedCurrentFixture(t, platformPrivate, 7, "0123456789ab", "android-a")
	response := enrollmentResponse{
		Schema: 1, ClientID: "android-a", Status: "ready", ClaimedAt: "2026-09-07T12:00:00Z",
		Next: "pull", Configuration: "ready",
		Bootstrap: &enrollmentBootstrap{
			NodeID: "android-a", DistributionURLs: []string{"https://dist.example/loom/"},
			DNS: []string{"1.1.1.1"}, SecretsEnv: "cred/android-a=secret-value\n",
			PlatformPublicKey: base64.RawStdEncoding.EncodeToString(platformPublic),
			ReleaseAuthority:  string(authority), CACertPEM: string(caPEM), NodeCertPEM: string(certificatePEM),
		},
	}
	responseJSON, _ := json.Marshal(&response)
	validated, err := ValidateAndroidEnrollmentResponse(inviteJSON, responseJSON, publicSPKI, 200)
	if err != nil {
		t.Fatal(err)
	}
	var output validatedEnrollment
	if err := decodeStrictJSON(validated, maxResponseBytes, &output); err != nil {
		t.Fatal(err)
	}
	if output.ReportEndpoint != "https://control.example/loom-client/report" ||
		output.Response.Bootstrap.PlatformPublicKey != base64.StdEncoding.EncodeToString(platformPublic) {
		t.Fatalf("validated enrollment=%+v", output)
	}

	_, otherSPKI, _, _ := testP256Identity(t, "android-a")
	if _, err := ValidateAndroidEnrollmentResponse(inviteJSON, responseJSON, otherSPKI, 200); err == nil {
		t.Fatal("certificate not bound to Keystore SPKI was accepted")
	}
	tampered := response
	tampered.Bootstrap = &enrollmentBootstrap{}
	*tampered.Bootstrap = *response.Bootstrap
	tampered.Bootstrap.PlatformPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, ed25519.PublicKeySize))
	tamperedJSON, _ := json.Marshal(&tampered)
	if _, err := ValidateAndroidEnrollmentResponse(inviteJSON, tamperedJSON, publicSPKI, 200); err == nil {
		t.Fatal("bootstrap platform key not bound to invite was accepted")
	}
	if _, err := ValidateAndroidEnrollmentResponse(inviteJSON, responseJSON, publicSPKI, 202); err == nil {
		t.Fatal("ready response with HTTP 202 was accepted")
	}
}

func TestValidateAndroidEnrollmentPendingIsStrict(t *testing.T) {
	platformPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	_, inviteJSON := testInvite(t, platformPublic)
	_, publicSPKI, _, _ := testP256Identity(t, "android-a")
	pending := []byte(`{"schema":1,"client_id":"android-a","status":"provisioning","claimed_at":"2026-09-07T12:00:00Z","replay":true,"next":"wait_for_configuration","configuration":"pending"}`)
	if _, err := ValidateAndroidEnrollmentResponse(inviteJSON, pending, publicSPKI, 202); err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(pending, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
	if _, err := ValidateAndroidEnrollmentResponse(inviteJSON, duplicate, publicSPKI, 202); err == nil {
		t.Fatal("duplicate response field was accepted")
	}
}
