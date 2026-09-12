package clientv2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestPrivateEnrollmentClientPinsInnerTLSAndKeepsPreflightTokenFree(t *testing.T) {
	now := time.Date(2026, 9, 11, 11, 5, 0, 0, time.UTC)
	certificate, roots, pin := privateEnrollmentCertificate(t, now, "10.30.0.1")
	opening := privateClientOpening(t)
	commitment, commitmentHash, err := wire.IntentCommitment(&opening)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		if request.URL.Path == "/v2/enrollment/claim" {
			if bytes.Contains(body, []byte(`"token"`)) {
				t.Error("resume submission 泄漏 Invite token field")
			}
			var resume wire.EnrollmentResumeSubmissionV1
			if _, err := wire.DecodeStrict(body, 1<<20, &resume); err != nil {
				t.Error(err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			result := wire.EnrollmentClaimResultV2{Schema: 2, Status: "reserved",
				TransactionStateHash: wire.HashRaw("private-client-test", []byte("resume-transaction")),
				ProgressReceipt:      []byte(`{"schema":1}`)}
			encoded, _ := wire.MarshalCanonical(result)
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("Cache-Control", "no-store")
			response.WriteHeader(http.StatusAccepted)
			_, _ = response.Write(encoded)
			return
		}
		if bytes.Contains(body, []byte(`"token"`)) || bytes.Contains(body, []byte(`"csr_der"`)) ||
			bytes.Contains(body, []byte(`"device_identity_public_key"`)) {
			t.Error("preflight 泄漏 token/CSR/key")
		}
		var preflight wire.EnrollmentIntentPreflightRequestV1
		if _, err := wire.DecodeStrict(body, 1<<20, &preflight); err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		requestHash, _ := wire.EnrollmentIntentPreflightRequestHash(&preflight)
		result := wire.EnrollmentIntentPreflightResponseV1{
			Schema: 1, ClusterID: preflight.ClusterID, InviteID: preflight.InviteID, RequestHash: requestHash,
			DeviceEnrollmentIntentCommitment: commitment, DeviceEnrollmentIntentOpening: opening,
		}
		encoded, _ := wire.MarshalCanonical(result)
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		_, _ = response.Write(encoded)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	ref := wire.PrivateEnrollmentServiceRefV1{
		Schema: 1, ServiceID: "enrollment-service", OverlayIP: "10.30.0.1", TCPPort: 7444,
		InternalCAProfileRef: "internal-ca-profile", ServerIdentitySPKIPins: []string{pin}, ServiceGeneration: 1,
	}
	client, err := NewPrivateEnrollmentClient(ref, roots, dial, func() time.Time { return now }, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := wire.EnrollmentIntentPreflightRequestV1{
		Schema: 1, ClusterID: "cluster", InviteID: "invite",
		CertifiedInviteRecordHash: wire.HashRaw("private-client-test", []byte("record")),
		CapabilityID:              wire.HashRaw("private-client-test", []byte("capability")),
	}
	result, err := client.Preflight(context.Background(), request, commitmentHash)
	if err != nil || !wire.EqualCanonical(result.DeviceEnrollmentIntentOpening, opening) {
		t.Fatalf("preflight result=%#v err=%v", result, err)
	}
	resumeResult, err := client.SubmitResume(context.Background(), wire.EnrollmentResumeSubmissionV1{Schema: 1})
	if err != nil || resumeResult.Status != "reserved" || len(resumeResult.ProgressReceipt) == 0 {
		t.Fatalf("token-free resume transport 失败: result=%#v err=%v", resumeResult, err)
	}

	wrong := ref
	wrong.ServerIdentitySPKIPins = []string{wire.HashRaw("private-client-test", []byte("wrong-pin"))}
	wrongClient, err := NewPrivateEnrollmentClient(wrong, roots, dial, func() time.Time { return now }, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongClient.Preflight(context.Background(), request, commitmentHash); err == nil || !strings.Contains(err.Error(), "SPKI") {
		t.Fatalf("wrong SPKI pin 未被 inner TLS 拒绝: %v", err)
	}
}

func privateEnrollmentCertificate(t *testing.T, now time.Time, overlayIP string) (tls.Certificate, *x509.CertPool, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Loom internal test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ip := net.ParseIP(overlayIP)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{ip}, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	privateDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	certificate, err := tls.X509KeyPair(certificatePEM, privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return certificate, roots, "sha256:" + hex.EncodeToString(digest[:])
}

func privateClientOpening(t *testing.T) wire.DeviceEnrollmentIntentOpeningV1 {
	t.Helper()
	intent := wire.DeviceEnrollmentIntentV1{
		Schema: 1, ClusterID: "cluster", InviteID: "invite", DeviceID: "linux-device", Platform: "linux-server",
		DeviceCertificateProfileRef: wire.DeviceCertificateProfileRefV1{
			ProfileID: "device-profile", Generation: 1,
			DeviceCertificateProfileIntentHash: wire.HashRaw("private-client-test", []byte("profile-intent")),
			DeviceCertificateProfileStateHash:  wire.HashRaw("private-client-test", []byte("profile-state")),
		},
		WrappingKeyProfiles: []string{"p256-root-only-pkcs8-ecdh-v1"},
		Membership:          wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"},
		Responsibilities:    wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}},
		Grants:              wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}},
	}
	intentHash, err := wire.EnrollmentIntentHash(&intent)
	if err != nil {
		t.Fatal(err)
	}
	return wire.DeviceEnrollmentIntentOpeningV1{
		Schema: 1, ClusterID: "cluster", InviteID: "invite", DeviceEnrollmentIntent: intent,
		DeviceEnrollmentIntentHash: intentHash, HidingNonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
}
