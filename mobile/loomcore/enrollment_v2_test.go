package loomcore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"strings"
	"testing"

	"loom/internal/wire"
)

func TestBuildAndroidEnrollmentClaimCoreIsStableAndKeystoreBound(t *testing.T) {
	inputs, preflight := androidEnrollmentCoreFixture(t)
	requestID := "android-request-1"
	identity, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	identitySPKI, _ := x509.MarshalPKIXPublicKey(&identity.PublicKey)
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: requestID}}, identity)
	if err != nil {
		t.Fatal(err)
	}
	wrapping, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrappingSPKI, _ := x509.MarshalPKIXPublicKey(&wrapping.PublicKey)
	nonce := bytes.Repeat([]byte{0x41}, 32)

	first, err := buildAndroidEnrollmentClaimCoreV2(inputs, preflight, requestID,
		identitySPKI, csr, wrappingSPKI, "p256-keystore-ecdh-v1", nonce)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildAndroidEnrollmentClaimCoreV2(inputs, preflight, requestID,
		identitySPKI, csr, wrappingSPKI, "p256-keystore-ecdh-v1", nonce)
	if err != nil || !wire.EqualCanonical(first, second) {
		t.Fatalf("stable core 重建不一致: %v", err)
	}
	if first.ClientPlatform != "android" ||
		first.DeviceIdentityKeyProfile != "p256-android-keystore-sha256-v1" {
		t.Fatalf("Android Keystore profile 未固定: %+v", first)
	}
	if _, err := wire.EnrollmentClaimCoreHash(&first); err != nil {
		t.Fatal(err)
	}

	if _, err := buildAndroidEnrollmentClaimCoreV2(inputs, preflight, requestID,
		identitySPKI, csr, wrappingSPKI, "rsa2048-keystore-decrypt-v1", nonce); err == nil {
		t.Fatal("未经 intent 授权的 wrapping profile 被接受")
	}
	wrongCSR, _ := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "other-request"}}, identity)
	if _, err := buildAndroidEnrollmentClaimCoreV2(inputs, preflight, requestID,
		identitySPKI, wrongCSR, wrappingSPKI, "p256-keystore-ecdh-v1", nonce); err == nil {
		t.Fatal("CSR/request_id 分叉被接受")
	}
	if _, err := buildAndroidEnrollmentClaimCoreV2(inputs, preflight, requestID,
		identitySPKI, csr, wrappingSPKI, "p256-keystore-ecdh-v1", nonce[:31]); err == nil {
		t.Fatal("31-byte client nonce 被接受")
	}
}

func TestAndroidEnrollmentPublicEntryPointsRejectUnverifiedInputsBeforeKeys(t *testing.T) {
	descriptor := []byte(`{"schema":2}`)
	proof := []byte(`{"schema":2}`)
	if _, err := PrepareAndroidEnrollmentV2Preflight(descriptor, proof, "2026-09-11T00:00:00Z"); err == nil {
		t.Fatal("未验证 Invite proof 产生了 preflight")
	}
	if _, err := VerifyAndroidEnrollmentV2Preflight(descriptor, proof, []byte(`{"schema":1}`),
		"2026-09-11T00:00:00Z"); err == nil {
		t.Fatal("未验证 Invite proof 放行了 opening")
	}
}

func TestPrepareAndroidV2MirrorFetchPlanContainsOnlyPublicPinnedCoordinates(t *testing.T) {
	hash := func(value string) string { return wire.HashRaw("android-mirror-plan-test", []byte(value)) }
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tokenCommitment, _ := wire.TokenCommitment("demo-cluster", "invite-android-1", token)
	service := wire.PrivateEnrollmentServiceRefV1{
		Schema: 1, ServiceID: "enrollment-service-1", OverlayIP: "10.30.0.1", TCPPort: 7444,
		InternalCAProfileRef: "internal-ca-1", ServerIdentitySPKIPins: []string{hash("service-pin")},
		ServiceGeneration: 1,
	}
	serviceHash, _ := wire.PrivateEnrollmentServiceRefHash(&service)
	body := wire.BootstrapTunnelCapabilityBodyV1{
		Schema: 1, ClusterID: "demo-cluster", InviteID: "invite-android-1",
		CommittedInviteRecordHash: hash("record"), InviteIssuancePolicyHash: hash("policy"),
		BootstrapIssuerAuthorizationHash: hash("issuer"), BootstrapIssuerRegistryRoot: hash("issuer-root"),
		EnrollmentServiceRefHash: serviceHash, Mode: "initial_claim",
		IssuedAt: "2026-09-11T00:00:00Z", NotBefore: "2026-09-11T00:00:00Z",
		ExpiresAt: "2026-09-11T00:15:00Z", AllowedIngressSetHash: hash("ingress"),
		AllowedServiceID: service.ServiceID, AllowedDestinationIP: service.OverlayIP,
		AllowedDestinationPrefixLength: 32, AllowedDestinationPort: service.TCPPort,
		AllowedInsideTransport: "tcp", MaximumConnectionAttempts: 3, MaximumConcurrentSessions: 1,
		MaximumSessionSeconds: 180, MaximumTotalBytes: 8 << 20, IssuerEpoch: 1, IssuerKeyID: "issuer-key-1",
	}
	capabilityID, err := wire.CapabilityID(&body)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := wire.InviteBootstrapDescriptorV2{
		Schema: 2, ClusterID: body.ClusterID, InviteID: body.InviteID, ExpiresAt: body.ExpiresAt,
		Token: token, TokenCommitment: tokenCommitment,
		BootstrapTunnelCapability: wire.BootstrapTunnelCapabilityV1{Body: body, CapabilityID: capabilityID},
		BootstrapCatalogHash:      hash("catalog"), ProofBundleHash: hash("proof"), EnrollmentServiceRef: service,
		DistributionMirrors: []wire.DistributionMirrorRefV1{
			{Schema: 1, EndpointID: "mirror-1", DistributionEndpointSetHash: hash("set-1"), ListenerGeneration: 1,
				BaseURL: "https://mirror-a.example.test:443/distribution/sha256/", ServerName: "mirror-a.example.test",
				WebPKIProfileRef: "webpki-v1", SPKIPins: []string{hash("pin-1")}, HintRank: 0},
			{Schema: 1, EndpointID: "mirror-2", DistributionEndpointSetHash: hash("set-2"), ListenerGeneration: 1,
				BaseURL: "https://mirror-b.example.test:443/distribution/sha256/", ServerName: "mirror-b.example.test",
				WebPKIProfileRef: "webpki-v1", SPKIPins: []string{hash("pin-2")}, HintRank: 1},
		},
		TrustedCheckpointHash: hash("checkpoint"),
	}
	descriptorJSON, _ := wire.MarshalCanonical(descriptor)
	fileCarrier, err := DecodeAndroidV2InviteFile(descriptorJSON)
	if err != nil || !bytes.Equal(fileCarrier, descriptorJSON) {
		t.Fatalf(".loom-invite carrier 没有保留 exact descriptor: %v", err)
	}
	compactCarrier := []byte(`{"schema":2}`)
	uri := androidV2InviteURIPrefix + base64.RawURLEncoding.EncodeToString(compactCarrier)
	uriCarrier, err := DecodeAndroidV2InviteURI(uri)
	if err != nil || !bytes.Equal(uriCarrier, compactCarrier) {
		t.Fatalf("QR URI carrier 没有保留 exact descriptor: %v", err)
	}
	if _, err := DecodeAndroidV2InviteURI(uri + "\n"); err == nil {
		t.Fatal("含空白的 Invite URI 被接受")
	}
	if _, err := DecodeAndroidV2InviteFile(append(descriptorJSON, '\n')); err == nil {
		t.Fatal("含尾随字节的 .loom-invite 被接受")
	}
	plan, err := PrepareAndroidV2MirrorFetchPlan(descriptorJSON, "2026-09-11T00:05:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plan), token) || !strings.Contains(string(plan), descriptor.ProofBundleHash) ||
		!strings.Contains(string(plan), "mirror-a.example.test") {
		t.Fatalf("mirror plan 秘密隔离/坐标无效: %s", plan)
	}
	if _, err := PrepareAndroidV2MirrorFetchPlan(append([]byte{' '}, descriptorJSON...),
		"2026-09-11T00:05:00Z"); err == nil {
		t.Fatal("非 canonical descriptor 被接受")
	}
	if _, err := PrepareAndroidV2MirrorFetchPlan(descriptorJSON,
		"2026-09-11T00:16:00Z"); err == nil {
		t.Fatal("过期 Invite 仍触发 mirror fetch plan")
	}
}

func androidEnrollmentCoreFixture(t *testing.T) (androidEnrollmentInputsV2, wire.EnrollmentIntentPreflightResponseV1) {
	t.Helper()
	set, envelope := androidV2EnvelopeFixture(t)
	hash := func(value string) string { return wire.HashRaw("android-enrollment-core-test", []byte(value)) }
	intent := wire.DeviceEnrollmentIntentV1{
		Schema: 1, ClusterID: set.ClusterID, InviteID: "invite-android-1",
		DeviceID: "android-device-1", Platform: "android",
		DeviceCertificateProfileRef: wire.DeviceCertificateProfileRefV1{
			ProfileID: "android-device-certificate", Generation: 1,
			DeviceCertificateProfileIntentHash: hash("certificate-intent"),
			DeviceCertificateProfileStateHash:  hash("certificate-state"),
		},
		WrappingKeyProfiles: []string{"p256-keystore-ecdh-v1"},
		Membership:          wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"},
		Responsibilities:    wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}},
		Grants:              wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}},
	}
	intentHash, err := wire.EnrollmentIntentHash(&intent)
	if err != nil {
		t.Fatal(err)
	}
	opening := wire.DeviceEnrollmentIntentOpeningV1{
		Schema: 1, ClusterID: set.ClusterID, InviteID: intent.InviteID,
		DeviceEnrollmentIntent: intent, DeviceEnrollmentIntentHash: intentHash,
		HidingNonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	commitment, commitmentHash, err := wire.IntentCommitment(&opening)
	if err != nil {
		t.Fatal(err)
	}
	inputs := androidEnrollmentInputsV2{
		descriptor: wire.InviteBootstrapDescriptorV2{
			Schema: 2, ClusterID: set.ClusterID, InviteID: intent.InviteID,
			Token:                     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			BootstrapTunnelCapability: wire.BootstrapTunnelCapabilityV1{CapabilityID: hash("capability")},
		},
		bundle: wire.InviteProofBundleV2{
			CertifiedInviteRecord: wire.CertifiedInviteRecordV2{
				DeviceEnrollmentIntentCommitmentHash: commitmentHash,
			},
			DeviceEnrollmentIntentCommitment: commitment,
		},
		recordHash: hash("record"), head: envelope.SignedCurrent.Head, set: set,
	}
	request, err := androidEnrollmentPreflightRequestV2(inputs)
	if err != nil {
		t.Fatal(err)
	}
	requestHash, err := wire.EnrollmentIntentPreflightRequestHash(&request)
	if err != nil {
		t.Fatal(err)
	}
	return inputs, wire.EnrollmentIntentPreflightResponseV1{
		Schema: 1, ClusterID: set.ClusterID, InviteID: intent.InviteID,
		RequestHash: requestHash, DeviceEnrollmentIntentOpening: opening,
		DeviceEnrollmentIntentCommitment: commitment,
	}
}
