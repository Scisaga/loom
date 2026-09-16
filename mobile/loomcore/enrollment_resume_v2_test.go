package loomcore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"testing"

	"loom/internal/wire"
)

func TestAndroidV2ResumeCarriersAreExact(t *testing.T) {
	descriptorJSON, err := wire.MarshalCanonical(wire.EnrollmentResumeDescriptorV1{Schema: 1})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAndroidV2ResumeFile(descriptorJSON)
	if err != nil || !bytes.Equal(decoded, descriptorJSON) {
		t.Fatalf(".loom-resume 没有保留 exact descriptor: %v", err)
	}
	uri := androidV2ResumeURIPrefix + base64.RawURLEncoding.EncodeToString(descriptorJSON)
	decoded, err = DecodeAndroidV2ResumeURI(uri)
	if err != nil || !bytes.Equal(decoded, descriptorJSON) {
		t.Fatalf("resume QR 没有保留 exact descriptor: %v", err)
	}
	for name, candidate := range map[string][]byte{
		"前导空白": append([]byte{' '}, descriptorJSON...),
		"尾随换行": append(append([]byte(nil), descriptorJSON...), '\n'),
		"未知字段": []byte(`{"schema":1,"unknown":true}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeAndroidV2ResumeFile(candidate); err == nil {
				t.Fatal("非 exact resume carrier 被接受")
			}
		})
	}
	if _, err := DecodeAndroidV2ResumeURI(uri + "\n"); err == nil {
		t.Fatal("含空白的 resume QR 被接受")
	}
}

func TestAndroidResumePreflightRequiresOriginalKeystoreSignature(t *testing.T) {
	initial, response := androidEnrollmentCoreFixture(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	identityHash, _ := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, spki)
	openingHash, _ := wire.IntentOpeningHash(&response.DeviceEnrollmentIntentOpening)
	intentHash, _ := wire.EnrollmentIntentHash(&response.DeviceEnrollmentIntentOpening.DeviceEnrollmentIntent)
	inputs := androidEnrollmentResumeInputsV1{bundle: initial.bundle, recordHash: initial.recordHash,
		core: wire.EnrollmentClaimCoreV2{ClusterID: initial.descriptor.ClusterID, InviteID: initial.descriptor.InviteID,
			DeviceIdentityPublicKey: base64.RawURLEncoding.EncodeToString(spki), DeviceEnrollmentIntentOpeningHash: openingHash,
			AcceptedDeviceEnrollmentIntentHash: intentHash}, expected: wire.EnrollmentResumeExpectedV1{IdentityKeyHash: identityHash},
		descriptor: wire.EnrollmentResumeDescriptorV1{ResumeTunnelCapability: wire.BootstrapTunnelCapabilityV1{
			CapabilityID: wire.HashRaw("demo-preflight", []byte("resume-capability"))}}}
	request := androidEnrollmentResumePreflightRequest(inputs)
	if _, err := wire.EnrollmentPreflightAuthorizationMessage(&request); err != nil {
		t.Fatal(err)
	}
	request, err := wire.AuthorizeResumeEnrollmentPreflight(request, key)
	if err != nil {
		t.Fatal(err)
	}
	response.RequestHash, err = wire.EnrollmentIntentPreflightRequestHash(&request)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := wire.MarshalCanonical(response)
	if _, err := verifyAndroidEnrollmentResumePreflight(inputs, request, raw); err != nil {
		t.Fatal(err)
	}
	request.Authorization.ProofSignature = ""
	if _, err := verifyAndroidEnrollmentResumePreflight(inputs, request, raw); err == nil {
		t.Fatal("Android resume 接受无 Keystore 证明的预取")
	}
}

func TestAndroidV2PendingProgressOnlyAdvancesMonotonically(t *testing.T) {
	core := androidPendingProgressCoreFixture(t)
	coreJSON, _ := wire.MarshalCanonical(core)
	coreHash, _ := wire.EnrollmentClaimCoreHash(&core)
	identityHash, wrappingHash, csrHash, err := wire.EnrollmentClaimBinaryHashes(&core)
	if err != nil {
		t.Fatal(err)
	}
	hash := func(value string) string { return wire.HashRaw("android-pending-progress-test", []byte(value)) }
	reserved := wire.EnrollmentResumeExpectedV1{
		ClusterID: core.ClusterID, InviteID: core.InviteID, RequestID: core.RequestID,
		ClaimCoreHash: coreHash, ClaimOperationHash: hash("operation"), AdmissionQCHash: hash("admission"),
		CSRHash: csrHash, IdentityKeyHash: identityHash, WrappingKeyHash: wrappingHash,
		EnrollmentTransactionStateHash: hash("reserved"), RetryNotAfter: "2026-09-12T01:00:00Z",
	}
	reservedJSON, _ := wire.MarshalCanonical(reserved)
	if err := ValidateAndroidV2PendingProgress(coreJSON, "reserved", reservedJSON); err != nil {
		t.Fatal(err)
	}
	if err := AdvanceAndroidV2PendingProgress(coreJSON, "reserved", reservedJSON,
		"reserved", reservedJSON); err != nil {
		t.Fatalf("exact replay 被拒绝: %v", err)
	}
	issued := reserved
	issued.EnrollmentTransactionStateHash = hash("issued")
	issuedJSON, _ := wire.MarshalCanonical(issued)
	if err := AdvanceAndroidV2PendingProgress(coreJSON, "reserved", reservedJSON,
		"issued_provisional", issuedJSON); err != nil {
		t.Fatalf("reserved→issued_provisional 被拒绝: %v", err)
	}
	completed := issued
	completed.EnrollmentTransactionStateHash = hash("completed")
	completedJSON, _ := wire.MarshalCanonical(completed)
	if err := AdvanceAndroidV2PendingProgress(coreJSON, "reserved", reservedJSON,
		"completed", completedJSON); err != nil {
		t.Fatalf("reserved→completed 被拒绝: %v", err)
	}
	if err := AdvanceAndroidV2PendingProgress(coreJSON, "issued_provisional", issuedJSON,
		"completed", completedJSON); err != nil {
		t.Fatalf("issued_provisional→completed 被拒绝: %v", err)
	}
	if err := AdvanceAndroidV2PendingProgress(coreJSON, "completed", completedJSON,
		"issued_provisional", issuedJSON); err == nil {
		t.Fatal("completed progress 回退被接受")
	}
	if err := AdvanceAndroidV2PendingProgress(coreJSON, "issued_provisional", issuedJSON,
		"reserved", reservedJSON); err == nil {
		t.Fatal("pending progress 回退被接受")
	}
	mutated := issued
	mutated.ClaimOperationHash = hash("other-operation")
	mutatedJSON, _ := wire.MarshalCanonical(mutated)
	if err := AdvanceAndroidV2PendingProgress(coreJSON, "reserved", reservedJSON,
		"issued_provisional", mutatedJSON); err == nil {
		t.Fatal("stable operation binding 改写被接受")
	}
}

func androidPendingProgressCoreFixture(t *testing.T) wire.EnrollmentClaimCoreV2 {
	t.Helper()
	inputs, preflight := androidEnrollmentCoreFixture(t)
	identity, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identitySPKI, _ := x509.MarshalPKIXPublicKey(&identity.PublicKey)
	requestID := "android-request-resume-1"
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: requestID}}, identity)
	if err != nil {
		t.Fatal(err)
	}
	wrapping, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrappingSPKI, _ := x509.MarshalPKIXPublicKey(&wrapping.PublicKey)
	core, err := buildAndroidEnrollmentClaimCoreV2(inputs, preflight, requestID,
		identitySPKI, csr, wrappingSPKI, "p256-keystore-ecdh-v1", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return core
}
