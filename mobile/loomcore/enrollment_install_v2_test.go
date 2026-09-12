package loomcore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestPrepareAndroidInstalledSecretBindsExactReleasedEnvelope(t *testing.T) {
	ref, envelope, secret := androidSealedSecretFixture(t)
	refJSON, _ := wire.MarshalCanonical(ref)
	envelopeJSON, _ := wire.MarshalCanonical(envelope)
	installedJSON, err := PrepareAndroidInstalledSecretV2(refJSON, envelopeJSON, secret)
	if err != nil {
		t.Fatal(err)
	}
	var installed androidInstalledSecretV1
	if err := decodeExactAndroidV2(installedJSON, 1<<20, &installed, "installed secret"); err != nil {
		t.Fatal(err)
	}
	if installed.SecretID != ref.SecretID || installed.Purpose != ref.Purpose ||
		installed.SecretBytes != base64.RawURLEncoding.EncodeToString(secret) ||
		installed.SecretDigest != wire.HashRaw(androidInstalledSecretDomainV1, secret) {
		t.Fatalf("installed secret 未绑定 exact ref/plaintext: %+v", installed)
	}
	mutated := envelope
	mutated.CiphertextAndTag = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
	mutatedJSON, _ := wire.MarshalCanonical(mutated)
	if _, err := PrepareAndroidInstalledSecretV2(refJSON, mutatedJSON, secret); err == nil {
		t.Fatal("ciphertext 被替换的 released envelope 仍生成 installed credential")
	}
}

func TestAndroidReleasedArtifactFetchRequiresVerifiedSessionResultAndExactPath(t *testing.T) {
	ref, envelope, _ := androidSealedSecretFixture(t)
	envelopeJSON, _ := wire.MarshalCanonical(envelope)
	digest, _ := wire.ParseHash(ref.SealedBlob.CiphertextDigest)
	wantPath := "/v2/enrollment/artifacts/sha256/" + strings.TrimPrefix(ref.SealedBlob.CiphertextDigest, "sha256:")
	if len(digest) != 32 {
		t.Fatal("fixture ciphertext digest 无效")
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.URL.Path != wantPath ||
			request.Header.Get("Accept") != "application/json" || request.Header.Get("Content-Type") != "" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(envelopeJSON)
	}))
	defer server.Close()
	now := time.Now().UTC()
	rootContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &AndroidV2BootstrapSession{
		client: server.Client(), baseURL: server.URL, context: rootContext, cancel: cancel,
		dialer: &androidBootstrapDialer{notBefore: now.Add(-time.Minute), expiresAt: now.Add(time.Minute)},
	}
	if _, err := session.FetchReleasedArtifacts(now.Format(time.RFC3339)); err == nil || requests != 0 {
		t.Fatalf("未验证 completed result 触发了 artifact fetch: requests=%d err=%v", requests, err)
	}
	result := wire.EnrollmentClaimResultV2{Schema: 2, Status: "completed",
		TransactionStateHash: wire.HashRaw("android-fetch-test", []byte("transaction")),
		ResultArtifact:       &wire.EnrollmentResultArtifactV1{SecretArtifactRefs: []wire.SecretArtifactRefV2{ref}}}
	resultJSON, _ := wire.MarshalCanonical(result)
	session.completedResult = resultJSON
	fetched, err := session.FetchReleasedArtifacts(now.Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	var bundle androidReleasedArtifactsV1
	if err := decodeExactAndroidV2(fetched, 8<<20, &bundle, "released artifacts"); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || bundle.Schema != 1 || len(bundle.Envelopes) != 1 ||
		!wire.EqualCanonical(bundle.Envelopes[0], envelope) {
		t.Fatalf("released artifact fetch/result 无效: requests=%d bundle=%+v", requests, bundle)
	}
}

func TestAndroidEnrollmentInstallationIsSingleReplayableState(t *testing.T) {
	inputs, preflight := androidEnrollmentCoreFixture(t)
	identity, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identitySPKI, _ := x509.MarshalPKIXPublicKey(&identity.PublicKey)
	wrapping, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrappingSPKI, _ := x509.MarshalPKIXPublicKey(&wrapping.PublicKey)
	requestID := "android-install-request-1"
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: requestID}}, identity)
	if err != nil {
		t.Fatal(err)
	}
	core, err := buildAndroidEnrollmentClaimCoreV2(inputs, preflight, requestID,
		identitySPKI, csr, wrappingSPKI, "p256-keystore-ecdh-v1", bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	identityHash, wrappingHash, _, err := wire.EnrollmentClaimBinaryHashes(&core)
	if err != nil {
		t.Fatal(err)
	}
	set, envelope := androidV2EnvelopeFixtureFor(t,
		preflight.DeviceEnrollmentIntentOpening.DeviceEnrollmentIntent.DeviceID,
		identityHash, []wire.SecretArtifactRefV2{})
	certificateTemplate := &x509.Certificate{SerialNumber: big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	certificateDER, err := x509.CreateCertificate(rand.Reader, certificateTemplate,
		certificateTemplate, &identity.PublicKey, identity)
	if err != nil {
		t.Fatal(err)
	}
	artifact := wire.EnrollmentResultArtifactV1{
		Schema: 1, ClusterID: envelope.Payload.ClusterID,
		InviteID: core.InviteID, RequestID: core.RequestID,
		DeviceCertificateDER: base64.RawURLEncoding.EncodeToString(certificateDER),
		InitialDeviceView:    envelope.Payload, SecretArtifactRefs: []wire.SecretArtifactRefV2{},
	}
	artifactHash, err := wire.EnrollmentResultArtifactHash(&artifact)
	if err != nil {
		t.Fatal(err)
	}
	claimCoreHash, _ := wire.EnrollmentClaimCoreHash(&core)
	certificateHash, _ := wire.DeviceCertificateHash(certificateDER)
	installation := &androidEnrollmentInstallationV1{
		Schema: 1, ClaimCore: core, ClaimCoreHash: claimCoreHash,
		IdentityKeyHash: identityHash, WrappingKeyHash: wrappingHash,
		TransactionStateHash: wire.HashRaw("android-install-test", []byte("transaction")),
		ResultArtifactHash:   artifactHash, DeviceCertificateHash: certificateHash,
		ResultArtifact: artifact, Credentials: []androidInstalledSecretV1{},
	}
	floors, err := wire.VerifyDeviceViewEnvelope(&envelope, &set)
	if err != nil {
		t.Fatal(err)
	}
	stateJSON, err := marshalAndroidV2DeviceState(androidV2DeviceState{
		Schema: 1, Floors: floors, Envelope: envelope, Enrollment: installation,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAndroidV2DeviceState(stateJSON); err != nil {
		t.Fatal(err)
	}
	envelopeJSON, _ := wire.MarshalCanonical(envelope)
	setJSON, _ := wire.MarshalCanonical(set)
	replayed, err := PrepareV2DeviceState(envelopeJSON, setJSON, envelope.Payload.DeviceID,
		identityHash, stateJSON)
	if err != nil || !bytes.Equal(replayed, stateJSON) {
		t.Fatalf("Device view replay 丢失 enrollment installation: equal=%v err=%v", bytes.Equal(replayed, stateJSON), err)
	}
	result := wire.EnrollmentClaimResultV2{
		Schema: 2, Status: "completed", TransactionStateHash: installation.TransactionStateHash,
		ResultArtifactHash: artifactHash, ResultArtifact: &artifact, CompletionReceipt: json.RawMessage(`{}`),
	}
	coreJSON, _ := wire.MarshalCanonical(core)
	resultJSON, _ := wire.MarshalCanonical(result)
	if err := ValidateAndroidV2InstalledPending(stateJSON, coreJSON, resultJSON); err != nil {
		t.Fatal(err)
	}
	otherCore := core
	otherCore.RequestID = "android-install-request-other"
	otherCoreJSON, _ := wire.MarshalCanonical(otherCore)
	if err := ValidateAndroidV2InstalledPending(stateJSON, otherCoreJSON, resultJSON); err == nil {
		t.Fatal("durable installation 清理了不同 stable core 的 pending")
	}
	installation.DeviceCertificateHash = wire.HashRaw("android-install-test", []byte("other-cert"))
	corrupted, _ := wire.MarshalCanonical(androidV2DeviceState{
		Schema: 1, Floors: floors, Envelope: envelope, Enrollment: installation,
	})
	if err := ValidateAndroidV2DeviceState(corrupted); err == nil {
		t.Fatal("certificate hash 被替换的 durable installation 仍通过回读")
	}
}

func androidSealedSecretFixture(t *testing.T) (wire.SecretArtifactRefV2,
	wire.SealedSecretEnvelopeV1, []byte,
) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&private.PublicKey)
	keyID, _ := wire.AuthorityProofKeyID(spki)
	key := wire.AuthorityProofKeyV1{Algorithm: "ecdsa-p256-sha256",
		PublicKeySPKIDER: base64.RawURLEncoding.EncodeToString(spki), KeyID: keyID}
	recipient := wire.SealedBlobRecipientKeyRefV1{
		RecipientID: "demo-android", RecipientKeyGeneration: 1, RecipientKeyID: keyID,
		RecipientKeyProfile: "p256-keystore-ecdh-v1", RecipientPublicKey: key,
	}
	policy := wire.P256SealingPolicyV1()
	owner := wire.SecretArtifactOwnerV1{Kind: "device",
		Device: &wire.SecretArtifactDeviceOwnerV1{DeviceID: recipient.RecipientID}}
	contextValue, err := wire.NewSealedSecretContext("demo-cluster", "proposal-1", "credential-1",
		"device_credential", owner, 1, &policy, []wire.SealedBlobRecipientKeyRefV1{recipient})
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("demo-android-secret")
	envelope, err := wire.SealSecret(rand.Reader, contextValue, &policy,
		[]wire.SealedBlobRecipientKeyRefV1{recipient}, secret)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := wire.SealedSecretEnvelopeHash(&envelope)
	policyHash, _ := wire.SealingPolicyHash(&policy)
	ref := wire.SecretArtifactRefV2{
		Schema: 2, ClusterID: contextValue.ClusterID, ProposalID: contextValue.ProposalID,
		SecretID: contextValue.SecretID, Purpose: contextValue.Purpose, Owner: owner, Generation: 1,
		ImmutableRef: "blob:sha256:demo-android-credential-1", BackendKind: "sealed_blob",
		SealedBlob: &wire.SealedBlobRefV1{CiphertextDigest: digest, SealingPolicy: policy,
			SealingPolicyHash: policyHash, RecipientKeyVersions: []wire.SealedBlobRecipientKeyRefV1{recipient}},
		AvailabilityPolicyHash:   wire.HashRaw("android-secret-test", []byte("availability")),
		AvailabilityReceiptsRoot: wire.HashRaw("android-secret-test", []byte("receipts")),
	}
	if err := wire.VerifySealedSecretBinding(&ref, &envelope); err != nil {
		t.Fatal(err)
	}
	return ref, envelope, secret
}
