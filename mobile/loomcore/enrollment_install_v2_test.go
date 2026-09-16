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
	"fmt"
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

func TestPrepareAndroidInstalledConfigBindsExactCertifiedRef(t *testing.T) {
	config, err := wire.MarshalCanonical(bundleWire{Owner: "demo-android", Files: map[string]string{
		"sing-box/config.json": `{"log":{"level":"warn"}}`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	contentHash, _ := wire.DeviceConfigArtifactContentHash(config)
	ref := wire.DeviceConfigArtifactRefV1{
		ArtifactID: "android-runtime", Generation: 1, Platform: "android",
		MediaType: "application/vnd.loom.config+json", RenderContractID: "android-runtime-v1",
		SizeBytes: int64(len(config)), ContentHash: contentHash,
	}
	refJSON, _ := wire.MarshalCanonical(ref)
	installedJSON, err := PrepareAndroidInstalledConfigV2(refJSON, config)
	if err != nil {
		t.Fatal(err)
	}
	var installed androidInstalledConfigV1
	if err := decodeExactAndroidV2(installedJSON, 1<<20, &installed, "installed config"); err != nil {
		t.Fatal(err)
	}
	if installed.ContentHash != ref.ContentHash || !bytes.Equal(installed.Config, config) {
		t.Fatalf("installed config 未绑定 exact ref/bytes: %+v", installed)
	}
	if _, err := PrepareAndroidInstalledConfigV2(refJSON,
		append(append([]byte(nil), config...), '\n')); err == nil {
		t.Fatal("非 canonical config 被接受")
	}
	mutated := ref
	mutated.ContentHash = wire.HashRaw("android-config-test", []byte("other"))
	mutatedJSON, _ := wire.MarshalCanonical(mutated)
	if _, err := PrepareAndroidInstalledConfigV2(mutatedJSON, config); err == nil {
		t.Fatal("content hash 不匹配的 config 被接受")
	}
}

func TestAndroidCompletionConfigPlanIsPinnedAndBounded(t *testing.T) {
	config := []byte(`{"owner":"demo-android"}`)
	contentHash, _ := wire.DeviceConfigArtifactContentHash(config)
	ref := wire.DeviceConfigArtifactRefV1{
		ArtifactID: "android-runtime", Generation: 1, Platform: "android",
		MediaType: "application/vnd.loom.config+json", RenderContractID: "android-runtime-v1",
		SizeBytes: int64(len(config)), ContentHash: contentHash,
	}
	_, envelope := androidV2EnvelopeFixtureForArtifacts(t, "demo-android",
		wire.HashRaw("android-config-plan-test", []byte("identity")), nil,
		[]wire.DeviceConfigArtifactRefV1{ref})
	hash := func(value string) string { return wire.HashRaw("android-config-plan-test", []byte(value)) }
	mirrors := []wire.DistributionMirrorRefV1{
		{Schema: 1, EndpointID: "mirror-1", DistributionEndpointSetHash: hash("set-1"), ListenerGeneration: 1,
			BaseURL: "https://mirror-a.example.test:443/distribution/sha256/", ServerName: "mirror-a.example.test",
			WebPKIProfileRef: "webpki-v1", SPKIPins: []string{hash("pin-1")}, HintRank: 0},
		{Schema: 1, EndpointID: "mirror-2", DistributionEndpointSetHash: hash("set-2"), ListenerGeneration: 1,
			BaseURL: "https://mirror-b.example.test:443/distribution/sha256/", ServerName: "mirror-b.example.test",
			WebPKIProfileRef: "webpki-v1", SPKIPins: []string{hash("pin-2")}, HintRank: 1},
	}
	planJSON, err := prepareAndroidCompletionConfigFetchPlan(envelope, mirrors)
	if err != nil {
		t.Fatal(err)
	}
	var plan androidCompletionConfigFetchPlanV1
	if err := decodeExactAndroidV2(planJSON, 4<<20, &plan, "config fetch plan"); err != nil {
		t.Fatal(err)
	}
	if len(plan.Refs) != 1 || !wire.EqualCanonical(plan.Refs[0], ref) || len(plan.Mirrors) != 2 {
		t.Fatalf("config plan 丢失 exact refs/mirrors: %+v", plan)
	}
	nonAndroid := envelope
	nonAndroid.Payload.Active.ConfigArtifactRefs[0].Platform = "linux-server"
	if _, err := prepareAndroidCompletionConfigFetchPlan(nonAndroid, mirrors); err == nil {
		t.Fatal("非 Android config ref 被投影")
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
	deviceID := preflight.DeviceEnrollmentIntentOpening.DeviceEnrollmentIntent.DeviceID
	var secretRefs []wire.SecretArtifactRefV2
	var installedSecrets []androidInstalledSecretV1
	for _, fixture := range androidV2RuntimeFixtureSecrets(deviceID) {
		secretRef, secretEnvelope, secret := androidSealedSecretFixtureFor(t, deviceID,
			fixture.id, "data_plane_credential", fixture.value)
		secretRefJSON, _ := wire.MarshalCanonical(secretRef)
		secretEnvelopeJSON, _ := wire.MarshalCanonical(secretEnvelope)
		installedSecretJSON, err := PrepareAndroidInstalledSecretV2(
			secretRefJSON, secretEnvelopeJSON, secret)
		if err != nil {
			t.Fatal(err)
		}
		var installedSecret androidInstalledSecretV1
		if err := decodeExactAndroidV2(installedSecretJSON, 1<<20, &installedSecret,
			"installed runtime secret"); err != nil {
			t.Fatal(err)
		}
		secretRefs = append(secretRefs, secretRef)
		installedSecrets = append(installedSecrets, installedSecret)
	}
	config := androidV2RuntimeBundleFixture(t, deviceID)
	configHash, _ := wire.DeviceConfigArtifactContentHash(config)
	configRef := wire.DeviceConfigArtifactRefV1{
		ArtifactID: "android-runtime", Generation: 1, Platform: "android",
		MediaType: "application/vnd.loom.config+json", RenderContractID: "android-runtime-v1",
		SizeBytes: int64(len(config)), ContentHash: configHash,
	}
	configRefJSON, _ := wire.MarshalCanonical(configRef)
	installedConfigJSON, err := PrepareAndroidInstalledConfigV2(configRefJSON, config)
	if err != nil {
		t.Fatal(err)
	}
	var installedConfig androidInstalledConfigV1
	if err := decodeExactAndroidV2(installedConfigJSON, 1<<20, &installedConfig,
		"installed config"); err != nil {
		t.Fatal(err)
	}
	set, envelope := androidV2EnvelopeFixtureForArtifacts(t,
		deviceID, identityHash, secretRefs,
		[]wire.DeviceConfigArtifactRefV1{configRef})
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
		InitialDeviceView:    envelope.Payload, SecretArtifactRefs: secretRefs,
	}
	artifactHash, err := wire.EnrollmentResultArtifactHash(&artifact)
	if err != nil {
		t.Fatal(err)
	}
	claimCoreHash, _ := wire.EnrollmentClaimCoreHash(&core)
	certificateHash, _ := wire.DeviceCertificateHash(certificateDER)
	installation := &androidEnrollmentInstallationV1{
		ClaimCore: core, ClaimCoreHash: claimCoreHash,
		TransactionStateHash: wire.HashRaw("android-install-test", []byte("transaction")),
		ResultArtifactHash:   artifactHash, ResultArtifact: artifact,
		androidDeviceInstallationV1: androidDeviceInstallationV1{
			Schema: 1, IdentityKeyHash: identityHash, WrappingKeyHash: wrappingHash,
			DeviceCertificateHash: certificateHash, Credentials: installedSecrets,
			Configs: []androidInstalledConfigV1{installedConfig},
		},
	}
	floors, err := wire.VerifyDeviceViewEnvelope(&envelope, &set)
	if err != nil {
		t.Fatal(err)
	}
	stateJSON, err := marshalAndroidV2DeviceState(androidV2DeviceState{
		Schema: 1, Floors: floors, Envelope: envelope, ControlSet: &set, Enrollment: installation,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAndroidV2DeviceState(stateJSON); err != nil {
		t.Fatal(err)
	}
	runtimeJSON, err := PrepareAndroidV2Runtime(stateJSON)
	if err != nil {
		t.Fatal(err)
	}
	var runtime preparedAndroidV2Runtime
	if err := decodeExactAndroidV2(runtimeJSON, 4<<20, &runtime, "v2 runtime"); err != nil {
		t.Fatal(err)
	}
	if runtime.DeviceID != deviceID || runtime.HeadHash != floors.HeadHash ||
		!strings.Contains(runtime.SingBoxConfig, `"type": "wireguard"`) || runtime.RoutePlan == "" ||
		strings.Contains(runtime.SingBoxConfig, "${secret:") {
		t.Fatalf("v2 runtime 未从原子状态 hydrate: %+v", runtime)
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
		Schema: 1, Floors: floors, Envelope: envelope, ControlSet: &set, Enrollment: installation,
	})
	if err := ValidateAndroidV2DeviceState(corrupted); err == nil {
		t.Fatal("certificate hash 被替换的 durable installation 仍通过回读")
	}
	installation.DeviceCertificateHash = certificateHash
	installation.Configs[0].Config = json.RawMessage(`{"owner":"other"}`)
	corrupted, _ = wire.MarshalCanonical(androidV2DeviceState{
		Schema: 1, Floors: floors, Envelope: envelope, ControlSet: &set, Enrollment: installation,
	})
	if err := ValidateAndroidV2DeviceState(corrupted); err == nil {
		t.Fatal("config bytes 被替换的 durable installation 仍通过回读")
	}
}

func androidSealedSecretFixture(t *testing.T) (wire.SecretArtifactRefV2,
	wire.SealedSecretEnvelopeV1, []byte,
) {
	return androidSealedSecretFixtureFor(t, "demo-android", "credential-1",
		"device_credential", []byte("demo-android-secret"))
}

func androidSealedSecretFixtureFor(t *testing.T, deviceID, secretID, purpose string, secret []byte) (
	wire.SecretArtifactRefV2, wire.SealedSecretEnvelopeV1, []byte,
) {
	return androidSealedSecretFixtureForGeneration(t, deviceID, secretID, purpose, 1, secret)
}

func androidSealedSecretFixtureForGeneration(t *testing.T, deviceID, secretID, purpose string,
	generation int64, secret []byte,
) (wire.SecretArtifactRefV2, wire.SealedSecretEnvelopeV1, []byte) {
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
		RecipientID: deviceID, RecipientKeyGeneration: 1, RecipientKeyID: keyID,
		RecipientKeyProfile: "p256-keystore-ecdh-v1", RecipientPublicKey: key,
	}
	policy := wire.P256SealingPolicyV1()
	owner := wire.SecretArtifactOwnerV1{Kind: "device",
		Device: &wire.SecretArtifactDeviceOwnerV1{DeviceID: recipient.RecipientID}}
	contextValue, err := wire.NewSealedSecretContext("demo-cluster", "proposal-1", secretID,
		purpose, owner, generation, &policy, []wire.SealedBlobRecipientKeyRefV1{recipient})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := wire.SealSecret(rand.Reader, contextValue, &policy,
		[]wire.SealedBlobRecipientKeyRefV1{recipient}, secret)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := wire.SealedSecretEnvelopeHash(&envelope)
	policyHash, _ := wire.SealingPolicyHash(&policy)
	ref := wire.SecretArtifactRefV2{
		Schema: 2, ClusterID: contextValue.ClusterID, ProposalID: contextValue.ProposalID,
		SecretID: contextValue.SecretID, Purpose: contextValue.Purpose, Owner: owner, Generation: generation,
		ImmutableRef: fmt.Sprintf("blob:sha256:%s-%d", secretID, generation), BackendKind: "sealed_blob",
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
