//go:build linux

package clientv2

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
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestPrepareLinuxEnrollmentInstallationUnsealsExactCredentials(t *testing.T) {
	attempt, inputs, _ := linuxEnrollmentAttemptFixture(t)
	if _, err := runLinuxEnrollmentAttempt(context.Background(), attempt, inputs); err != nil {
		t.Fatal(err)
	}
	identity, err := LoadEnrollmentIdentityForResume(attempt.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := readPendingClaim(attempt.PendingPath)
	if err != nil {
		t.Fatal(err)
	}
	result, envelope, secret := linuxCompletionResultFixture(t, identity, pending)
	mirrors := linuxCompletionTestMirrors()
	installation, err := prepareLinuxEnrollmentInstallation(identity, pending, &result,
		[]wire.SealedSecretEnvelopeV1{envelope}, []InstalledConfigV1{}, mirrors)
	if err != nil {
		t.Fatal(err)
	}
	if len(installation.Credentials) != 1 {
		t.Fatalf("未安装 exact credential: %#v", installation.Credentials)
	}
	got, err := base64.RawURLEncoding.DecodeString(installation.Credentials[0].SecretBytes)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("解封后的 credential 不匹配: got=%q err=%v", got, err)
	}
	viewEnvelope := wire.DeviceViewEnvelopeV2{Payload: result.ResultArtifact.InitialDeviceView,
		SecretArtifactRefs: []json.RawMessage{mustCanonicalRaw(t, result.ResultArtifact.SecretArtifactRefs[0])}}
	if err := validateEnrollmentInstallation(installation, &viewEnvelope); err != nil {
		t.Fatal(err)
	}
	tampered := envelope
	tampered.CiphertextAndTag = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	if _, err := prepareLinuxEnrollmentInstallation(identity, pending, &result,
		[]wire.SealedSecretEnvelopeV1{tampered}, []InstalledConfigV1{}, mirrors); err == nil {
		t.Fatal("接受了与 immutable ref 不匹配的 sealed credential")
	}
}

func linuxCompletionTestMirrors() []wire.DistributionMirrorRefV1 {
	hash := func(value string) string { return wire.HashRaw("linux-completion-mirror-test", []byte(value)) }
	return []wire.DistributionMirrorRefV1{
		{Schema: 1, EndpointID: "mirror-1", DistributionEndpointSetHash: hash("set-1"),
			ListenerGeneration: 1, BaseURL: "https://mirror-a.example.test:443/distribution/sha256/",
			ServerName: "mirror-a.example.test", WebPKIProfileRef: "webpki-v1",
			SPKIPins: []string{hash("pin-1")}, HintRank: 0},
		{Schema: 1, EndpointID: "mirror-2", DistributionEndpointSetHash: hash("set-2"),
			ListenerGeneration: 1, BaseURL: "https://mirror-b.example.test:443/distribution/sha256/",
			ServerName: "mirror-b.example.test", WebPKIProfileRef: "webpki-v1",
			SPKIPins: []string{hash("pin-2")}, HintRank: 1},
	}
}

func TestInitialInstallationIsOneDurableUnitAndSurvivesViewAdvance(t *testing.T) {
	set, key := clientControlSet(t)
	claimCore := validInstallClaimCore(t)
	identityHash, wrappingHash, _, err := wire.EnrollmentClaimBinaryHashes(&claimCore)
	if err != nil {
		t.Fatal(err)
	}
	envelope := clientEnvelopeWithIdentity(t, &set, key, identityHash)
	certificateDER := selfSignedEnrollmentCertificate(t, nil)
	artifact := wire.EnrollmentResultArtifactV1{
		Schema: 1, ClusterID: envelope.Payload.ClusterID, InviteID: "invite", RequestID: "request",
		DeviceCertificateDER: base64.RawURLEncoding.EncodeToString(certificateDER),
		InitialDeviceView:    envelope.Payload, SecretArtifactRefs: []wire.SecretArtifactRefV2{},
	}
	resultHash, err := wire.EnrollmentResultArtifactHash(&artifact)
	if err != nil {
		t.Fatal(err)
	}
	certificateHash, _ := wire.DeviceCertificateHash(certificateDER)
	installation := &EnrollmentInstallationV1{
		Schema: 1, ClaimCore: claimCore, IdentityKeyHash: identityHash,
		WrappingKeyHash: wrappingHash, TransactionStateHash: testInstallHash("transaction"),
		ResultArtifactHash: resultHash, DeviceCertificateHash: certificateHash,
		ResultArtifact: artifact, Credentials: []InstalledSecretV1{},
	}
	installation.ClaimCoreHash, _ = wire.EnrollmentClaimCoreHash(&installation.ClaimCore)
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "state.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	broken := *installation
	broken.ResultArtifactHash = testInstallHash("wrong")
	if _, err := store.acceptInitialInstallation(&envelope, &set, envelope.Payload.DeviceID,
		envelope.Payload.Active.IdentitySPKIHash, &broken); err == nil {
		t.Fatal("无效 installation 被部分提交")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("失败安装留下正式状态: %v", err)
	}
	wantFloors, err := store.acceptInitialInstallation(&envelope, &set, envelope.Payload.DeviceID,
		envelope.Payload.Active.IdentitySPKIHash, installation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.acceptInitialInstallation(&envelope, &set, envelope.Payload.DeviceID,
		envelope.Payload.Active.IdentitySPKIHash, installation); err != nil {
		t.Fatalf("exact installation replay 非幂等: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Enrollment(); got == nil || !wire.EqualCanonical(*got, *installation) ||
		!wire.EqualCanonical(reopened.Floors(), wantFloors) {
		t.Fatalf("重启后丢失原子 installation: got=%#v floors=%#v", got, reopened.Floors())
	}
	advanced := advanceClientEnvelope(t, envelope, &set, key)
	if _, err := reopened.Accept(&advanced, &set, envelope.Payload.DeviceID,
		envelope.Payload.Active.IdentitySPKIHash); err != nil {
		t.Fatal(err)
	}
	if got := reopened.Enrollment(); got == nil || !wire.EqualCanonical(*got, *installation) {
		t.Fatal("后续 DeviceView generation accept 擦除了 initial enrollment installation")
	}
	if got := reopened.Envelope(); got == nil || got.Payload.DeviceGeneration != 2 {
		t.Fatalf("合法后续 DeviceView 未替换 LKG: %#v", got)
	}
}

func TestProtectedTemporaryCleanupRejectsSymlink(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "carrier")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := removeProtectedEnrollmentTemporary(link, directory); err == nil {
		t.Fatal("cleanup 接受了 symlink")
	}
	if body, err := os.ReadFile(target); err != nil || string(body) != "keep" {
		t.Fatalf("cleanup 影响了 symlink target: body=%q err=%v", body, err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := removeProtectedEnrollmentTemporary(target, directory); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("0600 temporary 未删除: %v", err)
	}
}

func mustCanonicalRaw(t *testing.T, value any) []byte {
	t.Helper()
	body, err := wire.MarshalCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func linuxCompletionResultFixture(t *testing.T, identity *EnrollmentIdentityV1,
	pending *PendingClaimV2) (wire.EnrollmentClaimResultV2, wire.SealedSecretEnvelopeV1, []byte) {
	t.Helper()
	identityPrivate, wrappingPrivate, err := identity.keys()
	if err != nil {
		t.Fatal(err)
	}
	identityHash, _, _, err := wire.EnrollmentClaimBinaryHashes(&pending.ClaimCore)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "linux-device"
	owner := wire.SecretArtifactOwnerV1{Kind: "device",
		Device: &wire.SecretArtifactDeviceOwnerV1{DeviceID: deviceID}}
	spki, _ := x509.MarshalPKIXPublicKey(&wrappingPrivate.PublicKey)
	keyID, _ := wire.AuthorityProofKeyID(spki)
	recipient := wire.SealedBlobRecipientKeyRefV1{
		RecipientID: deviceID, RecipientKeyGeneration: 1, RecipientKeyID: keyID,
		RecipientKeyProfile: "p256-keystore-ecdh-v1",
		RecipientPublicKey: wire.AuthorityProofKeyV1{Algorithm: "ecdsa-p256-sha256",
			PublicKeySPKIDER: base64.RawURLEncoding.EncodeToString(spki), KeyID: keyID},
	}
	policy := wire.P256SealingPolicyV1()
	contextValue, err := wire.NewSealedSecretContext("cluster", "proposal", "credential", "device_credential",
		owner, 1, &policy, []wire.SealedBlobRecipientKeyRefV1{recipient})
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("private-device-credential")
	sealed, err := wire.SealSecret(rand.Reader, contextValue, &policy,
		[]wire.SealedBlobRecipientKeyRefV1{recipient}, secret)
	if err != nil {
		t.Fatal(err)
	}
	sealedHash, _ := wire.SealedSecretEnvelopeHash(&sealed)
	policyHash, _ := wire.SealingPolicyHash(&policy)
	ref := wire.SecretArtifactRefV2{
		Schema: 2, ClusterID: "cluster", ProposalID: "proposal", SecretID: "credential",
		Purpose: "device_credential", Owner: owner, Generation: 1, ImmutableRef: "blob:credential-1",
		BackendKind: "sealed_blob", SealedBlob: &wire.SealedBlobRefV1{
			CiphertextDigest: sealedHash, SealingPolicy: policy, SealingPolicyHash: policyHash,
			RecipientKeyVersions: []wire.SealedBlobRecipientKeyRefV1{recipient}},
		AvailabilityPolicyHash:   testInstallHash("availability-policy"),
		AvailabilityReceiptsRoot: testInstallHash("availability-receipts"),
	}
	refsRoot, err := wire.SecretArtifactRefsRoot([]wire.SecretArtifactRefV2{ref})
	if err != nil {
		t.Fatal(err)
	}
	membership := wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"}
	responsibilities := wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}}
	grants := wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}}
	membershipHash, _ := wire.HashObject("loom-enrollment-membership-v1", membership)
	responsibilitiesHash, _ := wire.HashObject("loom-enrollment-responsibilities-v1", responsibilities)
	grantsHash, _ := wire.HashObject("loom-enrollment-destination-grants-v1", grants)
	bundle := wire.DeviceEndpointBundleV1{Schema: 1, ClusterID: "cluster", DeviceID: deviceID,
		DeviceGeneration: 1, DataIngressSets: []wire.DeviceDataIngressBindingV1{}}
	bundleHash, _ := wire.DeviceEndpointBundleHash(&bundle)
	view := wire.DeviceViewPayloadV2{Schema: 2, ClusterID: "cluster", DeviceID: deviceID,
		DeviceGeneration: 1, State: "active", Active: &wire.DeviceActiveViewV1{
			IdentitySPKIHash: identityHash, Membership: membership, MembershipHash: membershipHash,
			Responsibilities: responsibilities, ResponsibilitiesHash: responsibilitiesHash,
			Grants: grants, GrantsHash: grantsHash, EndpointBundle: bundle, EndpointBundleHash: bundleHash,
			ConfigArtifactRefs: []wire.DeviceConfigArtifactRefV1{}, SecretArtifactRefsRoot: refsRoot,
		}}
	certificateDER := selfSignedEnrollmentCertificate(t, identityPrivate)
	artifact := wire.EnrollmentResultArtifactV1{Schema: 1, ClusterID: "cluster", InviteID: "invite",
		RequestID: "request", DeviceCertificateDER: base64.RawURLEncoding.EncodeToString(certificateDER),
		InitialDeviceView: view, SecretArtifactRefs: []wire.SecretArtifactRefV2{ref}}
	artifactHash, err := wire.EnrollmentResultArtifactHash(&artifact)
	if err != nil {
		t.Fatal(err)
	}
	return wire.EnrollmentClaimResultV2{Schema: 2, Status: "completed",
		TransactionStateHash: testInstallHash("completed"), ResultArtifactHash: artifactHash,
		ResultArtifact: &artifact, CompletionReceipt: []byte(`{}`)}, sealed, secret
}

func selfSignedEnrollmentCertificate(t *testing.T, private *ecdsa.PrivateKey) []byte {
	t.Helper()
	if private == nil {
		var err error
		private, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "linux-device"},
		NotBefore: time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2027, 9, 11, 0, 0, 0, 0, time.UTC),
		KeyUsage:  x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func validInstallClaimCore(t *testing.T) wire.EnrollmentClaimCoreV2 {
	t.Helper()
	identity, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrapping, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identitySPKI, _ := x509.MarshalPKIXPublicKey(&identity.PublicKey)
	wrappingSPKI, _ := x509.MarshalPKIXPublicKey(&wrapping.PublicKey)
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "request"}}, identity)
	if err != nil {
		t.Fatal(err)
	}
	return wire.EnrollmentClaimCoreV2{
		Schema: 2, ClusterID: "demo-cluster", InviteID: "invite", RequestID: "request",
		CertifiedInviteRecordHash:            testInstallHash("record"),
		DeviceEnrollmentIntentCommitmentHash: testInstallHash("commitment"),
		DeviceEnrollmentIntentOpeningHash:    testInstallHash("opening"),
		AcceptedDeviceEnrollmentIntentHash:   testInstallHash("intent"),
		ClientPlatform:                       "linux-server", BaseRecoveryEpoch: 0, BaseControlEpoch: 0,
		BaseControlSetHash: testInstallHash("set"), BaseHeadHash: testInstallHash("head"),
		DeviceIdentityPublicKey:  base64.RawURLEncoding.EncodeToString(identitySPKI),
		DeviceIdentityKeyProfile: "p256-root-only-pkcs8-sha256-v1",
		WrappingPublicKey:        base64.RawURLEncoding.EncodeToString(wrappingSPKI),
		WrappingKeyProfile:       "p256-root-only-pkcs8-ecdh-v1",
		CSRDER:                   base64.RawURLEncoding.EncodeToString(csr),
		ClientNonce:              base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32)),
	}
}

func testInstallHash(value string) string {
	return wire.HashRaw("linux-install-test", []byte(value))
}
