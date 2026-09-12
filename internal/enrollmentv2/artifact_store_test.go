package enrollmentv2

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

func TestSealedArtifactStorePublishesExactImmutableEnvelope(t *testing.T) {
	fixture := newPrivateServiceFixture(t)
	attempt := verifiedPrivateAttempt(t, fixture)
	ref, envelope := sealedArtifactForAttempt(t, attempt)
	store, err := OpenSealedArtifactStore(filepath.Join(t.TempDir(), "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(&ref, &envelope); err != nil {
		t.Fatal(err)
	}
	// exact first-result replay 是幂等的，不能再次产生或覆盖 ciphertext。
	if err := store.Put(&ref, &envelope); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ref.SealedBlob.CiphertextDigest)
	if err != nil || !wire.EqualCanonical(got, envelope) {
		t.Fatalf("immutable envelope 未逐字节重放: value=%#v err=%v", got, err)
	}
	path, _ := store.path(ref.SealedBlob.CiphertextDigest)
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("artifact file 权限/类型无效: info=%#v err=%v", info, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ref.SealedBlob.CiphertextDigest); err == nil {
		t.Fatal("读取了权限放宽的 private artifact")
	}
}

func TestReleasedArtifactReaderRequiresCompletedExactInvite(t *testing.T) {
	fixture := newPrivateServiceFixture(t)
	attempt := verifiedPrivateAttempt(t, fixture)
	ref, envelope := sealedArtifactForAttempt(t, attempt)
	resultArtifact := enrollmentResultArtifactFixture(t)
	bindResultArtifactToAttempt(t, &resultArtifact, attempt, fixture.deviceProfile,
		fixture.deviceIssuerKey, fixture.identity, fixture.now)
	resultArtifact.SecretArtifactRefs = []wire.SecretArtifactRefV2{ref}
	resultArtifact.InitialDeviceView.Active.SecretArtifactRefsRoot, _ =
		wire.SecretArtifactRefsRoot(resultArtifact.SecretArtifactRefs)

	transactions, err := OpenStore(filepath.Join(t.TempDir(), "transactions.json"))
	if err != nil {
		t.Fatal(err)
	}
	backend := &workflowBackendFixture{t: t, set: fixture.material.ControlSet,
		member: fixture.material.ControlSet.Members[0], enrollmentKey: privateEd25519(4),
		profile: fixture.deviceProfile, issuerKey: fixture.deviceIssuerKey,
		resultArtifact: resultArtifact, committedAt: fixture.now.Format("2006-01-02T15:04:05Z")}
	// workflow fixture 的 enrollment key 必须匹配 ControlSet member enrollment key。
	_, member, enrollmentKey := controlSet(t)
	backend.member, backend.enrollmentKey = member, enrollmentKey
	coordinator, err := NewCoordinator(transactions, backend)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := coordinator.ProcessClaim(context.Background(), attempt)
	if err != nil || completed.Status != "completed" {
		t.Fatalf("未建立 completed transaction: result=%#v err=%v", completed, err)
	}

	artifacts, err := OpenSealedArtifactStore(filepath.Join(t.TempDir(), "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	if err := artifacts.Put(&ref, &envelope); err != nil {
		t.Fatal(err)
	}
	reader, err := NewReleasedEnrollmentArtifactReader(transactions, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader(context.Background(), resultArtifact.ClusterID,
		resultArtifact.InviteID, ref.SealedBlob.CiphertextDigest)
	if err != nil || !wire.EqualCanonical(got, envelope) {
		t.Fatalf("completed exact artifact 未获释放: value=%#v err=%v", got, err)
	}
	if _, err := reader(context.Background(), resultArtifact.ClusterID,
		"other-invite", ref.SealedBlob.CiphertextDigest); err == nil {
		t.Fatal("跨 Invite 读取了 sealed artifact")
	}
	empty, _ := OpenStore(filepath.Join(t.TempDir(), "empty.json"))
	unreleased, _ := NewReleasedEnrollmentArtifactReader(empty, artifacts)
	if _, err := unreleased(context.Background(), resultArtifact.ClusterID,
		resultArtifact.InviteID, ref.SealedBlob.CiphertextDigest); err == nil {
		t.Fatal("仅凭 artifact 存在绕过了 completion release authorization")
	}
}

func sealedArtifactForAttempt(t *testing.T,
	attempt VerifiedClaimAttemptV2) (wire.SecretArtifactRefV2, wire.SealedSecretEnvelopeV1) {
	t.Helper()
	deviceID := attempt.material.Opening.DeviceEnrollmentIntent.DeviceID
	spki, err := base64.RawURLEncoding.DecodeString(attempt.submission.ClaimCore.WrappingPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKIXPublicKey(spki); err != nil {
		t.Fatal(err)
	}
	keyID, err := wire.AuthorityProofKeyID(spki)
	if err != nil {
		t.Fatal(err)
	}
	recipient := wire.SealedBlobRecipientKeyRefV1{
		RecipientID: deviceID, RecipientKeyGeneration: 1, RecipientKeyID: keyID,
		RecipientKeyProfile: "p256-keystore-ecdh-v1",
		RecipientPublicKey: wire.AuthorityProofKeyV1{Algorithm: "ecdsa-p256-sha256",
			PublicKeySPKIDER: base64.RawURLEncoding.EncodeToString(spki), KeyID: keyID},
	}
	owner := wire.SecretArtifactOwnerV1{Kind: "device",
		Device: &wire.SecretArtifactDeviceOwnerV1{DeviceID: deviceID}}
	policy := wire.P256SealingPolicyV1()
	contextValue, err := wire.NewSealedSecretContext(attempt.material.Record.ClusterID,
		"provisional-secret", "device-credential", "device_credential", owner, 1,
		&policy, []wire.SealedBlobRecipientKeyRefV1{recipient})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := wire.SealSecret(rand.Reader, contextValue, &policy,
		[]wire.SealedBlobRecipientKeyRefV1{recipient}, []byte("private-device-credential"))
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := wire.SealedSecretEnvelopeHash(&envelope)
	policyHash, _ := wire.SealingPolicyHash(&policy)
	ref := wire.SecretArtifactRefV2{
		Schema: 2, ClusterID: attempt.material.Record.ClusterID, ProposalID: "provisional-secret",
		SecretID: "device-credential", Purpose: "device_credential", Owner: owner, Generation: 1,
		ImmutableRef: "blob:" + digest, BackendKind: "sealed_blob",
		SealedBlob: &wire.SealedBlobRefV1{CiphertextDigest: digest, SealingPolicy: policy,
			SealingPolicyHash: policyHash, RecipientKeyVersions: []wire.SealedBlobRecipientKeyRefV1{recipient}},
		AvailabilityPolicyHash:   wire.HashRaw("artifact-store-test", []byte("availability-policy")),
		AvailabilityReceiptsRoot: wire.HashRaw("artifact-store-test", []byte("availability-receipts")),
	}
	if err := wire.VerifySealedSecretBinding(&ref, &envelope); err != nil {
		t.Fatal(err)
	}
	return ref, envelope
}
