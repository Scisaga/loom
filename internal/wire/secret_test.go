package wire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

func TestP256SealedSecretExactBindingAndUnseal(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096)))
	if err != nil {
		t.Fatal(err)
	}
	recipient := p256Recipient(t, "demo-android", private)
	policy := P256SealingPolicyV1()
	owner := SecretArtifactOwnerV1{Kind: "device", Device: &SecretArtifactDeviceOwnerV1{DeviceID: "demo-android"}}
	context, err := NewSealedSecretContext("demo-cluster", "proposal-1", "credential-1", "device_credential", owner, 1, &policy, []SealedBlobRecipientKeyRefV1{recipient})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealSecret(bytes.NewReader(bytes.Repeat([]byte{0x5a}, 8192)), context, &policy, []SealedBlobRecipientKeyRefV1{recipient}, []byte("demo-secret"))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := SealedSecretEnvelopeHash(&envelope)
	if err != nil {
		t.Fatal(err)
	}
	policyHash, _ := SealingPolicyHash(&policy)
	ref := SecretArtifactRefV2{
		Schema: 2, ClusterID: context.ClusterID, ProposalID: context.ProposalID, SecretID: context.SecretID,
		Purpose: context.Purpose, Owner: owner, Generation: 1, ImmutableRef: "blob:sha256:demo-immutable-1", BackendKind: "sealed_blob",
		SealedBlob:             &SealedBlobRefV1{CiphertextDigest: digest, SealingPolicy: policy, SealingPolicyHash: policyHash, RecipientKeyVersions: []SealedBlobRecipientKeyRefV1{recipient}},
		AvailabilityPolicyHash: hashForSecretTest("availability-policy"), AvailabilityReceiptsRoot: hashForSecretTest("receipts"),
	}
	if err := VerifySealedSecretBinding(&ref, &envelope); err != nil {
		t.Fatal(err)
	}
	secret, err := UnsealSecretP256(&envelope, recipient, private)
	if err != nil || string(secret) != "demo-secret" {
		t.Fatalf("secret=%q err=%v", secret, err)
	}
	mutated := envelope
	mutated.CiphertextAndTag = mutateRawURL(mutated.CiphertextAndTag)
	if err := VerifySealedSecretBinding(&ref, &mutated); err == nil {
		t.Fatal("接受了 ciphertext 被替换的 immutable envelope")
	}
	root, err := SecretArtifactRefsRoot([]SecretArtifactRefV2{ref})
	if err != nil {
		t.Fatal(err)
	}
	canonicalRef, _ := MarshalCanonical(ref)
	if err := VerifySecretArtifactRefsRoot([]json.RawMessage{canonicalRef}, root); err != nil {
		t.Fatal(err)
	}
	other := ref
	other.SecretID = "credential-2"
	otherRaw, _ := MarshalCanonical(other)
	if err := VerifySecretArtifactRefsRoot([]json.RawMessage{otherRaw}, root); err == nil {
		t.Fatal("Device view 接受了不匹配的 secret artifact refs root")
	}
}

func TestRSASealingUsesSHA256WithMGF1SHA1(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	recipient := rsaRecipient(t, "demo-android-legacy", private)
	policy := RSASealingPolicyV1()
	owner := SecretArtifactOwnerV1{Kind: "device", Device: &SecretArtifactDeviceOwnerV1{DeviceID: "demo-android-legacy"}}
	context, err := NewSealedSecretContext("demo-cluster", "proposal-rsa", "credential-rsa", "device_credential", owner, 1, &policy, []SealedBlobRecipientKeyRefV1{recipient})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealSecret(bytes.NewReader(bytes.Repeat([]byte{0x6b}, 8192)), context, &policy, []SealedBlobRecipientKeyRefV1{recipient}, []byte("legacy-secret"))
	if err != nil {
		t.Fatal(err)
	}
	wrapped, _ := decodeRawURL(envelope.RecipientEnvelopes[0].RSAOAEP.WrappedCEK, 256)
	cek, err := decryptOAEPWithMGF1SHA1ForTest(private, wrapped)
	if err != nil || len(cek) != 32 {
		t.Fatalf("RSA fallback 与 exact OAEP profile 不互操作: len=%d err=%v", len(cek), err)
	}
	if _, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, private, wrapped, nil); err == nil {
		t.Fatal("MGF1-SHA1 vector 意外被同-hash OAEP 接受")
	}
}

func TestSecretArtifactEvidenceBindsPoPReceiptsAndTime(t *testing.T) {
	public, private, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x11}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	proofKey := authorityKey(t, "ed25519", public)
	owner := SecretArtifactOwnerV1{Kind: "device", Device: &SecretArtifactDeviceOwnerV1{DeviceID: "demo-tls"}}
	proof := SecretPossessionProofV1{Body: SecretPossessionProofBodyV1{
		Schema: 1, ClusterID: "demo-cluster", ProposalID: "proposal-tls", SecretID: "tls-key", Generation: 1,
		Purpose: "tls_private_key", Owner: owner, ImmutableRef: "kms:demo/key/version-1", PublicKey: proofKey,
	}}
	proof.ProofSignature = signAuthorityEd25519(t, proofKey, private, DomainSecretPossessionProofSignature, proof.Body)
	proofHash, err := SecretPossessionProofHash(&proof)
	if err != nil {
		t.Fatal(err)
	}
	reporterPublic, reporterPrivate, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x22}, 64)))
	reporterKey := authorityKey(t, "ed25519", reporterPublic)
	policy := ArtifactAvailabilityPolicyV1{
		Schema: 1, ClusterID: "demo-cluster", PolicyID: "availability-1", Generation: 1,
		RequiredReceiptCount: 1, RequiredFaultDomainCount: 1, MaxReceiptAgeSeconds: 300,
		Reporters: []ArtifactAvailabilityReporterRefV1{{ReporterID: "reporter-1", ReporterKey: reporterKey, FaultDomain: "zone-a", AllowedPurposes: []string{"tls_private_key"}}},
	}
	policyHash, err := ArtifactAvailabilityPolicyHash(&policy)
	if err != nil {
		t.Fatal(err)
	}
	versionDigest := hashForSecretTest("kms-version-1")
	receipt := ArtifactAvailabilityReceiptV1{Body: ArtifactAvailabilityReceiptBodyV1{
		Schema: 1, ClusterID: "demo-cluster", ProposalID: "proposal-tls", SecretID: "tls-key", Generation: 1,
		Purpose: "tls_private_key", ImmutableRef: "kms:demo/key/version-1", ArtifactOrVersionDigest: versionDigest,
		ReporterID: "reporter-1", ObservedAt: "2026-09-11T00:00:00Z",
	}}
	receipt.ReporterSignature = signAuthorityEd25519(t, reporterKey, reporterPrivate, DomainArtifactAvailabilityReceiptSign, receipt.Body)
	receiptRoot, err := artifactReceiptRoot([]ArtifactAvailabilityReceiptV1{receipt})
	if err != nil {
		t.Fatal(err)
	}
	ref := SecretArtifactRefV2{
		Schema: 2, ClusterID: "demo-cluster", ProposalID: "proposal-tls", SecretID: "tls-key", Purpose: "tls_private_key",
		Owner: owner, Generation: 1, PublicKey: &proofKey, ImmutableRef: "kms:demo/key/version-1", BackendKind: "kms_or_hardware_key",
		KMSOrHardwareKey:    &KMSOrHardwareKeyRefV1{Provider: "demo-kms", ObjectID: "tls-key", ExactVersion: "version-1", PolicyHash: hashForSecretTest("kms-policy")},
		PossessionProofHash: &proofHash, AvailabilityPolicyHash: policyHash, AvailabilityReceiptsRoot: receiptRoot,
	}
	candidate := time.Date(2026, 9, 11, 0, 1, 0, 0, time.UTC)
	if err := VerifySecretArtifactEvidence(&ref, &proof, &policy, []ArtifactAvailabilityReceiptV1{receipt}, candidate, 30*time.Second, versionDigest); err != nil {
		t.Fatal(err)
	}
	late := receipt
	late.Body.ObservedAt = "2026-09-11T00:02:00Z"
	late.ReporterSignature = signAuthorityEd25519(t, reporterKey, reporterPrivate, DomainArtifactAvailabilityReceiptSign, late.Body)
	lateRoot, _ := artifactReceiptRoot([]ArtifactAvailabilityReceiptV1{late})
	lateRef := ref
	lateRef.AvailabilityReceiptsRoot = lateRoot
	if err := VerifySecretArtifactEvidence(&lateRef, &proof, &policy, []ArtifactAvailabilityReceiptV1{late}, candidate, 30*time.Second, versionDigest); err == nil {
		t.Fatal("接受了晚于 committed logical time + skew 的 receipt")
	}
	wrongProposal := proof
	wrongProposal.Body.ProposalID = "proposal-other"
	wrongProposal.ProofSignature = signAuthorityEd25519(t, proofKey, private, DomainSecretPossessionProofSignature, wrongProposal.Body)
	if err := VerifySecretArtifactEvidence(&ref, &wrongProposal, &policy, []ArtifactAvailabilityReceiptV1{receipt}, candidate, 30*time.Second, versionDigest); err == nil {
		t.Fatal("接受了跨 proposal 搬用的 possession proof")
	}
}

func p256Recipient(t *testing.T, id string, private *ecdsa.PrivateKey) SealedBlobRecipientKeyRefV1 {
	t.Helper()
	key := authorityKey(t, "ecdsa-p256-sha256", &private.PublicKey)
	return SealedBlobRecipientKeyRefV1{RecipientID: id, RecipientKeyGeneration: 1, RecipientKeyID: key.KeyID, RecipientKeyProfile: "p256-keystore-ecdh-v1", RecipientPublicKey: key}
}

func rsaRecipient(t *testing.T, id string, private *rsa.PrivateKey) SealedBlobRecipientKeyRefV1 {
	t.Helper()
	key := authorityKey(t, "rsa2048-pkcs1v15-sha256", &private.PublicKey)
	return SealedBlobRecipientKeyRefV1{RecipientID: id, RecipientKeyGeneration: 1, RecipientKeyID: key.KeyID, RecipientKeyProfile: "rsa2048-keystore-decrypt-v1", RecipientPublicKey: key}
}

func authorityKey(t *testing.T, algorithm string, public any) AuthorityProofKeyV1 {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := AuthorityProofKeyID(der)
	return AuthorityProofKeyV1{Algorithm: algorithm, PublicKeySPKIDER: base64.RawURLEncoding.EncodeToString(der), KeyID: keyID}
}

func signAuthorityEd25519(t *testing.T, key AuthorityProofKeyV1, private ed25519.PrivateKey, domain string, body any) AuthorityProofSignatureV1 {
	t.Helper()
	canonical, err := MarshalCanonical(body)
	if err != nil {
		t.Fatal(err)
	}
	message, _ := Frame(domain, canonical)
	return AuthorityProofSignatureV1{Algorithm: key.Algorithm, KeyID: key.KeyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))}
}

func hashForSecretTest(value string) string {
	return HashRaw("secret-artifact-test", []byte(value))
}

func mutateRawURL(value string) string {
	raw, _ := base64.RawURLEncoding.DecodeString(value)
	raw[len(raw)-1] ^= 1
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decryptOAEPWithMGF1SHA1ForTest(private *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(ciphertext)
	m := new(big.Int).Exp(c, private.D, private.N)
	em := m.FillBytes(make([]byte, private.Size()))
	hLen := sha256.Size
	maskedSeed, maskedDB := append([]byte(nil), em[1:1+hLen]...), append([]byte(nil), em[1+hLen:]...)
	seedMask := mgf1ForTest(maskedDB, hLen)
	for i := range maskedSeed {
		maskedSeed[i] ^= seedMask[i]
	}
	dbMask := mgf1ForTest(maskedSeed, len(maskedDB))
	for i := range maskedDB {
		maskedDB[i] ^= dbMask[i]
	}
	lHash := sha256.Sum256(nil)
	if em[0] != 0 || !bytes.Equal(maskedDB[:hLen], lHash[:]) {
		return nil, rsa.ErrDecryption
	}
	index := hLen
	for index < len(maskedDB) && maskedDB[index] == 0 {
		index++
	}
	if index >= len(maskedDB) || maskedDB[index] != 1 {
		return nil, rsa.ErrDecryption
	}
	return maskedDB[index+1:], nil
}

func mgf1ForTest(seed []byte, length int) []byte {
	result := make([]byte, 0, length)
	for counter := uint32(0); len(result) < length; counter++ {
		h := sha1.New()
		h.Write(seed)
		h.Write([]byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)})
		result = append(result, h.Sum(nil)...)
	}
	return result[:length]
}
