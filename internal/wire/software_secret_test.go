package wire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"
)

func TestSoftwareSigningKeysSealAndVerifyEvidence(t *testing.T) {
	for _, purpose := range []string{"ca_private_key", "acme_account_key", "tls_private_key", "control_peer_identity"} {
		t.Run(purpose, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			privateDER, err := x509.MarshalPKCS8PrivateKey(private)
			if err != nil {
				t.Fatal(err)
			}
			wrapping, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			recipient := p256Recipient(t, "demo-executor", wrapping)
			recipient.RecipientKeyProfile = "p256-root-only-pkcs8-ecdh-v1"
			policy := P256RootOnlySealingPolicyV1()
			owner := SecretArtifactOwnerV1{Kind: "device", Device: &SecretArtifactDeviceOwnerV1{DeviceID: recipient.RecipientID}}
			context, err := NewSealedSecretContext("demo-cluster", "demo-proposal", "demo-signing-key", purpose,
				owner, 1, &policy, []SealedBlobRecipientKeyRefV1{recipient})
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := SealSecret(rand.Reader, context, &policy, []SealedBlobRecipientKeyRefV1{recipient}, privateDER)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := SealedSecretEnvelopeHash(&envelope)
			if err != nil {
				t.Fatal(err)
			}
			proofKey := authorityKey(t, "ed25519", public)
			proof := SecretPossessionProofV1{Body: SecretPossessionProofBodyV1{
				Schema: 1, ClusterID: context.ClusterID, ProposalID: context.ProposalID, SecretID: context.SecretID,
				Generation: context.Generation, Purpose: purpose, Owner: owner, ImmutableRef: "blob:" + digest, PublicKey: proofKey,
			}}
			proof.ProofSignature = signAuthorityEd25519(t, proofKey, private, DomainSecretPossessionProofSignature, proof.Body)
			proofHash, err := SecretPossessionProofHash(&proof)
			if err != nil {
				t.Fatal(err)
			}
			reporterPublic, reporterPrivate, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			reporterKey := authorityKey(t, "ed25519", reporterPublic)
			availability := ArtifactAvailabilityPolicyV1{
				Schema: 1, ClusterID: context.ClusterID, PolicyID: "demo-availability", Generation: 1,
				RequiredReceiptCount: 1, RequiredFaultDomainCount: 1, MaxReceiptAgeSeconds: 300,
				Reporters: []ArtifactAvailabilityReporterRefV1{{ReporterID: "demo-reporter", ReporterKey: reporterKey,
					FaultDomain: "demo-zone", AllowedPurposes: []string{purpose}}},
			}
			availabilityHash, err := ArtifactAvailabilityPolicyHash(&availability)
			if err != nil {
				t.Fatal(err)
			}
			receipt := ArtifactAvailabilityReceiptV1{Body: ArtifactAvailabilityReceiptBodyV1{
				Schema: 1, ClusterID: context.ClusterID, ProposalID: context.ProposalID, SecretID: context.SecretID,
				Generation: 1, Purpose: purpose, ImmutableRef: proof.Body.ImmutableRef, ArtifactOrVersionDigest: digest,
				ReporterID: "demo-reporter", RecipientKeyRef: &recipient, ObservedAt: "2026-09-11T00:00:00Z",
			}}
			receipt.ReporterSignature = signAuthorityEd25519(t, reporterKey, reporterPrivate, DomainArtifactAvailabilityReceiptSign, receipt.Body)
			receipts := []ArtifactAvailabilityReceiptV1{receipt}
			receiptRoot, err := artifactReceiptRoot(receipts)
			if err != nil {
				t.Fatal(err)
			}
			ref := SecretArtifactRefV2{
				Schema: 2, ClusterID: context.ClusterID, ProposalID: context.ProposalID, SecretID: context.SecretID,
				Purpose: purpose, Owner: owner, Generation: 1, PublicKey: &proofKey,
				ImmutableRef: proof.Body.ImmutableRef, BackendKind: "sealed_blob",
				SealedBlob: &SealedBlobRefV1{CiphertextDigest: digest, SealingPolicy: policy,
					SealingPolicyHash: context.SealingPolicyHash, RecipientKeyVersions: []SealedBlobRecipientKeyRefV1{recipient}},
				PossessionProofHash: &proofHash, AvailabilityPolicyHash: availabilityHash, AvailabilityReceiptsRoot: receiptRoot,
			}
			candidate := time.Date(2026, 9, 11, 0, 1, 0, 0, time.UTC)
			if err := VerifySealedSecretBinding(&ref, &envelope); err != nil {
				t.Fatal(err)
			}
			if err := VerifySecretArtifactEvidence(&ref, &proof, &availability, receipts, candidate, 0, ""); err != nil {
				t.Fatal(err)
			}
			unsealed, err := UnsealSecretP256(&envelope, recipient, wrapping)
			if err != nil || !bytes.Equal(unsealed, privateDER) {
				t.Fatalf("software key changed during sealing: %v", err)
			}
			restored, err := x509.ParsePKCS8PrivateKey(unsealed)
			if err != nil {
				t.Fatal(err)
			}
			message := []byte("demo-signing-after-restore")
			if !ed25519.Verify(public, message, ed25519.Sign(restored.(ed25519.PrivateKey), message)) {
				t.Fatal("restored software key cannot sign as the original identity")
			}
			missing := ref
			missing.PossessionProofHash = nil
			if err := ValidateSecretArtifactRef(&missing); err == nil {
				t.Fatal("software backend bypassed mandatory possession proof")
			}
			if err := VerifySecretArtifactEvidence(&ref, nil, &availability, receipts, candidate, 0, ""); err == nil {
				t.Fatal("software backend accepted absent possession evidence")
			}
			if err := VerifySecretArtifactEvidence(&ref, &proof, &availability, nil, candidate, 0, ""); err == nil {
				t.Fatal("software backend accepted absent availability receipts")
			}
			wrongPurpose := proof
			wrongPurpose.Body.Purpose = "device_credential"
			wrongPurpose.ProofSignature = signAuthorityEd25519(t, proofKey, private, DomainSecretPossessionProofSignature, wrongPurpose.Body)
			if err := VerifySecretArtifactEvidence(&ref, &wrongPurpose, &availability, receipts, candidate, 0, ""); err == nil {
				t.Fatal("software backend accepted a proof for another purpose")
			}
			changed := envelope
			changed.CiphertextAndTag = mutateRawURL(changed.CiphertextAndTag)
			if err := VerifySealedSecretBinding(&ref, &changed); err == nil {
				t.Fatal("software backend accepted changed immutable ciphertext")
			}
		})
	}
}

func TestSoftwareAndKeystoreSealingProfilesRemainDistinct(t *testing.T) {
	software, keystore := P256RootOnlySealingPolicyV1(), P256SealingPolicyV1()
	softwareHash, err := SealingPolicyHash(&software)
	if err != nil {
		t.Fatal(err)
	}
	keystoreHash, err := SealingPolicyHash(&keystore)
	if err != nil || softwareHash == keystoreHash {
		t.Fatalf("software custody was not distinguished from Keystore: %v", err)
	}
	software.RecipientKeyProfile = keystore.RecipientKeyProfile
	if err := ValidateSealingPolicy(&software); err == nil {
		t.Fatal("accepted a software policy relabeled as Keystore")
	}
	keystore.RecipientKeyProfile = "p256-root-only-pkcs8-ecdh-v1"
	if err := ValidateSealingPolicy(&keystore); err == nil {
		t.Fatal("accepted a Keystore policy relabeled as software")
	}
}
