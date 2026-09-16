package enrollmentv2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestLocalMaterialUsesDurableCiphertextAndRealPossessionEvidence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "artifacts")
	store, err := OpenSealedArtifactStore(root)
	if err != nil {
		t.Fatal(err)
	}
	_, reporter, _ := ed25519.GenerateKey(rand.Reader)
	_, issuer, _ := ed25519.GenerateKey(rand.Reader)
	wrapping, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, _ := MaterialAuthorityKey(reporter.Public())
	wrapKey, _ := MaterialAuthorityKey(wrapping.Public())
	policy := wire.ArtifactAvailabilityPolicyV1{Schema: 1, ClusterID: "demo-cluster", PolicyID: "demo-local-policy",
		Generation: 1, RequiredReceiptCount: 1, RequiredFaultDomainCount: 1, MaxReceiptAgeSeconds: 300,
		Reporters: []wire.ArtifactAvailabilityReporterRefV1{{ReporterID: "demo-executor", ReporterKey: key,
			FaultDomain: "demo-host", AllowedPurposes: []string{"ca_private_key"}}}}
	sealing := wire.P256RootOnlySealingPolicyV1()
	recipients := []wire.SealedBlobRecipientKeyRefV1{{RecipientID: "demo-executor", RecipientKeyGeneration: 1,
		RecipientKeyID: wrapKey.KeyID, RecipientKeyProfile: sealing.RecipientKeyProfile, RecipientPublicKey: wrapKey}}
	context, err := wire.NewSealedSecretContext("demo-cluster", "demo-activation", "demo-device-ca", "ca_private_key",
		wire.SecretArtifactOwnerV1{Kind: "device", Device: &wire.SecretArtifactDeviceOwnerV1{DeviceID: "demo-executor"}},
		1, &sealing, recipients)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := x509.MarshalPKCS8PrivateKey(issuer)
	defer clear(secret)
	now := time.Now().UTC().Truncate(time.Second)
	evidence, err := CreateLocalSealedMaterial(store, context, sealing, recipients, secret, issuer, policy,
		"demo-executor", reporter, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSealedArtifactStore(root)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := reopened.Get(evidence.Ref.SealedBlob.CiphertextDigest)
	if err != nil {
		t.Fatal(err)
	}
	unsealed, err := wire.UnsealSecretP256(&envelope, recipients[0], wrapping)
	defer clear(unsealed)
	if err != nil || !bytes.Equal(unsealed, secret) {
		t.Fatal("restart did not recover original software CA key", err)
	}
	if err := wire.VerifySecretArtifactEvidence(&evidence.Ref, evidence.Proof, &evidence.Policy,
		evidence.Receipts, now, 0, ""); err != nil {
		t.Fatal(err)
	}
	changed := evidence.Receipts[0]
	changed.Body.ArtifactOrVersionDigest = wire.EmptyHashV1
	if err := wire.VerifySecretArtifactEvidence(&evidence.Ref, evidence.Proof, &evidence.Policy,
		[]wire.ArtifactAvailabilityReceiptV1{changed}, now, 0, ""); err == nil {
		t.Fatal("receipt for other ciphertext accepted")
	}
	for _, test := range []struct {
		name   string
		mutate func(*wire.ArtifactAvailabilityPolicyV1, *ed25519.PrivateKey)
	}{
		{"different-secret", func(_ *wire.ArtifactAvailabilityPolicyV1, signer *ed25519.PrivateKey) {
			_, *signer, _ = ed25519.GenerateKey(rand.Reader)
		}},
		{"multiple-required-reporters", func(policy *wire.ArtifactAvailabilityPolicyV1, _ *ed25519.PrivateKey) {
			policy.RequiredReceiptCount = 2
		}},
		{"wrong-purpose", func(policy *wire.ArtifactAvailabilityPolicyV1, _ *ed25519.PrivateKey) {
			policy.Reporters[0].AllowedPurposes = []string{"device_credential"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			badPolicy, badSigner := policy, issuer
			badPolicy.Reporters = append([]wire.ArtifactAvailabilityReporterRefV1(nil), policy.Reporters...)
			test.mutate(&badPolicy, &badSigner)
			isolated, _ := OpenSealedArtifactStore(filepath.Join(t.TempDir(), "artifacts"))
			if _, err := CreateLocalSealedMaterial(isolated, context, sealing, recipients, secret, badSigner,
				badPolicy, "demo-executor", reporter, now, rand.Reader); err == nil {
				t.Fatal("invalid evidence input accepted")
			}
			entries, err := os.ReadDir(isolated.root)
			if err != nil || len(entries) != 0 {
				t.Fatal("rejected input reached artifact publication", err)
			}
		})
	}
}
