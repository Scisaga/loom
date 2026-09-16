package wire

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func runtimeActivationFixture(t *testing.T) (RuntimeActivationBundleV1, InviteProofTrustV2, ed25519.PrivateKey) {
	t.Helper()
	bootstrap, _, _, _ := bootstrapBundleFixture(t)
	set, configKey, _ := controlSetAndPoPsFixture(t, 0x41)
	ownerPublic, ownerKey := deterministicEd25519(0x61)
	now, _ := ParseTimeZ("2026-09-11T00:00:00Z")
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-runtime-owner"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, ownerPublic, ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	legacy := LegacyRuntimePolicyV1{Schema: 1, AdminRoot: base64.RawURLEncoding.EncodeToString(der)}
	legacyHash, _ := HashObject(DomainLegacyRuntimePolicy, legacy)
	parentBody := bootstrap.InitialHeadEntry.Head.Body
	parentBody.Payload.RecoveryEpoch, parentBody.Payload.ControlEpoch = 1, 1
	parentBody.Payload.RecoveryPolicyHash, parentBody.Payload.RenderContractVersion = legacyHash, 1
	leaves := []ControlOperationLeafV1{{Schema: 1, OperationID: "demo-existing-operation", ObjectID: recoveryTestHash("old-operation")}}
	parentBody.Payload.OperationRoot, _ = ControlOperationRoot(leaves)
	parent, err := NewHeadEntry(parentBody)
	if err != nil {
		t.Fatal(err)
	}
	parentSignature, _ := SignHeadAttestation(AttestationForHead(&parent), set.Members[0], configKey)
	parentQC := StableQC(&parent, []ControlConfigSignatureV1{parentSignature})
	parentQCRaw, _ := MarshalCanonical(parentQC)
	parentQCHash, _ := ConfigQCHash(parentQCRaw)
	policy, _, pops := recoveryPolicyFixture(t, "demo-new-recovery", 1, 0x71)
	policyHash, _ := RecoveryPolicyHash(&policy)
	popRoot, _ := RecoveryKeyPossessionRoot(&policy, pops)
	platformPublic, platformKey := deterministicEd25519(0x21)
	platformDigest := sha256.Sum256(platformPublic)
	migrationRoot, _ := RuntimeDeviceMigrationRoot(nil)
	statement := RuntimeActivationStatementV1{DeviceMigrationRoot: migrationRoot, Schema: 1, ClusterID: set.ClusterID,
		OperationID: "demo-activation", ParentHeadHash: parent.HeadHash, ParentQCHash: parentQCHash,
		LegacyRecoveryPolicyHash: legacyHash, V1PlatformKeyID: "demo-platform-key",
		V1PlatformPublicKey: base64.RawURLEncoding.EncodeToString(platformPublic),
		V1PlatformKeyDigest: fmt.Sprintf("sha256:%x", platformDigest), NewRecoveryEpoch: 2,
		NewRecoveryPolicyHash: policyHash, NewRecoveryKeyPoPRoot: popRoot,
		Roots: RuntimeActivationRootsV1{SnapshotHash: recoveryTestHash("migrated-snapshot"),
			EffectiveSSOTHash: recoveryTestHash("preserved-ssot"), DeviceViewsRoot: recoveryTestHash("preserved-devices"),
			AdminACLRoot: recoveryTestHash("authorized-admin-acl"), CAProfileRoot: recoveryTestHash("actual-ca-registry"),
			BootstrapIssuerRegistryRoot: recoveryTestHash("actual-bootstrap-issuers"), RenderContractVersion: 2},
		IssuedAt: now.Add(time.Second).Format(time.RFC3339), Reason: "activate private enrollment"}
	proof, err := SignRuntimeActivationProof(statement, legacy, ownerKey, platformKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := RuntimeActivationBundleV1{Schema: 1, Proof: proof, Parent: parent, ParentQC: parentQC,
		ControlSet: set, RecoveryPolicy: policy, RecoveryKeyPossessionProofs: pops, PreviousOperationLeaves: leaves}
	body, err := RuntimeActivationHeadBody(&bundle, 2, 2, parent.EntryHash, statement.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Head, err = NewHeadEntry(body)
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := SignHeadAttestation(AttestationForHead(&bundle.Head), set.Members[0], configKey)
	bundle.ConfigQC = StableQC(&bundle.Head, []ControlConfigSignatureV1{signature})
	trust := InviteProofTrustV2{V1PlatformKey: platformPublic, V1PlatformKeyID: statement.V1PlatformKeyID,
		V1MigrationAnchorDigest: statement.V1PlatformKeyDigest}
	return bundle, trust, configKey
}

func TestRuntimeActivationPreservesAuthorityAndLogWithExplicitTrust(t *testing.T) {
	bundle, trust, _ := runtimeActivationFixture(t)
	for name, verify := range map[string]func() (string, error){
		"existing-platform": func() (string, error) { return VerifyRuntimeActivationBundle(&bundle, trust, "", "") },
		"existing-head": func() (string, error) {
			return VerifyRuntimeActivationBundle(&bundle, InviteProofTrustV2{}, bundle.Parent.HeadHash, "")
		},
		"new-device-qr": func() (string, error) {
			return VerifyRuntimeActivationBundle(&bundle, InviteProofTrustV2{}, "", bundle.Head.HeadHash)
		},
	} {
		t.Run(name, func(t *testing.T) {
			hash, err := verify()
			if err != nil || hash != bundle.Head.Body.TransitionProofHash {
				t.Fatalf("valid migration rejected: %v", err)
			}
		})
	}
	old, next := bundle.Parent.Body.Payload, bundle.Head.Body.Payload
	if next.ParentHeadHash != bundle.Parent.HeadHash || next.RaftIndex <= old.RaftIndex ||
		next.ControlSetHash != old.ControlSetHash || next.ControlPeerDirectoryHash != old.ControlPeerDirectoryHash ||
		next.RecoveryEpoch <= old.RecoveryEpoch || next.ControlRevision != next.RaftIndex {
		t.Fatal("迁移丢失原 authority 或日志连续性")
	}
	if _, err := VerifyRuntimeActivationBundle(&bundle, InviteProofTrustV2{}, "", ""); err == nil {
		t.Fatal("把自报签名当成 trusted root")
	}
}

func TestRuntimeActivationRejectsForgedRootsTruncatedHistoryAndRebootstrap(t *testing.T) {
	original, trust, configKey := runtimeActivationFixture(t)
	for name, change := range map[string]func(*RuntimeActivationBundleV1){
		"owner-signature":          func(b *RuntimeActivationBundleV1) { b.Proof.OwnerSignature = b.Proof.PlatformSignature },
		"platform-signature":       func(b *RuntimeActivationBundleV1) { b.Proof.PlatformSignature = b.Proof.OwnerSignature },
		"new-policy":               func(b *RuntimeActivationBundleV1) { b.RecoveryPolicy.PolicyID = "demo-replaced-policy" },
		"missing-key-possession":   func(b *RuntimeActivationBundleV1) { b.RecoveryKeyPossessionProofs = nil },
		"drop-existing-operations": func(b *RuntimeActivationBundleV1) { b.PreviousOperationLeaves = []ControlOperationLeafV1{} },
		"alter-authorized-snapshot": func(b *RuntimeActivationBundleV1) {
			b.Proof.Statement.Roots.SnapshotHash = recoveryTestHash("replacement")
		},
		"restart-log": func(b *RuntimeActivationBundleV1) {
			b.Head.Body.Payload.RaftIndex = 1
			b.Head.Body.Payload.ControlRevision = 1
		},
		"unsigned-extra-root": func(b *RuntimeActivationBundleV1) {
			b.Head.Body.Payload.AdminACLRoot = recoveryTestHash("extra-authority")
		},
		"replace-control":   func(b *RuntimeActivationBundleV1) { b.Head.Body.Payload.ControlSetHash = recoveryTestHash("other-set") },
		"missing-new-qc":    func(b *RuntimeActivationBundleV1) { b.ConfigQC.Signatures = nil },
		"replace-parent-qc": func(b *RuntimeActivationBundleV1) { b.ParentQC.Signatures = nil },
	} {
		t.Run(name, func(t *testing.T) {
			bundle := cloneInviteProofValue(original)
			change(&bundle)
			if _, err := VerifyRuntimeActivationBundle(&bundle, trust, original.Parent.HeadHash, ""); err == nil {
				t.Fatal("接受无效迁移")
			}
		})
	}
	// 即使现任 config signer 为越权的状态签出了真实 QC，owner statement 仍能挡住。
	forged := cloneInviteProofValue(original)
	forged.Head.Body.Payload.AdminACLRoot = recoveryTestHash("config-signer-escalation")
	forged.Head, _ = NewHeadEntry(forged.Head.Body)
	signature, _ := SignHeadAttestation(AttestationForHead(&forged.Head), forged.ControlSet.Members[0], configKey)
	forged.ConfigQC = StableQC(&forged.Head, []ControlConfigSignatureV1{signature})
	if _, err := VerifyRuntimeActivationBundle(&forged, trust, original.Parent.HeadHash, ""); err == nil {
		t.Fatal("现任 config signer 能绕过 owner 授予自己权限")
	}
	repeat := cloneInviteProofValue(original)
	repeat.Parent, repeat.ParentQC = original.Head, original.ConfigQC
	if _, err := RuntimeActivationHeadBody(&repeat, 3, 3, repeat.Parent.EntryHash, "2026-09-11T00:00:02Z"); err == nil {
		t.Fatal("完成迁移的正式状态还能再次进入旧运行时迁移路径")
	}
}
