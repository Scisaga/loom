package wire

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"
)

func runtimeDeviceMigrationFixture(t *testing.T) (RuntimeDeviceMigrationPackageV1, RuntimeDeviceMigrationExpectedV1, InviteProofTrustV2, time.Time) {
	t.Helper()
	activation, trust, configKey := runtimeActivationFixture(t)
	certificateFixture := newDeviceCertificateFixture(t)
	certificate, err := x509.ParseCertificate(certificateFixture.leafDER)
	if err != nil {
		t.Fatal(err)
	}
	const deviceID = "demo-migrated-device"
	identitySPKI := append([]byte(nil), certificate.RawSubjectPublicKeyInfo...)
	certificate.URIs = []*url.URL{{Scheme: "spiffe", Host: "cluster.example", Path: "/device/" + deviceID}}
	issuerDER, _ := base64.RawURLEncoding.DecodeString(certificateFixture.intent.IssuerCertificateDER)
	issuer, _ := x509.ParseCertificate(issuerDER)
	certificateDER, err := x509.CreateCertificate(rand.Reader, certificate, issuer, certificate.PublicKey, certificateFixture.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	intent := certificateFixture.intent
	intent.TargetStatus = "active"
	intentHash, _ := DeviceCertificateProfileIntentHash(&intent)
	approvedAt := certificateFixture.now.Format(time.RFC3339)
	profile := DeviceCertificateProfileStateV1{Schema: 1, ClusterID: activation.ControlSet.ClusterID,
		ProfileID: intent.ProfileID, Generation: intent.Generation, ProfileIntent: intent,
		DeviceCertificateProfileIntentHash: intentHash, Status: "active", StatusChangedAt: approvedAt}
	profileHash, err := DeviceCertificateProfileStateHash(&profile)
	if err != nil {
		t.Fatal(err)
	}
	caRoot, err := CAProfileRoot([]AdminCertificateProfileV1{}, []DeviceCertificateProfileStateV1{profile})
	if err != nil {
		t.Fatal(err)
	}
	certificateHash, _ := DeviceCertificateHash(certificateDER)
	legacy := BootstrapDeviceFloorLeafV1{Schema: 1, DeviceID: deviceID, V1Generation: 17,
		V1SignedCurrentHash: recoveryTestHash("demo-signed-current"), V1PayloadHash: recoveryTestHash("demo-current-payload")}
	leaf := RuntimeDeviceMigrationLeafV1{Schema: 1, ClusterID: activation.ControlSet.ClusterID, DeviceID: deviceID,
		Platform: "android", LegacyFloor: legacy, IdentitySPKIHash: certificateFixture.identityHash,
		WrappingKeyHash: recoveryTestHash("demo-existing-wrapping-key"), DeviceCertificateHash: certificateHash,
		DeviceCertificateProfileHash: profileHash, Issuance: IssuanceLogCoordinateV1{RecoveryEpoch: 2, RaftIndex: 2}}
	proof, err := BuildRuntimeDeviceMigrationProof([]RuntimeDeviceMigrationLeafV1{leaf}, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	view := validDeviceViewPayloadForResponsibilities(t)
	view.ClusterID, view.DeviceID = leaf.ClusterID, deviceID
	view.Active.IdentitySPKIHash = leaf.IdentitySPKIHash
	view.Active.EndpointBundle.ClusterID, view.Active.EndpointBundle.DeviceID = leaf.ClusterID, deviceID
	view.Active.EndpointBundleHash, _ = DeviceEndpointBundleHash(&view.Active.EndpointBundle)
	viewHash, _ := DeviceViewHash(&view)
	viewLeaf := DeviceViewLeafV2{Schema: 2, ClusterID: view.ClusterID, ViewSchemaVersion: 2, DeviceID: deviceID,
		DeviceGeneration: 1, State: "active", PayloadHash: viewHash, PreviousViewHash: EmptyHashV1,
		EndpointSetHash: view.Active.EndpointBundleHash, MinReaderVersion: 2}
	viewBytes, _ := MarshalCanonical(viewLeaf)
	statement := activation.Proof.Statement
	statement.DeviceMigrationRoot, _ = RuntimeDeviceMigrationRoot([]RuntimeDeviceMigrationLeafV1{leaf})
	statement.Roots.DeviceViewsRoot = fmt.Sprintf("sha256:%x", MerkleRoot([][]byte{viewBytes}))
	statement.Roots.CAProfileRoot, statement.IssuedAt = caRoot, approvedAt
	_, ownerKey := deterministicEd25519(0x61)
	_, platformKey := deterministicEd25519(0x21)
	activation.Proof, err = SignRuntimeActivationProof(statement, activation.Proof.LegacyPolicy, ownerKey, platformKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := RuntimeActivationHeadBody(&activation, 2, 2, activation.Parent.EntryHash, approvedAt)
	if err != nil {
		t.Fatal(err)
	}
	activation.Head, err = NewHeadEntry(body)
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := SignHeadAttestation(AttestationForHead(&activation.Head), activation.ControlSet.Members[0], configKey)
	activation.ConfigQC = StableQC(&activation.Head, []ControlConfigSignatureV1{signature})
	qc, _ := MarshalCanonical(activation.ConfigQC)
	envelope := DeviceViewEnvelopeV2{Schema: 2, Payload: view, Leaf: viewLeaf, TreeSize: 1,
		AuditPath: []string{}, SecretArtifactRefs: []json.RawMessage{},
		SignedCurrent: SignedCurrentV2{Schema: 2, Head: activation.Head, QuorumCertificate: qc, PublishedAt: approvedAt}}
	delivery := RuntimeDeviceMigrationPackageV1{Schema: 1, Activation: activation, Migration: proof,
		DeviceCertificateDER: base64.RawURLEncoding.EncodeToString(certificateDER), DeviceProfile: profile,
		AdminCertificateProfiles: []AdminCertificateProfileV1{}, DeviceCertificateProfiles: []DeviceCertificateProfileStateV1{profile},
		DistributionMirrors: []DistributionMirrorRefV1{
			{Schema: 1, EndpointID: "demo-mirror-a", DistributionEndpointSetHash: recoveryTestHash("demo-endpoints"), ListenerGeneration: 1,
				BaseURL: "https://mirror-a.example:443/distribution/sha256/", ServerName: "mirror-a.example", WebPKIProfileRef: "demo-webpki", SPKIPins: []string{recoveryTestHash("demo-mirror-pin")}},
			{Schema: 1, EndpointID: "demo-mirror-b", DistributionEndpointSetHash: recoveryTestHash("demo-endpoints"), ListenerGeneration: 1, HintRank: 1,
				BaseURL: "https://mirror-b.example:443/distribution/sha256/", ServerName: "mirror-b.example", WebPKIProfileRef: "demo-webpki", SPKIPins: []string{recoveryTestHash("demo-mirror-pin")}},
		},
		Configuration: DeviceConfigDeliveryV1{Schema: 1, ClusterID: leaf.ClusterID, DeviceID: deviceID,
			Updates: []DeviceConfigUpdateV1{{Schema: 1, Envelope: envelope, ControlSet: activation.ControlSet,
				RecoveryPolicy: &activation.RecoveryPolicy}}}}
	expected := RuntimeDeviceMigrationExpectedV1{DeviceID: deviceID, Platform: leaf.Platform,
		IdentitySPKIDER: identitySPKI, WrappingKeyHash: leaf.WrappingKeyHash, LegacyFloor: legacy}
	return delivery, expected, trust, certificateFixture.now.Add(time.Minute)
}

func TestRuntimeDeviceMigrationPreservesIdentityFloorAndCertifiedAuthority(t *testing.T) {
	delivery, expected, trust, now := runtimeDeviceMigrationFixture(t)
	verified, err := VerifyRuntimeDeviceMigration(&delivery, expected, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Leaf().IdentitySPKIHash != delivery.Migration.Leaf.IdentitySPKIHash ||
		verified.Configuration().Floors().HeadHash != delivery.Activation.Head.HeadHash ||
		verified.Configuration().Floors().BootstrapTransitionHash != delivery.Activation.Head.Body.TransitionProofHash {
		t.Fatal("迁移改变了原身份或没有保存 authority/floors")
	}
	copy := verified.CertificateDER()
	copy[0] ^= 1
	if copy[0] == verified.CertificateDER()[0] {
		t.Fatal("调用方能够改写已验证证书")
	}
}

func TestRuntimeDeviceMigrationContinuesThroughLaterPrivateConfig(t *testing.T) {
	delivery, expected, trust, now := runtimeDeviceMigrationFixture(t)
	first := delivery.Configuration.Updates[0]
	_, configKey, _ := controlSetAndPoPsFixture(t, 0x41)
	next := cloneDeviceConfigValue(first)
	head := nextDeviceProfileHead(t, first.Envelope.SignedCurrent.Head, now.Format(time.RFC3339))
	signature, err := SignHeadAttestation(AttestationForHead(&head), next.ControlSet.Members[0], configKey)
	if err != nil {
		t.Fatal(err)
	}
	qc := StableQC(&head, []ControlConfigSignatureV1{signature})
	qcBytes, _ := MarshalCanonical(qc)
	next.Envelope.SignedCurrent = SignedCurrentV2{Schema: 2, Head: head, QuorumCertificate: qcBytes,
		PublishedAt: now.Format(time.RFC3339)}
	delivery.Configuration.Updates = append(delivery.Configuration.Updates, next)
	verified, err := VerifyRuntimeDeviceMigration(&delivery, expected, trust, now)
	if err != nil || verified.Configuration().Floors().HeadHash != head.HeadHash {
		t.Fatal("迁移未接续后续真实配置坐标", err)
	}
	delivery.Configuration.Updates = delivery.Configuration.Updates[1:]
	if _, err := VerifyRuntimeDeviceMigration(&delivery, expected, trust, now); err == nil {
		t.Fatal("缺失原迁移 Head 的窗口被当成合法接续")
	}
}

func TestRuntimeDeviceMigrationRejectsReplacedKeysFloorsCertificatesAndAuthority(t *testing.T) {
	delivery, expected, trust, now := runtimeDeviceMigrationFixture(t)
	tests := map[string]func(*RuntimeDeviceMigrationPackageV1, *RuntimeDeviceMigrationExpectedV1, *InviteProofTrustV2){
		"old-floor": func(_ *RuntimeDeviceMigrationPackageV1, e *RuntimeDeviceMigrationExpectedV1, _ *InviteProofTrustV2) {
			e.LegacyFloor.V1Generation--
		},
		"other-current": func(_ *RuntimeDeviceMigrationPackageV1, e *RuntimeDeviceMigrationExpectedV1, _ *InviteProofTrustV2) {
			e.LegacyFloor.V1SignedCurrentHash = recoveryTestHash("demo-other-current")
		},
		"other-wrapping-key": func(_ *RuntimeDeviceMigrationPackageV1, e *RuntimeDeviceMigrationExpectedV1, _ *InviteProofTrustV2) {
			e.WrappingKeyHash = recoveryTestHash("demo-replaced-key")
		},
		"other-device": func(_ *RuntimeDeviceMigrationPackageV1, e *RuntimeDeviceMigrationExpectedV1, _ *InviteProofTrustV2) {
			e.DeviceID = "demo-other-device"
		},
		"other-platform": func(_ *RuntimeDeviceMigrationPackageV1, e *RuntimeDeviceMigrationExpectedV1, _ *InviteProofTrustV2) {
			e.Platform = "windows-desktop"
		},
		"missing-local-key": func(_ *RuntimeDeviceMigrationPackageV1, e *RuntimeDeviceMigrationExpectedV1, _ *InviteProofTrustV2) {
			e.IdentitySPKIDER = nil
		},
		"no-anchor": func(_ *RuntimeDeviceMigrationPackageV1, _ *RuntimeDeviceMigrationExpectedV1, t *InviteProofTrustV2) {
			*t = InviteProofTrustV2{}
		},
		"forged-migration-root": func(p *RuntimeDeviceMigrationPackageV1, _ *RuntimeDeviceMigrationExpectedV1, _ *InviteProofTrustV2) {
			p.Activation.Proof.Statement.DeviceMigrationRoot = recoveryTestHash("demo-forged-root")
		},
		"certificate": func(p *RuntimeDeviceMigrationPackageV1, _ *RuntimeDeviceMigrationExpectedV1, _ *InviteProofTrustV2) {
			p.DeviceCertificateDER = base64.RawURLEncoding.EncodeToString([]byte("demo-other-certificate"))
		},
		"missing-ca-profile": func(p *RuntimeDeviceMigrationPackageV1, _ *RuntimeDeviceMigrationExpectedV1, _ *InviteProofTrustV2) {
			p.DeviceCertificateProfiles = nil
		},
		"other-head": func(p *RuntimeDeviceMigrationPackageV1, _ *RuntimeDeviceMigrationExpectedV1, _ *InviteProofTrustV2) {
			p.Configuration.Updates[0].Envelope.SignedCurrent.Head = p.Activation.Parent
		},
		"extra-audit-node": func(p *RuntimeDeviceMigrationPackageV1, _ *RuntimeDeviceMigrationExpectedV1, _ *InviteProofTrustV2) {
			p.Migration.AuditPath = []string{recoveryTestHash("demo-extra-node")}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p, e, anchor := cloneDeviceConfigValue(delivery), expected, trust
			mutate(&p, &e, &anchor)
			if _, err := VerifyRuntimeDeviceMigration(&p, e, anchor, now); err == nil {
				t.Fatal("接受不匹配的迁移输入")
			}
		})
	}
	if _, err := VerifyRuntimeDeviceMigration(&delivery, expected, trust, now.Add(24*time.Hour)); err == nil {
		t.Fatal("迁移重新启用了过期证书")
	}
}

func TestRuntimeMigrationMerkleProofSeparatesDevices(t *testing.T) {
	delivery, expected, _, _ := runtimeDeviceMigrationFixture(t)
	leaves := []RuntimeDeviceMigrationLeafV1{}
	for _, id := range []string{"demo-a", "demo-b", "demo-c"} {
		leaf := delivery.Migration.Leaf
		leaf.DeviceID, leaf.LegacyFloor.DeviceID = id, id
		leaves = append(leaves, leaf)
	}
	root, err := RuntimeDeviceMigrationRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaf := range leaves {
		proof, err := BuildRuntimeDeviceMigrationProof(leaves, leaf.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		expected.DeviceID, expected.LegacyFloor = leaf.DeviceID, leaf.LegacyFloor
		if err := VerifyRuntimeDeviceMigrationProof(&proof, expected, leaf.ClusterID, root); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RuntimeDeviceMigrationRoot([]RuntimeDeviceMigrationLeafV1{leaves[0], leaves[0]}); err == nil {
		t.Fatal("重复身份进入迁移根")
	}
	if _, err := RuntimeDeviceMigrationRoot([]RuntimeDeviceMigrationLeafV1{leaves[1], leaves[0]}); err == nil {
		t.Fatal("未排序身份进入迁移根")
	}
}
