package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestInviteProofBundlePinsLineageBeforeDescriptorSecrets(t *testing.T) {
	policy := testInvitePolicy()
	policyHash, _ := InviteIssuancePolicyHash(&policy)
	issuerPublic, issuerPrivate := deterministicEd25519(0x19)
	issuerKeyID, _ := ControlKeyID(issuerPublic)
	ingressHash := recoveryTestHash("bootstrap-ingress")
	authorization := BootstrapIssuerAuthorizationV1{
		Schema: 1, ClusterID: "demo-cluster", AuthorizationID: "bootstrap-issuer-1", Generation: 1, Status: "active",
		Active: &BootstrapIssuerAuthorizationActiveV1{
			IssuerEpoch: 1, IssuerKeyID: issuerKeyID, IssuerPublicKey: base64.RawURLEncoding.EncodeToString(issuerPublic),
			InviteIssuancePolicyHash: policyHash, ValidFrom: "2026-09-11T00:00:00Z", ValidUntil: "2026-09-12T00:00:00Z",
			MaximumCapabilityTTLSeconds: 900, MaximumConnectionAttempts: 3, MaximumConcurrentSessions: 1,
			MaximumSessionSeconds: 180, MaximumTotalBytes: 8 << 20, PermittedIngressSetHashes: []string{ingressHash},
			PermittedServiceIDs: []string{"enrollment-service-1"}, PermittedModes: []string{"initial_claim", "resume_committed_claim"},
		}, ParentHeadHash: recoveryTestHash("issuer-parent"),
	}
	authorizationHash, _ := BootstrapIssuerAuthorizationHash(&authorization)
	authorizationLeaf := BootstrapIssuerAuthorizationLeafV1{Schema: 1, AuthorizationID: authorization.AuthorizationID,
		Generation: authorization.Generation, AuthorizationHash: authorizationHash}
	authorizationLeafBytes, _ := MarshalCanonical(authorizationLeaf)
	issuerRoot := "sha256:" + hex.EncodeToString(MerkleRoot([][]byte{authorizationLeafBytes}))
	issuerProof := BootstrapIssuerAuthorizationProofV1{
		Schema: 1, ClusterID: "demo-cluster", Authorization: authorization, AuthorizationHash: authorizationHash,
		Leaf: authorizationLeaf, LeafIndex: 0, RegistryTreeSize: 1, RegistryAuditPath: []string{}, RegistryRoot: issuerRoot,
	}
	bootstrap, platformPublic, platformID, platformDigest := bootstrapBundleFixtureWithIssuerRoot(t, issuerRoot)
	parent := bootstrap.InitialHeadEntry.Head

	intent := DeviceEnrollmentIntentV1{
		Schema: 1, ClusterID: "demo-cluster", InviteID: "invite-1", DeviceID: "linux-device-1", Platform: "linux-server",
		DeviceCertificateProfileRef: DeviceCertificateProfileRefV1{ProfileID: "device-profile-1", Generation: 1,
			DeviceCertificateProfileIntentHash: recoveryTestHash("device-profile-intent"), DeviceCertificateProfileStateHash: recoveryTestHash("device-profile-state")},
		WrappingKeyProfiles: []string{"p256-root-only-pkcs8-ecdh-v1"},
		Membership:          EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"},
		Responsibilities:    EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}},
		Grants:              EnrollmentDestinationGrantsV1{Schema: 1, Values: []EnrollmentDestinationGrantV1{}},
	}
	intentHash, _ := EnrollmentIntentHash(&intent)
	opening := DeviceEnrollmentIntentOpeningV1{Schema: 1, ClusterID: "demo-cluster", InviteID: "invite-1",
		DeviceEnrollmentIntent: intent, DeviceEnrollmentIntentHash: intentHash, HidingNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	commitment, commitmentHash, err := IntentCommitment(&opening)
	if err != nil {
		t.Fatal(err)
	}
	service := PrivateEnrollmentServiceRefV1{Schema: 1, ServiceID: "enrollment-service-1", OverlayIP: "10.30.0.1",
		TCPPort: 7444, InternalCAProfileRef: "internal-ca-1", ServerIdentitySPKIPins: []string{recoveryTestHash("service-pin")}, ServiceGeneration: 1}
	serviceHash, _ := PrivateEnrollmentServiceRefHash(&service)
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tokenCommitment, _ := TokenCommitment("demo-cluster", "invite-1", token)
	record := CertifiedInviteRecordV2{
		Schema: 2, ClusterID: "demo-cluster", InviteID: "invite-1", Generation: 1,
		IssuedAt: "2026-09-11T11:00:00Z", ExpiresAt: "2026-09-11T11:15:00Z",
		DeviceEnrollmentIntentCommitmentHash: commitmentHash, TokenCommitment: tokenCommitment,
		TokenArtifactBindingHash: recoveryTestHash("token-artifact"), InviteIssuancePolicyHash: policyHash,
		BootstrapIssuerAuthorizationHash: authorizationHash, BootstrapIssuerRegistryRoot: issuerRoot,
		BootstrapCatalogHash: recoveryTestHash("catalog"), EnrollmentServiceRefHash: serviceHash,
		OperationID: "invite-operation-1", ParentHeadHash: parent.HeadHash,
	}
	recordHash, _ := CertifiedInviteRecordHash(&record, &policy)
	operationLeaf := ControlOperationLeafV1{Schema: 1, OperationID: record.OperationID, ObjectID: recordHash}
	operationLeafBytes, _ := MarshalCanonical(operationLeaf)
	operationRoot := "sha256:" + hex.EncodeToString(MerkleRoot([][]byte{operationLeafBytes}))
	ordinaryContext, _ := MarshalCanonical(OrdinaryHeadContextV1{Schema: 1, Kind: "ordinary"})
	p := parent.Body.Payload
	recordHead, err := NewHeadEntry(HeadEntryBodyV2{Payload: HeadEntryPayloadV2{
		Schema: 2, HeadKind: "ordinary", ClusterID: p.ClusterID, RecoveryEpoch: p.RecoveryEpoch,
		RecoveryStatementHash: p.RecoveryStatementHash, RecoveryPolicyHash: p.RecoveryPolicyHash,
		ControlEpoch: p.ControlEpoch, ControlSetHash: p.ControlSetHash, ControlPeerDirectoryHash: p.ControlPeerDirectoryHash,
		RaftTerm: p.RaftTerm, RaftIndex: 2, PreviousLogEntryHash: parent.EntryHash, ControlRevision: 2,
		ParentHeadHash: parent.HeadHash, OperationRoot: operationRoot, SnapshotHash: recoveryTestHash("record-snapshot"),
		EffectiveSSOTHash: recoveryTestHash("record-ssot"), DeviceViewsRoot: p.DeviceViewsRoot,
		AdminACLRoot: p.AdminACLRoot, CAProfileRoot: p.CAProfileRoot, BootstrapIssuerRegistryRoot: issuerRoot,
		RenderContractVersion: p.RenderContractVersion, MinReaderVersion: p.MinReaderVersion,
		CommittedLogicalTime: "2026-09-11T11:00:01Z", MaxClockSkewSeconds: p.MaxClockSkewSeconds,
		TransitionContext: ordinaryContext,
	}, TransitionProofHash: parent.Body.TransitionProofHash})
	if err != nil {
		t.Fatal(err)
	}
	configPrivate := privateForSeed(0x42)
	recordSignature, _ := SignHeadAttestation(AttestationForHead(&recordHead), bootstrap.InitialControlSet.Members[0], configPrivate)
	recordQCRaw, _ := MarshalCanonical(StableQC(&recordHead, []ControlConfigSignatureV1{recordSignature}))

	capabilityBody := BootstrapTunnelCapabilityBodyV1{
		Schema: 1, ClusterID: "demo-cluster", InviteID: "invite-1", CommittedInviteRecordHash: recordHash,
		InviteIssuancePolicyHash: policyHash, BootstrapIssuerAuthorizationHash: authorizationHash,
		BootstrapIssuerRegistryRoot: issuerRoot, EnrollmentServiceRefHash: serviceHash, Mode: "initial_claim",
		IssuedAt: "2026-09-11T11:00:00Z", NotBefore: "2026-09-11T11:00:00Z", ExpiresAt: "2026-09-11T11:15:00Z",
		AllowedIngressSetHash: ingressHash, AllowedServiceID: service.ServiceID, AllowedDestinationIP: service.OverlayIP,
		AllowedDestinationPrefixLength: 32, AllowedDestinationPort: service.TCPPort, AllowedInsideTransport: "tcp",
		MaximumConnectionAttempts: 3, MaximumConcurrentSessions: 1, MaximumSessionSeconds: 180,
		MaximumTotalBytes: 8 << 20, IssuerEpoch: 1, IssuerKeyID: issuerKeyID,
	}
	capabilityID, _ := CapabilityID(&capabilityBody)
	capabilityBytes, _ := MarshalCanonical(capabilityBody)
	capabilityMessage, _ := Frame(DomainBootstrapCapabilitySignature, capabilityBytes)
	capability := BootstrapTunnelCapabilityV1{Body: capabilityBody, CapabilityID: capabilityID,
		Signature: BootstrapIssuerSignatureV1{Algorithm: "ed25519", KeyID: issuerKeyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerPrivate, capabilityMessage))}}
	descriptor := InviteBootstrapDescriptorV2{
		Schema: 2, ClusterID: "demo-cluster", InviteID: "invite-1", ExpiresAt: record.ExpiresAt, Token: token,
		TokenCommitment: tokenCommitment, BootstrapTunnelCapability: capability, BootstrapCatalogHash: record.BootstrapCatalogHash,
		EnrollmentServiceRef: service, DistributionMirrors: []DistributionMirrorRefV1{
			{Schema: 1, EndpointID: "mirror-1", DistributionEndpointSetHash: recoveryTestHash("mirror-set-1"), ListenerGeneration: 1,
				BaseURL: "https://mirror-a.example.test:443/distribution/sha256/", ServerName: "mirror-a.example.test",
				WebPKIProfileRef: "webpki-v1", SPKIPins: []string{recoveryTestHash("mirror-pin-a")}, HintRank: 0},
			{Schema: 1, EndpointID: "mirror-2", DistributionEndpointSetHash: recoveryTestHash("mirror-set-2"), ListenerGeneration: 1,
				BaseURL: "https://mirror-b.example.test:443/distribution/sha256/", ServerName: "mirror-b.example.test",
				WebPKIProfileRef: "webpki-v1", SPKIPins: []string{recoveryTestHash("mirror-pin-b")}, HintRank: 1},
		}, MinimumRecoveryEpoch: 0, TrustedCheckpointHash: parent.HeadHash,
	}
	bundle := InviteProofBundleV2{
		Schema: 2, ClusterID: "demo-cluster", InviteID: "invite-1", BootstrapTransitionBundle: bootstrap,
		AuthorityTransitions: []json.RawMessage{}, CertifiedInviteRecord: record, InviteIssuancePolicy: policy,
		DeviceEnrollmentIntentCommitment: commitment, InviteOperationLeaf: operationLeaf, InviteLeafIndex: 0,
		InviteOperationTreeSize: 1, InviteOperationAuditPath: []string{}, RecordHead: recordHead,
		RecordHeadQC: recordQCRaw, BootstrapIssuerAuthorizationProof: issuerProof, BootstrapCatalogHash: record.BootstrapCatalogHash,
	}
	descriptor.ProofBundleHash, _ = InviteProofBundleHash(&bundle)
	verified, err := VerifyInviteProofBundle(&bundle, &descriptor, time.Date(2026, 9, 11, 11, 5, 0, 0, time.UTC), InviteProofTrustV2{})
	if err != nil {
		t.Fatal(err)
	}
	if verified.CertifiedInviteRecordHash() != recordHash || verified.Head().HeadHash != recordHead.HeadHash {
		t.Fatal("verified Invite proof 未返回 exact record/head")
	}

	resumeBody := capabilityBody
	resumeBody.Mode = "resume_committed_claim"
	resumeBody.IssuedAt = "2026-09-11T11:16:00Z"
	resumeBody.NotBefore = resumeBody.IssuedAt
	resumeBody.ExpiresAt = "2026-09-11T11:20:00Z"
	resumeBody.ResumeBinding = &BootstrapCapabilityResumeBindingV1{
		RequestID: "request-1", ClaimOperationHash: recoveryTestHash("claim-operation"),
		AdmissionQCHash: recoveryTestHash("admission-qc"), ClaimCoreHash: recoveryTestHash("claim-core"),
		CSRHash: recoveryTestHash("csr"), IdentityKeyHash: recoveryTestHash("identity"),
		WrappingKeyHash:                recoveryTestHash("wrapping"),
		EnrollmentTransactionStateHash: recoveryTestHash("transaction"),
	}
	resumeCapability, err := SignBootstrapCapability(resumeBody, issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	resumeDescriptor := EnrollmentResumeDescriptorV1{
		Schema: 1, ClusterID: record.ClusterID, InviteID: record.InviteID,
		RequestID: "request-1", ExpiresAt: "2026-09-11T11:20:00Z",
		ResumeTunnelCapability: resumeCapability, ClaimCoreHash: resumeBody.ResumeBinding.ClaimCoreHash,
		ClaimOperationHash:             resumeBody.ResumeBinding.ClaimOperationHash,
		AdmissionQCHash:                resumeBody.ResumeBinding.AdmissionQCHash,
		EnrollmentTransactionStateHash: resumeBody.ResumeBinding.EnrollmentTransactionStateHash,
		BootstrapCatalogHash:           record.BootstrapCatalogHash, ProofBundleHash: descriptor.ProofBundleHash,
		EnrollmentServiceRef: service, DistributionMirrors: descriptor.DistributionMirrors,
	}
	resumeVerified, err := VerifyResumeInviteProofBundle(&bundle, &resumeDescriptor,
		time.Date(2026, 9, 11, 11, 16, 30, 0, time.UTC), InviteProofTrustV2{
			V1PlatformKey: platformPublic, V1PlatformKeyID: platformID,
			V1MigrationAnchorDigest: platformDigest,
		})
	if err != nil || resumeVerified.CertifiedInviteRecordHash() != recordHash {
		t.Fatalf("Invite 过期后的 resume proof 未从 v1 root 重验: evidence=%#v err=%v", resumeVerified, err)
	}
	if head, set, previous, ok := resumeVerified.AuthorityForHead(parent.HeadHash); !ok ||
		head.HeadHash != parent.HeadHash || set.ClusterID != record.ClusterID || previous != nil {
		t.Fatal("resume proof 未保留 catalog parent Head authority")
	}
	if _, err := VerifyResumeInviteProofBundle(&bundle, &resumeDescriptor,
		time.Date(2026, 9, 11, 11, 16, 30, 0, time.UTC), InviteProofTrustV2{}); err == nil {
		t.Fatal("resume proof 接受了 descriptor 自报 trust root")
	}

	tampered := bundle
	tampered.InviteOperationLeaf.ObjectID = recoveryTestHash("other-record")
	descriptor.ProofBundleHash, _ = InviteProofBundleHash(&tampered)
	if _, err := VerifyInviteProofBundle(&tampered, &descriptor, time.Date(2026, 9, 11, 11, 5, 0, 0, time.UTC), InviteProofTrustV2{}); err == nil {
		t.Fatal("接受了 record 与 operation leaf 拼接")
	}
}
