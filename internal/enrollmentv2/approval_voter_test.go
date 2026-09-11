package enrollmentv2

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"
	"time"

	"loom/internal/wire"
)

type approvalEvidenceFixture struct {
	evidence      EnrollmentApprovalEvidenceV1
	attestation   wire.EnrollmentApprovalAttestationBodyV2
	set           wire.ControlSetV1
	member        wire.ControlMemberV1
	enrollmentKey ed25519.PrivateKey
	trustedTime   time.Time
}

func TestApprovalVoterIndependentlyVerifiesLocalIssuanceEvidence(t *testing.T) {
	fixture := newApprovalEvidenceFixture(t)
	reads := 0
	voter, err := NewApprovalVoter(fixture.member.MemberID, fixture.set, fixture.enrollmentKey,
		func() time.Time { return fixture.trustedTime },
		func(_ context.Context, clusterID, inviteID, requestID string) (EnrollmentApprovalEvidenceV1, error) {
			reads++
			if clusterID != "cluster" || inviteID != "invite" || requestID != "request" {
				t.Fatal("approval voter 未按 attestation identity 读取本地证据")
			}
			return fixture.evidence, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := voter.VoteApproval(context.Background(), EnrollmentApprovalVoteRequestV1{
		Schema: 1, Attestation: fixture.attestation,
	})
	if err != nil {
		t.Fatal(err)
	}
	if reads != 1 || wire.VerifyEnrollmentApprovalSignature(&fixture.attestation, &signature, &fixture.set) != nil {
		t.Fatalf("approval voter 未返回 exact purpose signature: reads=%d signature=%#v", reads, signature)
	}
}

func TestApprovalVoterRejectsArtifactOrCertifiedInclusionMismatch(t *testing.T) {
	fixture := newApprovalEvidenceFixture(t)
	tests := []struct {
		name   string
		mutate func(*EnrollmentApprovalEvidenceV1)
	}{
		{name: "result artifact", mutate: func(evidence *EnrollmentApprovalEvidenceV1) {
			evidence.ResultArtifact.InitialDeviceView.DeviceID = "other-device"
		}},
		{name: "issuance inclusion", mutate: func(evidence *EnrollmentApprovalEvidenceV1) {
			evidence.Issuance.OperationLeaf.ObjectID = wire.HashRaw("approval-test", []byte("other-operation"))
		}},
		{name: "registry previous preimage", mutate: func(evidence *EnrollmentApprovalEvidenceV1) {
			evidence.PreviousIssuanceRegistryLeaves = append(evidence.PreviousIssuanceRegistryLeaves,
				wire.EnrollmentIssuanceRegistryLeafV1{Schema: 1, ClaimOperationHash: wire.HashRaw("approval-test", []byte("old-claim")),
					ProvisionalIssuanceHash: wire.HashRaw("approval-test", []byte("old-issuance"))})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := cloneApprovalEvidence(t, fixture.evidence)
			test.mutate(&evidence)
			voter, err := NewApprovalVoter(fixture.member.MemberID, fixture.set, fixture.enrollmentKey,
				func() time.Time { return fixture.trustedTime },
				func(context.Context, string, string, string) (EnrollmentApprovalEvidenceV1, error) {
					return evidence, nil
				})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := voter.VoteApproval(context.Background(), EnrollmentApprovalVoteRequestV1{
				Schema: 1, Attestation: fixture.attestation,
			}); err == nil {
				t.Fatal("approval voter 对损坏的本地证据签名")
			}
		})
	}
}

func newApprovalEvidenceFixture(t *testing.T) approvalEvidenceFixture {
	t.Helper()
	set, member, enrollmentKey := controlSet(t)
	configKey := privateEd25519(2)
	profile, issuerKey := activeEnrollmentProfile(t)
	identity, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	identitySPKI, _ := x509.MarshalPKIXPublicKey(&identity.PublicKey)
	identityHash, _ := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, identitySPKI)
	wrapping, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrappingSPKI, _ := x509.MarshalPKIXPublicKey(&wrapping.PublicKey)
	wrappingEncoded := base64.RawURLEncoding.EncodeToString(wrappingSPKI)
	wrappingHash, _ := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, wrappingSPKI)
	certificateDER := approvalDeviceCertificate(t, profile, issuerKey, identity, "linux-device",
		time.Date(2026, 1, 1, 0, 5, 0, 0, time.UTC))
	parsedCertificate, _ := x509.ParseCertificate(certificateDER)
	profile.ProfileIntent.ExtensionOrderOIDs = make([]string, len(parsedCertificate.Extensions))
	for index := range parsedCertificate.Extensions {
		profile.ProfileIntent.ExtensionOrderOIDs[index] = parsedCertificate.Extensions[index].Id.String()
	}
	profileIntentHash, err := wire.DeviceCertificateProfileIntentHash(&profile.ProfileIntent)
	if err != nil {
		t.Fatal(err)
	}
	profile.DeviceCertificateProfileIntentHash = profileIntentHash
	profileHash, err := wire.DeviceCertificateProfileStateHash(&profile)
	if err != nil {
		t.Fatal(err)
	}
	intent := wire.DeviceEnrollmentIntentV1{
		Schema: 1, ClusterID: "cluster", InviteID: "invite", DeviceID: "linux-device", Platform: "linux-server",
		DeviceCertificateProfileRef: wire.DeviceCertificateProfileRefV1{ProfileID: profile.ProfileID,
			Generation: profile.Generation, DeviceCertificateProfileIntentHash: profileIntentHash,
			DeviceCertificateProfileStateHash: profileHash},
		WrappingKeyProfiles: []string{"p256-root-only-pkcs8-ecdh-v1"},
		Membership:          wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"},
		Responsibilities:    wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}},
		Grants:              wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}},
	}
	intentHash, _ := wire.EnrollmentIntentHash(&intent)
	opening := wire.DeviceEnrollmentIntentOpeningV1{Schema: 1, ClusterID: "cluster", InviteID: "invite",
		DeviceEnrollmentIntent: intent, DeviceEnrollmentIntentHash: intentHash,
		HidingNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	_, commitmentHash, err := wire.IntentCommitment(&opening)
	if err != nil {
		t.Fatal(err)
	}
	openingHash, _ := wire.IntentOpeningHash(&opening)
	setHash, _ := wire.ControlSetHash(&set)
	baseHash := wire.HashRaw("approval-test", []byte("base"))
	admissionBody := wire.EnrollmentAdmissionAttestationBodyV1{
		Schema: 1, AttestationType: "enrollment_admission", ClusterID: "cluster", InviteID: "invite", RequestID: "request",
		CertifiedInviteRecordHash: baseHash, DeviceEnrollmentIntentCommitmentHash: commitmentHash,
		DeviceEnrollmentIntentOpeningHash: openingHash, TokenCommitment: wire.HashRaw("approval-test", []byte("token")),
		ClaimCoreHash: wire.HashRaw("approval-test", []byte("core")), IdentityKeyHash: identityHash,
		WrappingKeyHash: wrappingHash, CSRHash: wire.HashRaw("approval-test", []byte("csr")),
		PoPVerificationProfile: "loom-enrollment-server-nonce-detached-v2", BaseRecoveryEpoch: 0,
		BaseControlEpoch: 0, BaseControlSetHash: setHash, BaseHeadHash: baseHash,
		AdmissionNotAfter: "2026-01-01T00:10:00Z", RetryNotAfter: "2026-01-01T00:15:00Z",
	}
	admissionSignature, err := wire.SignEnrollmentAdmission(admissionBody, member, enrollmentKey)
	if err != nil {
		t.Fatal(err)
	}
	admissionQC := wire.StableEnrollmentAdmissionQC(admissionBody, []wire.ControlEnrollmentSignatureV1{admissionSignature})
	admissionHash, _ := wire.EnrollmentAdmissionQCHash(&admissionQC)
	invite := InviteContext{ClusterID: "cluster", InviteID: "invite", Status: "available",
		CertifiedInviteRecordHash: baseHash, DeviceEnrollmentIntentCommitmentHash: commitmentHash,
		DeviceEnrollmentIntentOpeningHash: openingHash, TokenCommitment: admissionBody.TokenCommitment,
		ExpiresAt: "2026-01-01T00:10:00Z", MaximumReservationRetrySeconds: 300}
	claim := ClaimOperationV2{Schema: 2, ClusterID: "cluster", OperationID: "claim-operation",
		InviteID: "invite", RequestID: "request", CertifiedInviteRecordHash: baseHash,
		DeviceEnrollmentIntentCommitmentHash: commitmentHash, DeviceEnrollmentIntentOpeningHash: openingHash,
		TokenCommitment: admissionBody.TokenCommitment, ClaimCoreHash: admissionBody.ClaimCoreHash,
		AdmissionQCHash: admissionHash, IdentityKeyHash: identityHash, WrappingKeyHash: admissionBody.WrappingKeyHash,
		CSRHash: admissionBody.CSRHash, ReservedAt: "2026-01-01T00:05:00Z", RetryNotAfter: "2026-01-01T00:15:00Z"}
	claimHash, _ := wire.HashObject(DomainClaimOperation, claim)
	claimLeaf := wire.ControlOperationLeafV1{Schema: 1, OperationID: claim.OperationID, ObjectID: claimHash}
	reservationRoot, _ := wire.ControlOperationRoot([]wire.ControlOperationLeafV1{claimLeaf})
	caRoot, err := wire.CAProfileRoot(nil, []wire.DeviceCertificateProfileStateV1{profile})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := approvalTestHead(t, nil, setHash, wire.HashRaw("approval-test", []byte("bootstrap-operations")),
		caRoot, "2026-01-01T00:00:00Z")
	reservationHead := approvalTestHead(t, &bootstrap, setHash, reservationRoot, caRoot, claim.ReservedAt)
	reservationQC := approvalHeadQC(t, reservationHead, member, configKey)
	reservationQCRaw, _ := wire.MarshalCanonical(reservationQC)
	reservationQCHash, _ := wire.ConfigQCHash(reservationQCRaw)
	reserved, err := Reserve(invite, claim, &admissionQC, &set, claim.ReservedAt)
	if err != nil {
		t.Fatal(err)
	}
	certificateHash, _ := wire.DeviceCertificateHash(certificateDER)
	secretRefs := []wire.SecretArtifactRefV2{}
	secretRoot, _ := wire.SecretArtifactRefsRoot(secretRefs)
	membershipHash, _ := wire.HashObject("loom-enrollment-membership-v1", intent.Membership)
	responsibilitiesHash, _ := wire.HashObject("loom-enrollment-responsibilities-v1", intent.Responsibilities)
	grantsHash, _ := wire.HashObject("loom-enrollment-destination-grants-v1", intent.Grants)
	endpointBundle := wire.DeviceEndpointBundleV1{Schema: 1, ClusterID: "cluster", DeviceID: "linux-device",
		DeviceGeneration: 1, DataIngressSets: []wire.DeviceDataIngressBindingV1{}}
	endpointHash, _ := wire.DeviceEndpointBundleHash(&endpointBundle)
	view := wire.DeviceViewPayloadV2{Schema: 2, ClusterID: "cluster", DeviceID: "linux-device", DeviceGeneration: 1,
		State: "active", Active: &wire.DeviceActiveViewV1{IdentitySPKIHash: identityHash,
			Membership: intent.Membership, MembershipHash: membershipHash,
			Responsibilities: intent.Responsibilities, ResponsibilitiesHash: responsibilitiesHash,
			Grants: intent.Grants, GrantsHash: grantsHash, EndpointBundle: endpointBundle,
			EndpointBundleHash: endpointHash, ConfigArtifactRefs: []wire.DeviceConfigArtifactRefV1{},
			SecretArtifactRefsRoot: secretRoot}}
	viewHash, _ := wire.DeviceViewHash(&view)
	result := wire.EnrollmentResultArtifactV1{Schema: 1, ClusterID: "cluster", InviteID: "invite", RequestID: "request",
		DeviceCertificateDER: base64.RawURLEncoding.EncodeToString(certificateDER), InitialDeviceView: view,
		SecretArtifactRefs: secretRefs}
	resultHash, err := wire.EnrollmentResultArtifactHash(&result)
	if err != nil {
		t.Fatal(err)
	}
	issuanceBody := wire.EnrollmentProvisionalIssuanceBodyV1{Schema: 1, ClusterID: "cluster", InviteID: "invite",
		RequestID: "request", ClaimOperationHash: claimHash, ReservationHeadHash: reservationHead.HeadHash,
		ReservationHeadQCHash: reservationQCHash, DeviceCertificateHash: certificateHash,
		InitialDeviceViewHash: viewHash, SecretArtifactRefsRoot: secretRoot, ResultArtifactHash: resultHash,
		DeviceCertificateProfileStateHash: profileHash,
		IssuanceLogCoordinate:             wire.IssuanceLogCoordinateV1{RecoveryEpoch: 0, RaftIndex: 3}}
	issuanceEnvelope, err := wire.SignEnrollmentProvisionalIssuance(issuanceBody, &profile, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuanceHash, _ := wire.EnrollmentProvisionalIssuanceHash(&issuanceEnvelope)
	registryLeaf := wire.EnrollmentIssuanceRegistryLeafV1{Schema: 1, ClaimOperationHash: claimHash,
		ProvisionalIssuanceHash: issuanceHash}
	previousRegistryRoot, _ := wire.EnrollmentIssuanceRegistryRoot(nil)
	resultingRegistryRoot, _ := wire.EnrollmentIssuanceRegistryRoot([]wire.EnrollmentIssuanceRegistryLeafV1{registryLeaf})
	reservedHash, _ := TransactionHash(reserved)
	provisional := ProvisionalIssuanceOperationV1{Schema: 1, ClusterID: "cluster", OperationID: "provisional-operation",
		InviteID: "invite", RequestID: "request", ExpectedTransactionStateHash: reservedHash,
		ClaimOperationHash: claimHash, ProvisionalIssuanceHash: issuanceHash, IssuanceRegistryLeaf: registryLeaf,
		PreviousIssuanceRegistryRoot: previousRegistryRoot, ResultingIssuanceRegistryRoot: resultingRegistryRoot,
		IssuedAt: "2026-01-01T00:06:00Z"}
	provisionalHash, _ := wire.HashObject(DomainProvisionalOperation, provisional)
	provisionalLeaf := wire.ControlOperationLeafV1{Schema: 1, OperationID: provisional.OperationID, ObjectID: provisionalHash}
	issuanceRoot, _ := wire.ControlOperationRoot([]wire.ControlOperationLeafV1{claimLeaf, provisionalLeaf})
	issuanceHead := approvalTestHead(t, &reservationHead, setHash, issuanceRoot, caRoot, provisional.IssuedAt)
	issuanceQC := approvalHeadQC(t, issuanceHead, member, configKey)
	issuanceQCRaw, _ := wire.MarshalCanonical(issuanceQC)
	claimCanonical, _ := wire.MarshalCanonical(claimLeaf)
	issuanceAuditPath := []string{"sha256:" + hex.EncodeToString(wire.MerkleLeafHash(claimCanonical))}
	evidence := EnrollmentApprovalEvidenceV1{Schema: 1, Invite: invite,
		ClaimEvidence: ClaimPrivateEvidenceV1{Schema: 1, Opening: opening,
			WrappingPublicKey: wrappingEncoded, WrappingKeyProfile: "p256-root-only-pkcs8-ecdh-v1"}, ClaimOperation: claim,
		AdmissionQC: admissionQC, AdmissionControlSet: set,
		Reservation: CertifiedEnrollmentOperationProofV1{Head: reservationHead, ConfigQC: reservationQCRaw,
			ControlSet: set, OperationLeaf: claimLeaf, OperationLeafIndex: 0, OperationTreeSize: 1,
			OperationAuditPath: []string{}},
		ReservationCARegistry: CARegistryPreimageV1{AdminProfiles: []wire.AdminCertificateProfileV1{},
			DeviceProfiles: []wire.DeviceCertificateProfileStateV1{profile}},
		ProvisionalOperation: provisional, ProvisionalIssuance: issuanceEnvelope, DeviceCertificateProfile: profile,
		PreviousIssuanceRegistryLeaves: []wire.EnrollmentIssuanceRegistryLeafV1{}, IntermediateHeads: []wire.HeadEntryV2{},
		Issuance: CertifiedEnrollmentOperationProofV1{Head: issuanceHead, ConfigQC: issuanceQCRaw,
			ControlSet: set, OperationLeaf: provisionalLeaf, OperationLeafIndex: 1, OperationTreeSize: 2,
			OperationAuditPath: issuanceAuditPath},
		IssuanceCARegistry: CARegistryPreimageV1{AdminProfiles: []wire.AdminCertificateProfileV1{},
			DeviceProfiles: []wire.DeviceCertificateProfileStateV1{profile}}, ResultArtifact: result}
	trustedTime := time.Date(2026, 1, 1, 0, 7, 0, 0, time.UTC)
	attestation, approvalSet, err := ApprovalAttestationForEvidence(&evidence, trustedTime)
	if err != nil {
		t.Fatal(err)
	}
	if !wire.EqualCanonical(approvalSet, set) {
		t.Fatal("approval evidence 派生了错误 ControlSet")
	}
	return approvalEvidenceFixture{evidence: evidence, attestation: attestation, set: set,
		member: member, enrollmentKey: enrollmentKey, trustedTime: trustedTime}
}

func approvalTestHead(t *testing.T, parent *wire.HeadEntryV2, setHash, operationRoot, caRoot,
	committedAt string) wire.HeadEntryV2 {
	t.Helper()
	kind := "bootstrap"
	index := int64(1)
	previousEntryHash, parentHeadHash := wire.EmptyHashV1, wire.EmptyHashV1
	transition, _ := json.Marshal(wire.BootstrapHeadContextV1{Schema: 1, Kind: "bootstrap",
		InitialV2HeadPayloadHash: wire.HashRaw("approval-test", []byte("initial"))})
	transitionProofHash := wire.HashRaw("approval-test", []byte("transition"))
	if parent != nil {
		kind = "ordinary"
		index = parent.Body.Payload.RaftIndex + 1
		previousEntryHash, parentHeadHash = parent.EntryHash, parent.HeadHash
		transition, _ = json.Marshal(wire.OrdinaryHeadContextV1{Schema: 1, Kind: "ordinary"})
		transitionProofHash = parent.Body.TransitionProofHash
	}
	head, err := wire.NewHeadEntry(wire.HeadEntryBodyV2{Payload: wire.HeadEntryPayloadV2{
		Schema: 2, HeadKind: kind, ClusterID: "cluster", RecoveryEpoch: 0,
		RecoveryStatementHash: wire.HashRaw("approval-test", []byte("recovery")),
		RecoveryPolicyHash:    wire.HashRaw("approval-test", []byte("recovery-policy")),
		ControlEpoch:          0, ControlSetHash: setHash,
		ControlPeerDirectoryHash: wire.HashRaw("approval-test", []byte("directory")),
		RaftTerm:                 1, RaftIndex: index, PreviousLogEntryHash: previousEntryHash, ControlRevision: index,
		ParentHeadHash: parentHeadHash, OperationRoot: operationRoot,
		SnapshotHash:      wire.HashRaw("approval-test", []byte("snapshot")),
		EffectiveSSOTHash: wire.HashRaw("approval-test", []byte("ssot")),
		DeviceViewsRoot:   wire.HashRaw("approval-test", []byte("views")),
		AdminACLRoot:      wire.HashRaw("approval-test", []byte("admin")), CAProfileRoot: caRoot,
		BootstrapIssuerRegistryRoot: wire.HashRaw("approval-test", []byte("issuer")),
		RenderContractVersion:       2, MinReaderVersion: 2, CommittedLogicalTime: committedAt,
		MaxClockSkewSeconds: 30, TransitionContext: transition,
	}, TransitionProofHash: transitionProofHash})
	if err != nil {
		t.Fatal(err)
	}
	if parent != nil {
		if err := wire.ValidateHeadEntry(&head, parent); err != nil {
			t.Fatal(err)
		}
	}
	return head
}

func approvalHeadQC(t *testing.T, head wire.HeadEntryV2, member wire.ControlMemberV1,
	configKey ed25519.PrivateKey) wire.StableHeadReplicationQCV1 {
	t.Helper()
	signature, err := wire.SignHeadAttestation(wire.AttestationForHead(&head), member, configKey)
	if err != nil {
		t.Fatal(err)
	}
	return wire.StableQC(&head, []wire.ControlConfigSignatureV1{signature})
}

func approvalDeviceCertificate(t *testing.T, profile wire.DeviceCertificateProfileStateV1,
	issuerKey ed25519.PrivateKey, identity *ecdsa.PrivateKey, deviceID string, issuedAt time.Time) []byte {
	t.Helper()
	issuerDER, err := base64.RawURLEncoding.DecodeString(profile.ProfileIntent.IssuerCertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	policyASN1 := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 2}
	policy, _ := x509.OIDFromASN1OID(policyASN1)
	deviceURI, _ := url.Parse(profile.ProfileIntent.SANURIPrefix + deviceID)
	template := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{}, NotBefore: issuedAt,
		NotAfter: issuedAt.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, Policies: []x509.OID{policy},
		URIs: []*url.URL{deviceURI}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &identity.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func cloneApprovalEvidence(t *testing.T, value EnrollmentApprovalEvidenceV1) EnrollmentApprovalEvidenceV1 {
	t.Helper()
	body, err := wire.MarshalCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone EnrollmentApprovalEvidenceV1
	if _, err := wire.DecodeStrict(body, 16<<20, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}
