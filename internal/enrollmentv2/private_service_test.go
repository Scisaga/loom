package enrollmentv2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

type privateServiceFixture struct {
	now                  time.Time
	service              *PrivateService
	capability           wire.VerifiedBootstrapCapabilityV1
	material             InviteMaterialV2
	core                 wire.EnrollmentClaimCoreV2
	identity             *ecdsa.PrivateKey
	issuerPrivate        ed25519.PrivateKey
	issuerProof          wire.BootstrapIssuerAuthorizationProofV1
	deviceProfile        wire.DeviceCertificateProfileStateV1
	deviceIssuerKey      ed25519.PrivateKey
	bootstrapCatalog     wire.BootstrapEndpointCatalogV1
	bootstrapCatalogHead wire.HeadEntryV2
	token                string
	processed            *int
}

func TestPrivateEnrollmentPreflightChallengeClaimAndReplayBoundary(t *testing.T) {
	fixture := newPrivateServiceFixture(t)
	request := wire.EnrollmentIntentPreflightRequestV1{
		Schema: 1, ClusterID: "cluster", InviteID: "invite",
		CertifiedInviteRecordHash: fixture.capability.Body().CommittedInviteRecordHash,
		CapabilityID:              fixture.capability.CapabilityID(),
	}
	response, err := fixture.service.Preflight(context.Background(), fixture.capability, &request)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.VerifyEnrollmentIntentPreflight(&response, &request, fixture.material.Record.DeviceEnrollmentIntentCommitmentHash); err != nil {
		t.Fatal(err)
	}
	challenge, err := fixture.service.Challenge(context.Background(), fixture.capability, &fixture.core)
	if err != nil {
		t.Fatal(err)
	}
	submission := signedPrivateSubmission(t, fixture, challenge)
	result, err := fixture.service.SubmitClaim(context.Background(), fixture.capability, &submission)
	if err != nil || result.Status != "reserved" || *fixture.processed != 1 {
		t.Fatalf("claim result=%#v processed=%d err=%v", result, *fixture.processed, err)
	}
	if _, err := fixture.service.SubmitClaim(context.Background(), fixture.capability, &submission); err == nil {
		t.Fatal("重复使用同一 server challenge 被接受")
	}
	if *fixture.processed != 1 {
		t.Fatal("replay 到达了 claim processor")
	}
}

func TestPrivateEnrollmentRejectsClientChosenChallenge(t *testing.T) {
	fixture := newPrivateServiceFixture(t)
	coreHash, _ := wire.EnrollmentClaimCoreHash(&fixture.core)
	challenge := wire.EnrollmentPoPChallengeV1{
		Schema: 1, ClusterID: "cluster", InviteID: "invite", RequestID: fixture.core.RequestID,
		EnrollmentServiceID: "enrollment-service", ClaimCoreHash: coreHash,
		ServerNonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7f}, 32)),
		IssuedAt:    fixture.now.Format(time.RFC3339), ExpiresAt: fixture.now.Add(time.Minute).Format(time.RFC3339),
	}
	submission := signedPrivateSubmission(t, fixture, challenge)
	if _, err := fixture.service.SubmitClaim(context.Background(), fixture.capability, &submission); err == nil {
		t.Fatal("接受了客户端自行选择 nonce 的 challenge")
	}
	if *fixture.processed != 0 {
		t.Fatal("伪造 challenge 到达了 claim processor")
	}
}

func TestPrivateEnrollmentResumesCommittedClaimWithoutTokenAfterInviteExpiry(t *testing.T) {
	fixture := newPrivateServiceFixture(t)
	resumeNow := time.Date(2026, 9, 11, 11, 16, 0, 0, time.UTC)
	material := cloneInviteMaterial(fixture.material)
	material.Status = "reserved"
	coreHash, _ := wire.EnrollmentClaimCoreHash(&fixture.core)
	identityHash, wrappingHash, csrHash, err := wire.EnrollmentClaimBinaryHashes(&fixture.core)
	if err != nil {
		t.Fatal(err)
	}
	body := fixture.capability.Body()
	body.Mode = "resume_committed_claim"
	body.ResumeBinding = &wire.BootstrapCapabilityResumeBindingV1{
		RequestID:          fixture.core.RequestID,
		ClaimOperationHash: wire.HashRaw("private-service-test", []byte("resume-claim-operation")),
		AdmissionQCHash:    wire.HashRaw("private-service-test", []byte("resume-admission-qc")),
		ClaimCoreHash:      coreHash, CSRHash: csrHash, IdentityKeyHash: identityHash,
		WrappingKeyHash: wrappingHash, EnrollmentTransactionStateHash: wire.HashRaw("private-service-test", []byte("resume-transaction")),
	}
	body.IssuedAt = resumeNow.Format(time.RFC3339)
	body.NotBefore = body.IssuedAt
	body.ExpiresAt = resumeNow.Add(5 * time.Minute).Format(time.RFC3339)
	capability, err := wire.SignBootstrapCapability(body, fixture.issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verifiedCapability, err := wire.VerifyCapabilityAuthorizationEvidence(&capability,
		&fixture.issuerProof, &material.Policy, resumeNow)
	if err != nil {
		t.Fatal(err)
	}
	processed := 0
	replay, err := OpenChallengeReplayStore(filepath.Join(t.TempDir(), "resume-challenge.json"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewPrivateService("cluster", "enrollment-service", func() time.Time { return resumeNow },
		bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)), time.Minute, replay,
		func(context.Context, string, string) (InviteMaterialV2, error) { return material, nil },
		func(_ context.Context, attempt VerifiedClaimAttemptV2) (wire.EnrollmentClaimResultV2, error) {
			processed++
			if attempt.Submission().Token != "" || attempt.Claim().TokenCommitment() != material.Record.TokenCommitment {
				t.Fatal("token-free resume attempt 未保持 commitment 或仍携 token")
			}
			return wire.EnrollmentClaimResultV2{Schema: 2, Status: "reserved",
				TransactionStateHash: body.ResumeBinding.EnrollmentTransactionStateHash}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := service.Challenge(context.Background(), verifiedCapability, &fixture.core)
	if err != nil {
		t.Fatal(err)
	}
	resume := signedPrivateResumeSubmission(t, fixture, challenge, resumeNow)
	result, err := service.SubmitResume(context.Background(), verifiedCapability, &resume)
	if err != nil || result.Status != "reserved" || processed != 1 {
		t.Fatalf("过期 Invite 的 exact resume 未继续: result=%#v processed=%d err=%v", result, processed, err)
	}
	initial := wire.EnrollmentClaimSubmissionV2{
		Schema: 2, Token: fixture.token, ClaimCore: resume.ClaimCore,
		Challenge: resume.Challenge, PoPBody: resume.PoPBody, ProofSignature: resume.ProofSignature,
	}
	if _, err := service.SubmitClaim(context.Background(), verifiedCapability, &initial); err == nil {
		t.Fatal("resume capability 接受了重新出示 token 的 initial claim wire")
	}
}

func TestPrivateEnrollmentHTTPRequiresVerifiedOuterContextAndInnerTLS(t *testing.T) {
	fixture := newPrivateServiceFixture(t)
	value := wire.EnrollmentIntentPreflightRequestV1{
		Schema: 1, ClusterID: "cluster", InviteID: "invite",
		CertifiedInviteRecordHash: fixture.capability.Body().CommittedInviteRecordHash,
		CapabilityID:              fixture.capability.CapabilityID(),
	}
	body, _ := wire.MarshalCanonical(value)
	request := httptest.NewRequest(http.MethodPost, "https://10.30.0.1/v2/enrollment/preflight", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}

	direct := httptest.NewRecorder()
	fixture.service.ServeHTTP(direct, request.Clone(request.Context()))
	if direct.Code != http.StatusForbidden {
		t.Fatalf("未经过 outer verifier 的直接挂载返回 %d", direct.Code)
	}

	verified := httptest.NewRecorder()
	fixture.service.ServeVerifiedHTTP(verified, request, fixture.capability)
	if verified.Code != http.StatusOK || verified.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("verified private request status=%d body=%s", verified.Code, verified.Body.String())
	}
	var response wire.EnrollmentIntentPreflightResponseV1
	canonical, err := wire.DecodeStrict(verified.Body.Bytes(), 1<<20, &response)
	if err != nil || !bytes.Equal(canonical, verified.Body.Bytes()) {
		t.Fatalf("response 不是 exact canonical wire: %v", err)
	}

	cleartext := httptest.NewRequest(http.MethodPost, "http://10.30.0.1/v2/enrollment/preflight", bytes.NewReader(body))
	cleartext.Header.Set("Content-Type", "application/json")
	denied := httptest.NewRecorder()
	fixture.service.ServeVerifiedHTTP(denied, cleartext, fixture.capability)
	if denied.Code != http.StatusForbidden {
		t.Fatal("private Enrollment 接受了无 inner TLS 请求")
	}
}

func TestPrivateEnrollmentArtifactReleaseRequiresCompletedCapabilityContext(t *testing.T) {
	fixture := newPrivateServiceFixture(t)
	attempt := verifiedPrivateAttempt(t, fixture)
	ref, envelope := sealedArtifactForAttempt(t, attempt)
	material := cloneInviteMaterial(fixture.material)
	material.Status = "completed"
	replay, err := OpenChallengeReplayStore(filepath.Join(t.TempDir(), "artifact-challenges.json"))
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	service, err := NewPrivateServiceWithReleasedArtifacts("cluster", "enrollment-service",
		func() time.Time { return fixture.now }, bytes.NewReader(bytes.Repeat([]byte{0x65}, 128)),
		time.Minute, replay,
		func(context.Context, string, string) (InviteMaterialV2, error) { return material, nil },
		func(context.Context, VerifiedClaimAttemptV2) (wire.EnrollmentClaimResultV2, error) {
			return wire.EnrollmentClaimResultV2{}, context.Canceled
		},
		func(_ context.Context, clusterID, inviteID, digest string) (wire.SealedSecretEnvelopeV1, error) {
			reads++
			if clusterID != "cluster" || inviteID != "invite" || digest != ref.SealedBlob.CiphertextDigest {
				return wire.SealedSecretEnvelopeV1{}, context.Canceled
			}
			return envelope, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := wire.ParseHash(ref.SealedBlob.CiphertextDigest)
	path := PrivateEnrollmentArtifactPathPrefix + hex.EncodeToString(digest)
	request := httptest.NewRequest(http.MethodGet, "https://10.30.0.1"+path, nil)
	request.Header.Set("Accept", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	response := httptest.NewRecorder()
	service.ServeVerifiedHTTP(response, request, fixture.capability)
	if response.Code != http.StatusOK || reads != 1 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("completed artifact release status=%d reads=%d body=%s", response.Code, reads, response.Body.String())
	}
	var got wire.SealedSecretEnvelopeV1
	canonical, err := wire.DecodeStrict(response.Body.Bytes(), maximumSealedArtifactBytes, &got)
	if err != nil || !bytes.Equal(canonical, response.Body.Bytes()) || !wire.EqualCanonical(got, envelope) {
		t.Fatalf("artifact response 不是 exact envelope: value=%#v err=%v", got, err)
	}

	material.Status = "issued_provisional"
	denied := httptest.NewRecorder()
	service.ServeVerifiedHTTP(denied, request.Clone(request.Context()), fixture.capability)
	if denied.Code != http.StatusForbidden || reads != 1 {
		t.Fatalf("completion 前读取未被拒绝: status=%d reads=%d", denied.Code, reads)
	}
	direct := httptest.NewRecorder()
	service.ServeHTTP(direct, request.Clone(request.Context()))
	if direct.Code != http.StatusForbidden {
		t.Fatalf("未经过 outer verifier 的 artifact 返回 %d", direct.Code)
	}
}

func TestAdmissionVoterIndependentlyVerifiesPrivateSubmission(t *testing.T) {
	fixture := newPrivateServiceFixture(t)
	attempt := verifiedPrivateAttempt(t, fixture)
	attestation, err := attempt.AdmissionAttestation()
	if err != nil {
		t.Fatal(err)
	}
	set, member, enrollmentKey := controlSet(t)
	voter, err := NewAdmissionVoter(member.MemberID, set, enrollmentKey, func() time.Time { return fixture.now },
		func(_ context.Context, clusterID, inviteID string) (InviteMaterialV2, error) {
			if clusterID != fixture.material.Record.ClusterID || inviteID != fixture.material.Record.InviteID {
				return InviteMaterialV2{}, context.Canceled
			}
			return fixture.material, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	request := EnrollmentAdmissionVoteRequestV1{Schema: 1, EnrollmentServiceID: "enrollment-service",
		Submission: attempt.Submission(), Attestation: attestation}
	signature, err := voter.VoteAdmission(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.VerifyEnrollmentAdmissionSignature(&attestation, &signature, &set); err != nil {
		t.Fatal(err)
	}
	tampered := request
	tampered.Submission.Token = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x45}, 32))
	if _, err := voter.VoteAdmission(context.Background(), tampered); err == nil {
		t.Fatal("peer voter 信任 ingress，接受了不同 token preimage")
	}
	expired, err := NewAdmissionVoter(member.MemberID, set, enrollmentKey,
		func() time.Time { return time.Date(2026, 9, 11, 11, 15, 0, 0, time.UTC) },
		func(context.Context, string, string) (InviteMaterialV2, error) { return fixture.material, nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := expired.VoteAdmission(context.Background(), request); err == nil {
		t.Fatal("peer voter 在 Invite expiry 后签发了新 admission")
	}
}

func newPrivateServiceFixture(t *testing.T) privateServiceFixture {
	t.Helper()
	now := time.Date(2026, 9, 11, 11, 5, 0, 0, time.UTC)
	deviceProfile, deviceIssuerKey := activeEnrollmentProfile(t)
	deviceProfileHash, err := wire.DeviceCertificateProfileStateHash(&deviceProfile)
	if err != nil {
		t.Fatal(err)
	}
	set, member, _ := controlSet(t)
	setHash := mustSetHash(t, &set)
	bootstrapHead := privateTestHead(t, setHash, wire.EmptyHashV1, wire.EmptyHashV1,
		wire.HashRaw("private-service-test", []byte("bootstrap-operations")),
		wire.HashRaw("private-service-test", []byte("issuer-root")), "bootstrap", 1, "2026-09-11T11:00:00Z")
	bootstrapSignature, err := wire.SignHeadAttestation(wire.AttestationForHead(&bootstrapHead), member, privateEd25519(2))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapQC, err := wire.MarshalCanonical(wire.StableQC(&bootstrapHead,
		[]wire.ControlConfigSignatureV1{bootstrapSignature}))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapListener := wire.ListenerGenerationV2{
		Schema: 2, ListenerGeneration: 1, PublishedState: "preferred", DialTargetFQDN: "bootstrap.example.test",
		PublicPort: 8443, AddressFamilies: []string{"ipv4"},
		TransportIdentityRefs: []string{"profile:bootstrap-webpki-v1", wire.HashRaw("private-service-test", []byte("bootstrap-spki"))},
		CredentialGeneration:  1, CertificateIdentityProjectionHash: wire.HashRaw("private-service-test", []byte("bootstrap-certificate")),
		PublicProfileGeneration: 1, IntroducedRevision: 1, ValidFrom: "2026-09-11T11:00:00Z",
		ValidUntil: "2026-09-12T11:00:00Z", RotationOperationHash: wire.HashRaw("private-service-test", []byte("bootstrap-rotation")),
	}
	bootstrapIngress := wire.BootstrapIngressEndpointSetV1{
		Schema: 1, ClusterID: "cluster", EndpointSetID: "bootstrap-ingress", Generation: 1,
		ValidFrom: "2026-09-11T11:00:00Z", ValidUntil: "2026-09-12T11:00:00Z",
		Endpoints: []wire.BootstrapIngressEndpointV1{{EndpointID: "bootstrap-edge", LogicalServerID: "bootstrap-server",
			Transport: "hysteria2", HintRank: 0, ListenerGenerations: []wire.ListenerGenerationV2{bootstrapListener},
			ListenerTombstones: []wire.ListenerGenerationTombstoneV1{}}},
		ParentHeadHash: bootstrapHead.HeadHash, ConfigQC: bootstrapQC,
	}
	bootstrapIngressHash, err := wire.BootstrapIngressSetHash(&bootstrapIngress)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapQCHash, err := wire.ConfigQCHash(bootstrapQC)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapCatalog := wire.BootstrapEndpointCatalogV1{
		Schema: 1, ClusterID: "cluster", CatalogGeneration: 1,
		ValidFrom: "2026-09-11T11:00:00Z", ValidUntil: "2026-09-12T11:00:00Z",
		BootstrapIngressSet: bootstrapIngress, BootstrapIngressSetHash: bootstrapIngressHash,
		RequiredClientProtocol: 2, ParentHeadHash: bootstrapHead.HeadHash, ConfigQCHash: bootstrapQCHash,
	}
	bootstrapCatalogHash, err := wire.BootstrapEndpointCatalogHash(&bootstrapCatalog)
	if err != nil {
		t.Fatal(err)
	}

	policy := wire.InviteIssuancePolicyV2{
		Schema: 2, ClusterID: "cluster", PolicyID: "invite-policy", Generation: 1,
		MinimumTTLSeconds: 300, MaximumTTLSeconds: 1800, MaximumDescriptorBytes: 65536,
		MaximumIntentOpeningBytes: 65536, MinimumDistributionMirrors: 2, MaximumDistributionMirrors: 3,
		AllowedBootstrapTransports:         []string{"hysteria2", "trojan_tls"},
		MaximumInitialCapabilityTTLSeconds: 900, MaximumResumeCapabilityTTLSeconds: 900,
		MaximumReservationRetrySeconds: 1800, BootstrapSessionSeconds: 180,
		BootstrapTotalBytes: 8 << 20, BootstrapConnectionAttempts: 3, BootstrapMaxConcurrentSessions: 1,
	}
	policyHash, _ := wire.InviteIssuancePolicyHash(&policy)
	intent := wire.DeviceEnrollmentIntentV1{
		Schema: 1, ClusterID: "cluster", InviteID: "invite", DeviceID: "linux-device", Platform: "linux-server",
		DeviceCertificateProfileRef: wire.DeviceCertificateProfileRefV1{
			ProfileID: deviceProfile.ProfileID, Generation: deviceProfile.Generation,
			DeviceCertificateProfileIntentHash: deviceProfile.DeviceCertificateProfileIntentHash,
			DeviceCertificateProfileStateHash:  deviceProfileHash,
		},
		WrappingKeyProfiles: []string{"p256-root-only-pkcs8-ecdh-v1"},
		Membership:          wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"},
		Responsibilities:    wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}},
		Grants:              wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}},
	}
	intentHash, _ := wire.EnrollmentIntentHash(&intent)
	opening := wire.DeviceEnrollmentIntentOpeningV1{
		Schema: 1, ClusterID: "cluster", InviteID: "invite", DeviceEnrollmentIntent: intent,
		DeviceEnrollmentIntentHash: intentHash, HidingNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	commitment, commitmentHash, err := wire.IntentCommitment(&opening)
	if err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32))
	tokenCommitment, _ := wire.TokenCommitment("cluster", "invite", token)

	issuerSeed := bytes.Repeat([]byte{0x21}, ed25519.SeedSize)
	issuerPrivate := ed25519.NewKeyFromSeed(issuerSeed)
	issuerPublic := issuerPrivate.Public().(ed25519.PublicKey)
	issuerKeyID, _ := wire.ControlKeyID(issuerPublic)
	ingressHash := bootstrapIngressHash
	authorization := wire.BootstrapIssuerAuthorizationV1{
		Schema: 1, ClusterID: "cluster", AuthorizationID: "bootstrap-issuer", Generation: 1, Status: "active",
		Active: &wire.BootstrapIssuerAuthorizationActiveV1{
			IssuerEpoch: 1, IssuerKeyID: issuerKeyID, IssuerPublicKey: base64.RawURLEncoding.EncodeToString(issuerPublic),
			InviteIssuancePolicyHash: policyHash, ValidFrom: "2026-09-11T11:00:00Z", ValidUntil: "2026-09-12T11:00:00Z",
			MaximumCapabilityTTLSeconds: 900, MaximumConnectionAttempts: 3, MaximumConcurrentSessions: 1,
			MaximumSessionSeconds: 180, MaximumTotalBytes: 8 << 20, PermittedIngressSetHashes: []string{ingressHash},
			PermittedServiceIDs: []string{"enrollment-service"}, PermittedModes: []string{"initial_claim", "resume_committed_claim"},
		},
		ParentHeadHash: bootstrapHead.HeadHash,
	}
	authorizationHash, _ := wire.BootstrapIssuerAuthorizationHash(&authorization)
	authorizationLeaf := wire.BootstrapIssuerAuthorizationLeafV1{
		Schema: 1, AuthorizationID: authorization.AuthorizationID, Generation: 1, AuthorizationHash: authorizationHash,
	}
	authorizationLeafBytes, _ := wire.MarshalCanonical(authorizationLeaf)
	authorizationRoot := "sha256:" + hex.EncodeToString(wire.MerkleRoot([][]byte{authorizationLeafBytes}))
	authorizationProof := wire.BootstrapIssuerAuthorizationProofV1{
		Schema: 1, ClusterID: "cluster", Authorization: authorization, AuthorizationHash: authorizationHash,
		Leaf: authorizationLeaf, LeafIndex: 0, RegistryTreeSize: 1, RegistryAuditPath: []string{}, RegistryRoot: authorizationRoot,
	}
	authorityHead := privateTestHead(t, setHash, bootstrapHead.EntryHash, bootstrapHead.HeadHash,
		wire.HashRaw("private-service-test", []byte("authorization-operation")), authorizationRoot,
		"ordinary", 2, "2026-09-11T11:00:01Z")
	serviceRef := wire.PrivateEnrollmentServiceRefV1{
		Schema: 1, ServiceID: "enrollment-service", OverlayIP: "10.30.0.1", TCPPort: 7444,
		InternalCAProfileRef: "enrollment-internal-ca", ServerIdentitySPKIPins: []string{
			wire.HashRaw("private-service-test", []byte("enrollment-service-spki")),
		}, ServiceGeneration: 1,
	}
	serviceHash, err := wire.PrivateEnrollmentServiceRefHash(&serviceRef)
	if err != nil {
		t.Fatal(err)
	}
	record := wire.CertifiedInviteRecordV2{
		Schema: 2, ClusterID: "cluster", InviteID: "invite", Generation: 1,
		IssuedAt: "2026-09-11T11:00:00Z", ExpiresAt: "2026-09-11T11:15:00Z",
		DeviceEnrollmentIntentCommitmentHash: commitmentHash, TokenCommitment: tokenCommitment,
		TokenArtifactBindingHash: wire.HashRaw("private-service-test", []byte("token-artifact")),
		InviteIssuancePolicyHash: policyHash, BootstrapIssuerAuthorizationHash: authorizationHash,
		BootstrapIssuerRegistryRoot: authorizationRoot, BootstrapCatalogHash: bootstrapCatalogHash,
		EnrollmentServiceRefHash: serviceHash, OperationID: "invite-operation", ParentHeadHash: authorityHead.HeadHash,
	}
	recordHash, _ := wire.CertifiedInviteRecordHash(&record, &policy)
	operationLeaf := wire.ControlOperationLeafV1{Schema: 1, OperationID: record.OperationID, ObjectID: recordHash}
	operationLeafBytes, _ := wire.MarshalCanonical(operationLeaf)
	operationRoot := "sha256:" + hex.EncodeToString(wire.MerkleRoot([][]byte{operationLeafBytes}))
	recordHead := privateTestHead(t, setHash, authorityHead.EntryHash, authorityHead.HeadHash,
		operationRoot, authorizationRoot, "ordinary", 3, "2026-09-11T11:00:02Z")
	configPrivate := privateEd25519(2)
	configSignature, err := wire.SignHeadAttestation(wire.AttestationForHead(&recordHead), member, configPrivate)
	if err != nil {
		t.Fatal(err)
	}
	recordHeadQC, _ := wire.MarshalCanonical(wire.StableQC(&recordHead, []wire.ControlConfigSignatureV1{configSignature}))

	capabilityBody := wire.BootstrapTunnelCapabilityBodyV1{
		Schema: 1, ClusterID: "cluster", InviteID: "invite", CommittedInviteRecordHash: recordHash,
		InviteIssuancePolicyHash: policyHash, BootstrapIssuerAuthorizationHash: authorizationHash,
		BootstrapIssuerRegistryRoot: authorizationRoot, EnrollmentServiceRefHash: serviceHash, Mode: "initial_claim",
		IssuedAt: "2026-09-11T11:00:00Z", NotBefore: "2026-09-11T11:00:00Z", ExpiresAt: "2026-09-11T11:15:00Z",
		AllowedIngressSetHash: ingressHash, AllowedServiceID: "enrollment-service", AllowedDestinationIP: "10.30.0.1",
		AllowedDestinationPrefixLength: 32, AllowedDestinationPort: 7444, AllowedInsideTransport: "tcp",
		MaximumConnectionAttempts: 3, MaximumConcurrentSessions: 1, MaximumSessionSeconds: 180,
		MaximumTotalBytes: 8 << 20, IssuerEpoch: 1, IssuerKeyID: issuerKeyID,
	}
	capability, err := wire.SignBootstrapCapability(capabilityBody, issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verifiedCapability, err := wire.VerifyCapabilityAuthorizationEvidence(&capability, &authorizationProof, &policy, now)
	if err != nil {
		t.Fatal(err)
	}

	identity, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrapping, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	identitySPKI, _ := x509.MarshalPKIXPublicKey(&identity.PublicKey)
	wrappingSPKI, _ := x509.MarshalPKIXPublicKey(&wrapping.PublicKey)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "request"}}, identity)
	openingHash, _ := wire.IntentOpeningHash(&opening)
	core := wire.EnrollmentClaimCoreV2{
		Schema: 2, ClusterID: "cluster", InviteID: "invite", RequestID: "request",
		CertifiedInviteRecordHash: recordHash, DeviceEnrollmentIntentCommitmentHash: commitmentHash,
		DeviceEnrollmentIntentOpeningHash: openingHash, AcceptedDeviceEnrollmentIntentHash: intentHash,
		ClientPlatform: "linux-server", BaseRecoveryEpoch: recordHead.Body.Payload.RecoveryEpoch,
		BaseControlEpoch: recordHead.Body.Payload.ControlEpoch, BaseControlSetHash: setHash, BaseHeadHash: recordHead.HeadHash,
		DeviceIdentityPublicKey:  base64.RawURLEncoding.EncodeToString(identitySPKI),
		DeviceIdentityKeyProfile: "p256-root-only-pkcs8-sha256-v1",
		WrappingPublicKey:        base64.RawURLEncoding.EncodeToString(wrappingSPKI), WrappingKeyProfile: "p256-root-only-pkcs8-ecdh-v1",
		CSRDER: base64.RawURLEncoding.EncodeToString(csrDER), ClientNonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32)),
	}
	material := InviteMaterialV2{
		Status: "available", Record: record, Policy: policy, Commitment: commitment, Opening: opening,
		EnrollmentServiceRef: serviceRef,
		ParentHead:           authorityHead, RecordHead: recordHead, RecordHeadQC: recordHeadQC, ControlSet: set, InviteOperationLeaf: operationLeaf,
		InviteLeafIndex: 0, InviteTreeSize: 1, InviteAuditPath: []string{},
	}
	processed := 0
	replay, err := OpenChallengeReplayStore(filepath.Join(t.TempDir(), "challenge.json"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewPrivateService("cluster", "enrollment-service", func() time.Time { return now },
		bytes.NewReader(bytes.Repeat([]byte{0x33}, 1024)), time.Minute, replay,
		func(_ context.Context, clusterID, inviteID string) (InviteMaterialV2, error) {
			if clusterID != "cluster" || inviteID != "invite" {
				return InviteMaterialV2{}, context.Canceled
			}
			return material, nil
		},
		func(_ context.Context, attempt VerifiedClaimAttemptV2) (wire.EnrollmentClaimResultV2, error) {
			processed++
			attestation, err := attempt.AdmissionAttestation()
			if err != nil || attestation.ClaimCoreHash != attempt.Claim().ClaimCoreHash() ||
				attestation.IdentityKeyHash != attempt.Claim().IdentityKeyHash() {
				t.Fatalf("admission attestation 未绑定 verified claim: %#v err=%v", attestation, err)
			}
			return wire.EnrollmentClaimResultV2{Schema: 2, Status: "reserved",
				TransactionStateHash: wire.HashRaw("private-service-test", []byte("transaction"))}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	return privateServiceFixture{now: now, service: service, capability: verifiedCapability, material: material,
		core: core, identity: identity, issuerPrivate: issuerPrivate, issuerProof: authorizationProof,
		deviceProfile: deviceProfile, deviceIssuerKey: deviceIssuerKey,
		bootstrapCatalog: bootstrapCatalog, bootstrapCatalogHead: bootstrapHead, token: token, processed: &processed}
}

func signedPrivateSubmission(t *testing.T, fixture privateServiceFixture,
	challenge wire.EnrollmentPoPChallengeV1) wire.EnrollmentClaimSubmissionV2 {
	t.Helper()
	coreHash, err := wire.EnrollmentClaimCoreHash(&fixture.core)
	if err != nil {
		t.Fatal(err)
	}
	challengeHash, err := wire.EnrollmentChallengeHash(&challenge, coreHash, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	pop := wire.EnrollmentPoPBodyV2{
		Schema: 2, ClusterID: "cluster", InviteID: "invite", RequestID: fixture.core.RequestID,
		ClaimCoreHash: coreHash, TokenCommitment: fixture.material.Record.TokenCommitment, ChallengeHash: challengeHash,
	}
	signature, err := wire.SignEnrollmentPoPP256(&pop, fixture.identity)
	if err != nil {
		t.Fatal(err)
	}
	return wire.EnrollmentClaimSubmissionV2{
		Schema: 2, Token: fixture.token, ClaimCore: fixture.core, Challenge: challenge, PoPBody: pop, ProofSignature: signature,
	}
}

func signedPrivateResumeSubmission(t *testing.T, fixture privateServiceFixture,
	challenge wire.EnrollmentPoPChallengeV1, now time.Time) wire.EnrollmentResumeSubmissionV1 {
	t.Helper()
	coreHash, err := wire.EnrollmentClaimCoreHash(&fixture.core)
	if err != nil {
		t.Fatal(err)
	}
	challengeHash, err := wire.EnrollmentChallengeHash(&challenge, coreHash, now)
	if err != nil {
		t.Fatal(err)
	}
	pop := wire.EnrollmentPoPBodyV2{
		Schema: 2, ClusterID: fixture.core.ClusterID, InviteID: fixture.core.InviteID,
		RequestID: fixture.core.RequestID, ClaimCoreHash: coreHash,
		TokenCommitment: fixture.material.Record.TokenCommitment, ChallengeHash: challengeHash,
	}
	signature, err := wire.SignEnrollmentPoPP256(&pop, fixture.identity)
	if err != nil {
		t.Fatal(err)
	}
	return wire.EnrollmentResumeSubmissionV1{
		Schema: 1, ClaimCore: fixture.core, Challenge: challenge,
		PoPBody: pop, ProofSignature: signature,
	}
}

func privateTestHead(t *testing.T, setHash, previousEntryHash, parentHeadHash, operationRoot, issuerRoot, kind string,
	index int64, committedAt string) wire.HeadEntryV2 {
	t.Helper()
	transition, _ := json.Marshal(wire.OrdinaryHeadContextV1{Schema: 1, Kind: "ordinary"})
	transitionProofHash := wire.HashRaw("private-service-test", []byte("transition-proof"))
	if kind == "bootstrap" {
		transition, _ = json.Marshal(wire.BootstrapHeadContextV1{
			Schema: 1, Kind: "bootstrap", InitialV2HeadPayloadHash: wire.HashRaw("private-service-test", []byte("initial")),
		})
	}
	entry, err := wire.NewHeadEntry(wire.HeadEntryBodyV2{Payload: wire.HeadEntryPayloadV2{
		Schema: 2, HeadKind: kind, ClusterID: "cluster", RecoveryEpoch: 0,
		RecoveryStatementHash: wire.HashRaw("private-service-test", []byte("recovery")),
		RecoveryPolicyHash:    wire.HashRaw("private-service-test", []byte("recovery-policy")),
		ControlEpoch:          0, ControlSetHash: setHash,
		ControlPeerDirectoryHash: wire.HashRaw("private-service-test", []byte("directory")),
		RaftTerm:                 1, RaftIndex: index, PreviousLogEntryHash: previousEntryHash, ControlRevision: index,
		ParentHeadHash: parentHeadHash, OperationRoot: operationRoot,
		SnapshotHash:                wire.HashRaw("private-service-test", []byte("snapshot")),
		EffectiveSSOTHash:           wire.HashRaw("private-service-test", []byte("ssot")),
		DeviceViewsRoot:             wire.HashRaw("private-service-test", []byte("device-views")),
		AdminACLRoot:                wire.HashRaw("private-service-test", []byte("admin")),
		CAProfileRoot:               wire.HashRaw("private-service-test", []byte("ca")),
		BootstrapIssuerRegistryRoot: issuerRoot,
		RenderContractVersion:       2, MinReaderVersion: 2, CommittedLogicalTime: committedAt,
		MaxClockSkewSeconds: 30, TransitionContext: transition,
	}, TransitionProofHash: transitionProofHash})
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func privateEd25519(marker byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	seed[len(seed)-1] = marker
	return ed25519.NewKeyFromSeed(seed)
}
