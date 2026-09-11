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
	now        time.Time
	service    *PrivateService
	capability wire.VerifiedBootstrapCapabilityV1
	material   InviteMaterialV2
	core       wire.EnrollmentClaimCoreV2
	identity   *ecdsa.PrivateKey
	token      string
	processed  *int
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

func newPrivateServiceFixture(t *testing.T) privateServiceFixture {
	t.Helper()
	now := time.Date(2026, 9, 11, 11, 5, 0, 0, time.UTC)
	set, member, _ := controlSet(t)
	setHash := mustSetHash(t, &set)
	bootstrapHead := privateTestHead(t, setHash, wire.EmptyHashV1, wire.EmptyHashV1,
		wire.HashRaw("private-service-test", []byte("bootstrap-operations")),
		wire.HashRaw("private-service-test", []byte("issuer-root")), "bootstrap", 1, "2026-09-11T11:00:00Z")

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
			ProfileID: "device-profile", Generation: 1,
			DeviceCertificateProfileIntentHash: wire.HashRaw("private-service-test", []byte("profile-intent")),
			DeviceCertificateProfileStateHash:  wire.HashRaw("private-service-test", []byte("profile-state")),
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
	ingressHash := wire.HashRaw("private-service-test", []byte("ingress"))
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
	serviceHash := wire.HashRaw("private-service-test", []byte("service-ref"))
	record := wire.CertifiedInviteRecordV2{
		Schema: 2, ClusterID: "cluster", InviteID: "invite", Generation: 1,
		IssuedAt: "2026-09-11T11:00:00Z", ExpiresAt: "2026-09-11T11:15:00Z",
		DeviceEnrollmentIntentCommitmentHash: commitmentHash, TokenCommitment: tokenCommitment,
		TokenArtifactBindingHash: wire.HashRaw("private-service-test", []byte("token-artifact")),
		InviteIssuancePolicyHash: policyHash, BootstrapIssuerAuthorizationHash: authorizationHash,
		BootstrapIssuerRegistryRoot: authorizationRoot, BootstrapCatalogHash: wire.HashRaw("private-service-test", []byte("catalog")),
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
		ParentHead: authorityHead, RecordHead: recordHead, RecordHeadQC: recordHeadQC, ControlSet: set, InviteOperationLeaf: operationLeaf,
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
		core: core, identity: identity, token: token, processed: &processed}
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
