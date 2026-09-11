package enrollmentv2

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestDurableStoreMakesReservationReplayIdempotent(t *testing.T) {
	set, invite, claim, admission := reservationFixture(t)
	path := filepath.Join(t.TempDir(), "transactions.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Reserve(invite, claim, admission, &set, claim.ReservedAt)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := reopened.Reserve(invite, claim, admission, &set, claim.ReservedAt)
	if err != nil || !wire.EqualCanonical(first, replayed) {
		t.Fatalf("相同 reservation 重启重放未返回同一结果: %#v, %v", replayed, err)
	}
	competing := claim
	competing.RequestID = "different-request"
	if _, err := reopened.Reserve(invite, competing, admission, &set, competing.ReservedAt); err == nil {
		t.Fatal("同一 token 的不同 request 绕过耐久 CAS")
	}
}

func TestDurableStoreRejectsCorruptOrdering(t *testing.T) {
	set, invite, claim, admission := reservationFixture(t)
	path := filepath.Join(t.TempDir(), "transactions.json")
	store, _ := OpenStore(path)
	if _, err := store.Reserve(invite, claim, admission, &set, claim.ReservedAt); err != nil {
		t.Fatal(err)
	}
	body, err := wire.MarshalCanonical(durableState{Schema: 2, Records: []DurableRecord{
		{InviteID: "z", TokenCommitment: hash, State: TransactionStateV2{Schema: 2, ClusterID: "cluster", InviteID: "z", RequestID: "r", Status: "reserved", ClaimCoreHash: hash, IdentityKeyHash: hash, WrappingKeyHash: hash, ClaimOperationHash: hash}},
		{InviteID: "a", TokenCommitment: wire.EmptyHashV1, State: TransactionStateV2{Schema: 2, ClusterID: "cluster", InviteID: "a", RequestID: "r", Status: "reserved", ClaimCoreHash: hash, IdentityKeyHash: hash, WrappingKeyHash: hash, ClaimOperationHash: hash}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(path); err == nil {
		t.Fatal("接受了乱序的耐久 transaction records")
	}
}

func TestDurableStoreRecoversExactProvisionalAndCompletionArtifacts(t *testing.T) {
	set, invite, claim, admission := reservationFixture(t)
	path := filepath.Join(t.TempDir(), "transactions.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := store.Reserve(invite, claim, admission, &set, claim.ReservedAt)
	if err != nil {
		t.Fatal(err)
	}
	profile, issuerKey := activeEnrollmentProfile(t)
	profileHash, _ := wire.DeviceCertificateProfileStateHash(&profile)
	body := wire.EnrollmentProvisionalIssuanceBodyV1{
		Schema: 1, ClusterID: claim.ClusterID, InviteID: claim.InviteID, RequestID: claim.RequestID,
		ClaimOperationHash: reserved.ClaimOperationHash, ReservationHeadHash: hash,
		ReservationHeadQCHash: hash, DeviceCertificateHash: hash, InitialDeviceViewHash: hash,
		SecretArtifactRefsRoot: hash, ResultArtifactHash: hash,
		DeviceCertificateProfileStateHash: profileHash,
		IssuanceLogCoordinate:             wire.IssuanceLogCoordinateV1{RecoveryEpoch: 0, RaftIndex: 2},
	}
	issuance, err := wire.SignEnrollmentProvisionalIssuance(body, &profile, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuanceHash, _ := wire.EnrollmentProvisionalIssuanceHash(&issuance)
	leaf := wire.EnrollmentIssuanceRegistryLeafV1{Schema: 1,
		ClaimOperationHash: reserved.ClaimOperationHash, ProvisionalIssuanceHash: issuanceHash}
	previousRoot, _ := wire.EnrollmentIssuanceRegistryRoot(nil)
	resultingRoot, _ := wire.EnrollmentIssuanceRegistryRoot([]wire.EnrollmentIssuanceRegistryLeafV1{leaf})
	reservedHash, _ := TransactionHash(reserved)
	provisional := ProvisionalIssuanceOperationV1{
		Schema: 1, ClusterID: claim.ClusterID, OperationID: "issue-op", InviteID: claim.InviteID,
		RequestID: claim.RequestID, ExpectedTransactionStateHash: reservedHash,
		ClaimOperationHash: reserved.ClaimOperationHash, ProvisionalIssuanceHash: issuanceHash,
		IssuanceRegistryLeaf: leaf, PreviousIssuanceRegistryRoot: previousRoot,
		ResultingIssuanceRegistryRoot: resultingRoot, IssuedAt: "2026-01-01T00:11:00Z",
	}
	issued, err := store.RecordProvisional(provisional, issuance, profile)
	if err != nil {
		t.Fatal(err)
	}
	provisionalHash, _ := wire.HashObject(DomainProvisionalOperation, provisional)
	approvalBody := wire.EnrollmentApprovalAttestationBodyV2{
		Schema: 2, AttestationType: "enrollment_approval", ClusterID: claim.ClusterID,
		InviteID: claim.InviteID, RequestID: claim.RequestID, ClaimOperationHash: reserved.ClaimOperationHash,
		ProvisionalIssuanceOperationHash: provisionalHash, ProvisionalIssuanceHash: issuanceHash,
		IssuanceHeadHash: hash, IssuanceHeadQCHash: hash, ResultingIssuanceRegistryRoot: resultingRoot,
		DeviceCertificateHash: body.DeviceCertificateHash, InitialDeviceViewHash: body.InitialDeviceViewHash,
		SecretArtifactRefsRoot: body.SecretArtifactRefsRoot, ResultArtifactHash: body.ResultArtifactHash,
	}
	_, member, enrollmentKey := controlSet(t)
	approvalSignature, err := wire.SignEnrollmentApproval(approvalBody, member, enrollmentKey)
	if err != nil {
		t.Fatal(err)
	}
	approval := wire.StableEnrollmentApprovalQC(approvalBody, []wire.ControlEnrollmentSignatureV1{approvalSignature})
	approvalHash, _ := wire.EnrollmentApprovalQCHash(&approval)
	issuedHash, _ := TransactionHash(issued)
	completion := CompletionOperationV2{
		Schema: 2, ClusterID: claim.ClusterID, OperationID: "complete-op", InviteID: claim.InviteID,
		RequestID: claim.RequestID, ExpectedTransactionStateHash: issuedHash,
		ClaimOperationHash: reserved.ClaimOperationHash, ProvisionalIssuanceOperationHash: provisionalHash,
		ProvisionalIssuanceHash: issuanceHash, ResultingIssuanceRegistryRoot: resultingRoot,
		EnrollmentApprovalQCHash: approvalHash, ResultArtifactHash: body.ResultArtifactHash,
	}
	completed, err := store.Complete(completion, &approval, &set)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	record, found := reopened.SnapshotRecord(invite.InviteID)
	if !found || !wire.EqualCanonical(record.State, completed) || record.ProvisionalIssuance == nil ||
		record.CompletionOperation == nil || !wire.EqualCanonical(*record.ProvisionalIssuance, issuance) {
		t.Fatalf("重启未恢复 exact enrollment artifacts: found=%v record=%#v", found, record)
	}
}

func reservationFixture(t *testing.T) (wire.ControlSetV1, InviteContext, ClaimOperationV2, *wire.StableEnrollmentAdmissionQCV1) {
	t.Helper()
	set, member, enrollmentKey := controlSet(t)
	invite := InviteContext{
		ClusterID: "cluster", InviteID: "invite", Status: "available", CertifiedInviteRecordHash: hash,
		DeviceEnrollmentIntentCommitmentHash: hash, DeviceEnrollmentIntentOpeningHash: hash,
		TokenCommitment: hash, ExpiresAt: "2026-01-01T00:10:00Z", MaximumReservationRetrySeconds: 300,
	}
	attestation := wire.EnrollmentAdmissionAttestationBodyV1{
		Schema: 1, AttestationType: "enrollment_admission", ClusterID: "cluster", InviteID: "invite", RequestID: "request",
		CertifiedInviteRecordHash: hash, DeviceEnrollmentIntentCommitmentHash: hash, DeviceEnrollmentIntentOpeningHash: hash,
		TokenCommitment: hash, ClaimCoreHash: hash, IdentityKeyHash: hash, WrappingKeyHash: hash, CSRHash: hash,
		PoPVerificationProfile: "loom-enrollment-server-nonce-detached-v2", BaseRecoveryEpoch: 0, BaseControlEpoch: 0,
		BaseControlSetHash: mustSetHash(t, &set), BaseHeadHash: hash, AdmissionNotAfter: "2026-01-01T00:10:00Z", RetryNotAfter: "2026-01-01T00:15:00Z",
	}
	signature, err := wire.SignEnrollmentAdmission(attestation, member, enrollmentKey)
	if err != nil {
		t.Fatal(err)
	}
	value := wire.StableEnrollmentAdmissionQC(attestation, []wire.ControlEnrollmentSignatureV1{signature})
	qcHash, _ := wire.EnrollmentAdmissionQCHash(&value)
	claim := ClaimOperationV2{
		Schema: 2, ClusterID: "cluster", OperationID: "claim-op", InviteID: "invite", RequestID: "request",
		CertifiedInviteRecordHash: hash, DeviceEnrollmentIntentCommitmentHash: hash, DeviceEnrollmentIntentOpeningHash: hash,
		TokenCommitment: hash, ClaimCoreHash: hash, AdmissionQCHash: qcHash, IdentityKeyHash: hash, WrappingKeyHash: hash, CSRHash: hash,
		ReservedAt: "2026-01-01T00:09:00Z", RetryNotAfter: "2026-01-01T00:15:00Z",
	}
	return set, invite, claim, &value
}

func activeEnrollmentProfile(t *testing.T) (wire.DeviceCertificateProfileStateV1, ed25519.PrivateKey) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rootPublic, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(800 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	issuerPublic, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "issuer"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(500 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, root, issuerPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := []string{base64.RawURLEncoding.EncodeToString(issuerDER), base64.RawURLEncoding.EncodeToString(rootDER)}
	issuerHash, _ := wire.HashBytes(wire.DomainDeviceIssuerCertificateDER, issuerDER)
	chainHash, _ := wire.HashObject(wire.DomainDeviceIssuerChain, struct {
		Schema         int      `json:"schema"`
		IssuerChainDER []string `json:"issuer_chain_der"`
	}{Schema: 1, IssuerChainDER: chain})
	intent := wire.DeviceCertificateProfileIntentV1{
		Schema: 1, ClusterID: "cluster", ProfileID: "profile", Generation: 1, TargetStatus: "active",
		IssuerID: "issuer", IssuerGeneration: 1, IssuerFencingEpoch: 1,
		IssuanceNotBefore: "2026-01-01T00:00:00Z", IssuanceNotAfter: "2026-12-31T00:00:00Z",
		ProfileKind: "loom-device-x509-v1", IssuerCertificateDER: chain[0], IssuerCertificateHash: issuerHash,
		IssuerChainDER: chain, IssuerChainHash: chainHash, IssuerKeyArtifactHash: hash,
		AllowedPlatforms: []string{"linux-server"}, AllowedResponsibilities: []string{"use_loom"},
		ValiditySeconds: 3600, AllowedSubjectKeyAlgorithm: "p256", SignatureAlgorithm: "ed25519",
		SubjectMode: "empty", SANURIPrefix: "spiffe://cluster.example/device/",
		KeyUsageBits: []string{"digital_signature"}, BasicConstraintsCA: false,
		RequiredEKUOIDs: []string{"1.3.6.1.5.5.7.3.2"}, RequiredPolicyOIDs: []string{"1.3.6.1.4.1.55555.2"},
		ExtensionOrderOIDs: []string{"2.5.29.15", "2.5.29.17", "2.5.29.19", "2.5.29.32", "2.5.29.37"},
	}
	intentHash, err := wire.DeviceCertificateProfileIntentHash(&intent)
	if err != nil {
		t.Fatal(err)
	}
	state := wire.DeviceCertificateProfileStateV1{Schema: 1, ClusterID: intent.ClusterID,
		ProfileID: intent.ProfileID, Generation: intent.Generation, ProfileIntent: intent,
		DeviceCertificateProfileIntentHash: intentHash, Status: "active", StatusChangedAt: "2026-01-01T00:00:00Z"}
	if err := wire.ValidateDeviceCertificateProfileState(&state); err != nil {
		t.Fatal(err)
	}
	return state, issuerKey
}
