package enrollmentv2

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"loom/internal/wire"
)

const hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestEnrollmentFourStageCAS(t *testing.T) {
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
	admissionValue := wire.StableEnrollmentAdmissionQC(attestation, []wire.ControlEnrollmentSignatureV1{signature})
	admission := &admissionValue
	admissionHash, _ := wire.EnrollmentAdmissionQCHash(admission)
	claim := ClaimOperationV2{
		Schema: 2, ClusterID: "cluster", OperationID: "claim-op", InviteID: "invite", RequestID: "request",
		CertifiedInviteRecordHash: hash, DeviceEnrollmentIntentCommitmentHash: hash, DeviceEnrollmentIntentOpeningHash: hash,
		TokenCommitment: hash, ClaimCoreHash: hash, AdmissionQCHash: admissionHash, IdentityKeyHash: hash, WrappingKeyHash: hash, CSRHash: hash,
		ReservedAt: "2026-01-01T00:09:00Z", RetryNotAfter: "2026-01-01T00:15:00Z",
	}
	reserved, err := Reserve(invite, claim, admission, &set, claim.ReservedAt)
	if err != nil {
		t.Fatal(err)
	}
	reservedHash, _ := TransactionHash(reserved)
	registryLeaf := wire.EnrollmentIssuanceRegistryLeafV1{Schema: 1, ClaimOperationHash: reserved.ClaimOperationHash,
		ProvisionalIssuanceHash: hash}
	previousRegistryRoot, _ := wire.EnrollmentIssuanceRegistryRoot(nil)
	resultingRegistryRoot, _ := wire.EnrollmentIssuanceRegistryRoot([]wire.EnrollmentIssuanceRegistryLeafV1{registryLeaf})
	provisional := ProvisionalIssuanceOperationV1{
		Schema: 1, ClusterID: "cluster", OperationID: "issue-op", InviteID: "invite", RequestID: "request",
		ExpectedTransactionStateHash: reservedHash, ClaimOperationHash: reserved.ClaimOperationHash,
		ProvisionalIssuanceHash: hash, IssuanceRegistryLeaf: registryLeaf,
		PreviousIssuanceRegistryRoot:  previousRegistryRoot,
		ResultingIssuanceRegistryRoot: resultingRegistryRoot, IssuedAt: "2026-01-01T00:11:00Z",
	}
	issued, err := RecordProvisional(reserved, provisional)
	if err != nil {
		t.Fatal(err)
	}
	approvalBody := wire.EnrollmentApprovalAttestationBodyV2{
		Schema: 2, AttestationType: "enrollment_approval", ClusterID: "cluster", InviteID: "invite", RequestID: "request",
		ClaimOperationHash: issued.ClaimOperationHash, ProvisionalIssuanceOperationHash: issued.ProvisionalIssuanceOperationHash,
		ProvisionalIssuanceHash: issued.ProvisionalIssuanceHash, IssuanceHeadHash: hash, IssuanceHeadQCHash: hash,
		ResultingIssuanceRegistryRoot: issued.ResultingIssuanceRegistryRoot, DeviceCertificateHash: hash,
		InitialDeviceViewHash: hash, SecretArtifactRefsRoot: hash, ResultArtifactHash: hash,
	}
	approvalSignature, err := wire.SignEnrollmentApproval(approvalBody, member, enrollmentKey)
	if err != nil {
		t.Fatal(err)
	}
	approvalValue := wire.StableEnrollmentApprovalQC(approvalBody, []wire.ControlEnrollmentSignatureV1{approvalSignature})
	approval := &approvalValue
	approvalHash, _ := wire.EnrollmentApprovalQCHash(approval)
	issuedHash, _ := TransactionHash(issued)
	completion := CompletionOperationV2{
		Schema: 2, ClusterID: "cluster", OperationID: "complete-op", InviteID: "invite", RequestID: "request",
		ExpectedTransactionStateHash: issuedHash, ClaimOperationHash: issued.ClaimOperationHash,
		ProvisionalIssuanceOperationHash: issued.ProvisionalIssuanceOperationHash, ProvisionalIssuanceHash: issued.ProvisionalIssuanceHash,
		ResultingIssuanceRegistryRoot: issued.ResultingIssuanceRegistryRoot, EnrollmentApprovalQCHash: approvalHash, ResultArtifactHash: hash,
	}
	completed, err := Complete(issued, completion, approval, &set)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != "completed" || completed.ResultArtifactHash != hash {
		t.Fatalf("not completed: %#v", completed)
	}
}

func TestEnrollmentRejectsCompetingCoreAndWrongPurposeSignature(t *testing.T) {
	set, member, enrollmentKey := controlSet(t)
	attestation := wire.EnrollmentAdmissionAttestationBodyV1{
		Schema: 1, AttestationType: "enrollment_admission", ClusterID: "cluster", InviteID: "invite", RequestID: "request",
		CertifiedInviteRecordHash: hash, DeviceEnrollmentIntentCommitmentHash: hash, DeviceEnrollmentIntentOpeningHash: hash,
		TokenCommitment: hash, ClaimCoreHash: hash, IdentityKeyHash: hash, WrappingKeyHash: hash, CSRHash: hash,
		PoPVerificationProfile: "loom-enrollment-server-nonce-detached-v2", BaseControlSetHash: mustSetHash(t, &set), BaseHeadHash: hash,
		AdmissionNotAfter: "2026-01-01T00:10:00Z", RetryNotAfter: "2026-01-01T00:15:00Z",
	}
	signature, _ := wire.SignEnrollmentAdmission(attestation, member, enrollmentKey)
	qcValue := wire.StableEnrollmentAdmissionQC(attestation, []wire.ControlEnrollmentSignatureV1{signature})
	qc := &qcValue
	qcHash, _ := wire.EnrollmentAdmissionQCHash(qc)
	invite := InviteContext{ClusterID: "cluster", InviteID: "invite", Status: "available", CertifiedInviteRecordHash: hash, DeviceEnrollmentIntentCommitmentHash: hash, DeviceEnrollmentIntentOpeningHash: hash, TokenCommitment: hash, ExpiresAt: "2026-01-01T00:10:00Z", MaximumReservationRetrySeconds: 300}
	claim := ClaimOperationV2{Schema: 2, ClusterID: "cluster", OperationID: "claim", InviteID: "invite", RequestID: "request", CertifiedInviteRecordHash: hash, DeviceEnrollmentIntentCommitmentHash: hash, DeviceEnrollmentIntentOpeningHash: hash, TokenCommitment: hash, ClaimCoreHash: wire.EmptyHashV1, AdmissionQCHash: qcHash, IdentityKeyHash: hash, WrappingKeyHash: hash, CSRHash: hash, ReservedAt: "2026-01-01T00:09:00Z", RetryNotAfter: "2026-01-01T00:15:00Z"}
	if _, err := Reserve(invite, claim, qc, &set, claim.ReservedAt); err == nil {
		t.Fatal("competing claim core accepted")
	}
}

func controlSet(t *testing.T) (wire.ControlSetV1, wire.ControlMemberV1, ed25519.PrivateKey) {
	t.Helper()
	newKey := func(marker byte) (string, string, ed25519.PrivateKey) {
		seed := make([]byte, ed25519.SeedSize)
		seed[len(seed)-1] = marker
		private := ed25519.NewKeyFromSeed(seed)
		public := private.Public().(ed25519.PublicKey)
		id, _ := wire.ControlKeyID(public)
		return id, base64.RawURLEncoding.EncodeToString(public), private
	}
	membershipID, membershipPublic, _ := newKey(1)
	configID, configPublic, _ := newKey(2)
	enrollmentID, enrollmentPublic, enrollmentPrivate := newKey(3)
	member := wire.ControlMemberV1{Schema: 1, ClusterID: "cluster", MemberID: "00000000000000000000000001", MembershipKeyID: membershipID, MembershipPublicKey: membershipPublic, ConfigKeyID: configID, ConfigPublicKey: configPublic, EnrollmentKeyID: enrollmentID, EnrollmentPublicKey: enrollmentPublic, MinimumControlProtocol: 2}
	return wire.ControlSetV1{Schema: 1, ClusterID: "cluster", Members: []wire.ControlMemberV1{member}}, member, enrollmentPrivate
}

func mustSetHash(t *testing.T, set *wire.ControlSetV1) string {
	t.Helper()
	hash, err := wire.ControlSetHash(set)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
