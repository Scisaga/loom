package enrollmentv2

import (
	"os"
	"path/filepath"
	"testing"

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
	body, err := wire.MarshalCanonical(durableState{Schema: 1, Records: []DurableRecord{
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
