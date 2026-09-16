package enrollmentv2

import (
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestExpiryRequiresDeadlineAndCertifiedProofAndRetainsReservation(t *testing.T) {
	set, invite, evidence, claim, admission, base := reservationFixture(t)
	reservation := certifiedOperationFixture(t, set, claim.OperationID, DomainClaimOperation, claim, claim.ReservedAt, 2, &base)
	path := filepath.Join(t.TempDir(), "transactions.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(invite, evidence, claim, admission, &set, base, nil, nil, reservation); err != nil {
		t.Fatal(err)
	}
	record, _ := store.SnapshotRecord(invite.InviteID)
	operation, err := TransactionExpiryOperation(record)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := wire.ParseTimeZ(claim.RetryNotAfter)
	if _, err := ExpireTransaction(record, operation, deadline.Add(-time.Second).Format(time.RFC3339)); err == nil {
		t.Fatal("提前终止认证 reservation")
	}
	cert := certifiedOperationFixture(t, set, operation.OperationID, DomainExpiryOperation, operation, claim.RetryNotAfter, 3, &reservation.Head)
	proof := EnrollmentExpiryEvidenceV1{Operation: operation, Certification: cert}
	tampered := clonePrivateValue(proof)
	tampered.Certification.OperationLeaf.ObjectID = wire.EmptyHashV1
	if _, err := store.Expire(tampered); err == nil {
		t.Fatal("未证明 operation inclusion 即终止")
	}
	if _, err := store.Expire(proof); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := store.Expire(proof); err != nil || state.Status != "aborted" {
		t.Fatalf("终止重放失败: %v", err)
	}
	retained, _ := store.SnapshotRecord(invite.InviteID)
	if !wire.EqualCanonical(retained.ClaimOperation, record.ClaimOperation) || retained.TokenCommitment != record.TokenCommitment {
		t.Fatal("丢失 token 占用或原 claim")
	}
	if _, err := store.Reserve(invite, evidence, claim, admission, &set, base, nil, nil, reservation); err != nil {
		t.Fatal(err)
	}
	state, _ := store.Snapshot(invite.InviteID)
	if state.Status != "aborted" {
		t.Fatal("reservation 重放复活了 token")
	}
}
