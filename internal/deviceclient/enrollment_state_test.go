package deviceclient

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/control"
)

func TestPendingIdentityAcceptsOnlyMatchingProofAndPreservesExistingBytes(t *testing.T) {
	invite, view := schema3Fixture(t, "linux")
	reference, err := control.ReferenceForInvite(invite)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity")
	store, err := OpenReference(path, reference)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte("policy_ids")) || bytes.Contains(before, []byte("control_proof")) || store.state.Invite != nil {
		t.Fatal("internal invitation persisted before authentication")
	}
	pending := store.state
	identity, err := store.IdentityReadback()
	if err != nil || identity.Joined || identity.DeviceID != "" || identity.TransactionID != reference.TransactionID {
		t.Fatal("pending identity inspection fabricated target data", err)
	}
	other, _ := schema3Fixture(t, "linux", func(value *control.Invite) { value.ID = "demo-other" })
	if err := store.SaveEnrollmentProof(other); err == nil {
		t.Fatal("different proof accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected proof changed pending identity")
	}
	if err := store.SaveLKG(view(store.PublicKey(), 7)); err == nil {
		t.Fatal("View accepted before binding proof")
	}
	if err := store.SaveEnrollmentProof(invite); err != nil {
		t.Fatal(err)
	}
	if err := CheckIdentityStateAdvance(pending, store.state); err == nil {
		t.Fatal("complete proof reverted to short reference")
	}
	if err := CheckIdentityStateAdvance(store.state, pending); err != nil {
		t.Fatal(err)
	}
	if store.PublicKey() != pending.PublicKey || store.ClaimRequestID() != pending.ClaimRequestID || !store.state.AuthenticatedLatch {
		t.Fatal("binding changed local identity")
	}
	if err := store.SaveLKG(view(store.PublicKey(), 7)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveReportSequence(); err != nil {
		t.Fatal(err)
	}
	joined, _ := os.ReadFile(path)
	reopened, err := OpenReference(path, reference)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.SaveEnrollmentProof(invite); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := os.ReadFile(path)
	if !bytes.Equal(joined, unchanged) || reopened.state.ReportSequence != 1 || len(reopened.state.HighWater) == 0 {
		t.Fatal("repeated import changed accepted signed bytes or progress")
	}
	// The previously deployed complete identity shape has no new optional field.
	if bytes.Contains(joined, []byte("invitation_reference")) {
		t.Fatal("reference retained as parallel authority")
	}
	original, err := OpenForPlatform(filepath.Join(t.TempDir(), "identity"), invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	original.state.PrivateKey = pending.PrivateKey
	original.state.PublicKey = pending.PublicKey
	original.state.ClaimRequestID = pending.ClaimRequestID
	authenticated, err := AcceptLKG(original.state, view(store.PublicKey(), 7))
	if err != nil {
		t.Fatal(err)
	}
	authenticated.ReportSequence = 1
	expected, err := EncodeIdentityState(authenticated)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(joined, expected) {
		t.Fatal("forward acceptance changed existing complete identity encoding")
	}
}
