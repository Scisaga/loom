package controlplane

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

func TestCommitQCCrashRecoveryN1(t *testing.T) {
	set, configKeys := testControlSet(t, 1)
	path := filepath.Join(t.TempDir(), "control.json")
	store, err := Open(path, set)
	if err != nil {
		t.Fatal(err)
	}
	entry := testControlHead(t, &set)
	if err := store.Prepare(entry); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(entry.EntryHash, []string{set.Members[0].MemberID}); err != nil {
		t.Fatal(err)
	}
	if store.Snapshot().Active.Phase != PhaseCommittedNotCertified {
		t.Fatal("commit incorrectly became certified without a post-commit attestation")
	}
	reopened, err := Open(path, set)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.RecoverCertification(configKeys); err != nil {
		t.Fatal(err)
	}
	state := reopened.Snapshot()
	if state.Active.Phase != PhaseCertified || state.CertifiedHead.EntryHash != entry.EntryHash {
		t.Fatalf("same result was not recovered: %#v", state)
	}
	if err := reopened.MarkApplied(entry.EntryHash); err != nil {
		t.Fatal(err)
	}
	final, err := Open(path, set)
	if err != nil || final.Snapshot().Active != nil || final.Snapshot().CertifiedHead.EntryHash != entry.EntryHash {
		t.Fatalf("applied state not durable: %v", err)
	}
}

func TestN3MinorityCannotCommitOrDriveReconcile(t *testing.T) {
	set, _ := testControlSet(t, 3)
	store, _ := Open(filepath.Join(t.TempDir(), "control.json"), set)
	entry := testControlHead(t, &set)
	if err := store.Prepare(entry); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(entry.EntryHash, []string{set.Members[0].MemberID}); err == nil {
		t.Fatal("minority commit accepted")
	}
	if err := store.MarkReconciled(entry.EntryHash, nil); err == nil {
		t.Fatal("pending state drove an external reconcile")
	}
}

func TestCertifiedQCSignerSetCannotChange(t *testing.T) {
	set, configKeys := testControlSet(t, 3)
	store, _ := Open(filepath.Join(t.TempDir(), "control.json"), set)
	entry := testControlHead(t, &set)
	if err := store.Prepare(entry); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(entry.EntryHash, []string{set.Members[0].MemberID, set.Members[1].MemberID}); err != nil {
		t.Fatal(err)
	}
	attestation := wire.AttestationForHead(&entry)
	for _, member := range set.Members[:2] {
		signature, _ := wire.SignHeadAttestation(attestation, member, configKeys[member.MemberID])
		if err := store.AddAttestation(entry.EntryHash, signature); err != nil {
			t.Fatal(err)
		}
	}
	third := set.Members[2]
	thirdSignature, _ := wire.SignHeadAttestation(attestation, third, configKeys[third.MemberID])
	if err := store.AddAttestation(entry.EntryHash, thirdSignature); err == nil {
		t.Fatal("certified 后接受了会改变 QC bytes 的额外 signer")
	}
}

func testControlSet(t *testing.T, count int) (wire.ControlSetV1, map[string]ed25519.PrivateKey) {
	t.Helper()
	set := wire.ControlSetV1{Schema: 1, ClusterID: "cluster"}
	configKeys := make(map[string]ed25519.PrivateKey, count)
	for memberOrdinal := 1; memberOrdinal <= count; memberOrdinal++ {
		keys := make([]ed25519.PrivateKey, 3)
		ids := make([]string, 3)
		publics := make([]string, 3)
		for purpose := range keys {
			seed := make([]byte, ed25519.SeedSize)
			seed[len(seed)-2], seed[len(seed)-1] = byte(memberOrdinal), byte(purpose+1)
			keys[purpose] = ed25519.NewKeyFromSeed(seed)
			public := keys[purpose].Public().(ed25519.PublicKey)
			ids[purpose], _ = wire.ControlKeyID(public)
			publics[purpose] = base64.RawURLEncoding.EncodeToString(public)
		}
		memberID := fmt.Sprintf("%026d", memberOrdinal)
		member := wire.ControlMemberV1{Schema: 1, ClusterID: "cluster", MemberID: memberID, MembershipKeyID: ids[0], MembershipPublicKey: publics[0], ConfigKeyID: ids[1], ConfigPublicKey: publics[1], EnrollmentKeyID: ids[2], EnrollmentPublicKey: publics[2], MinimumControlProtocol: 2}
		set.Members = append(set.Members, member)
		configKeys[memberID] = keys[1]
	}
	if err := wire.ValidateControlSet(&set); err != nil {
		t.Fatal(err)
	}
	return set, configKeys
}

func testControlHead(t *testing.T, set *wire.ControlSetV1) wire.HeadEntryV2 {
	t.Helper()
	setHash, _ := wire.ControlSetHash(set)
	hash := func(value string) string { return wire.HashRaw("controlplane-test", []byte(value)) }
	transition, _ := json.Marshal(struct {
		Schema                   int    `json:"schema"`
		Kind                     string `json:"kind"`
		InitialV2HeadPayloadHash string `json:"initial_v2_head_payload_hash"`
	}{1, "bootstrap", hash("initial")})
	entry, err := wire.NewHeadEntry(wire.HeadEntryBodyV2{Payload: wire.HeadEntryPayloadV2{
		Schema: 2, HeadKind: "bootstrap", ClusterID: "cluster", RecoveryEpoch: 0,
		RecoveryStatementHash: hash("recovery"), RecoveryPolicyHash: hash("policy"), ControlEpoch: 0,
		ControlSetHash: setHash, ControlPeerDirectoryHash: hash("directory"), RaftTerm: 1, RaftIndex: 1,
		PreviousLogEntryHash: wire.EmptyHashV1, ControlRevision: 1, ParentHeadHash: wire.EmptyHashV1,
		OperationRoot: hash("operations"), SnapshotHash: hash("snapshot"), EffectiveSSOTHash: hash("ssot"),
		DeviceViewsRoot: hash("views"), AdminACLRoot: hash("admin"), CAProfileRoot: hash("ca"), BootstrapIssuerRegistryRoot: hash("issuer"),
		RenderContractVersion: 2, MinReaderVersion: 2, CommittedLogicalTime: "2026-09-11T00:00:00Z", MaxClockSkewSeconds: 30,
		TransitionContext: transition,
	}, TransitionProofHash: hash("proof")})
	if err != nil {
		t.Fatal(err)
	}
	return entry
}
