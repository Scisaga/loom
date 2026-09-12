package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"loom/internal/wire"
)

type membershipLedgerFixture struct {
	path          string
	ledger        *MembershipLedger
	parent        wire.SignedCurrentV2
	oldSet        wire.ControlSetV1
	newSet        wire.ControlSetV1
	oldConfigKeys map[string]ed25519.PrivateKey
	newConfigKeys map[string]ed25519.PrivateKey
	approval      wire.ControlMembershipApprovalProofV1
}

func TestMembershipLedgerRecoversJointAndFinalCommitBeforeQC(t *testing.T) {
	fixture := newMembershipLedgerFixture(t)
	jointBody := membershipJointBody(t, fixture)
	if err := fixture.ledger.RecordJointCommitFromRaft(nil, jointBody); err == nil {
		t.Fatal("learners 尚未 catch-up 就提交了 Joint")
	}
	if err := fixture.ledger.BeginLearners(); err != nil {
		t.Fatal(err)
	}
	for _, learner := range fixture.ledger.Snapshot().Candidate.Learners {
		if err := fixture.ledger.MarkLearnerCaughtUp(learner.MemberID,
			wire.HashRaw("membership-ledger-test", []byte("checkpoint-"+learner.MemberID)), 1); err != nil {
			t.Fatal(err)
		}
	}
	raft, err := OpenRaftStorage(filepath.Join(t.TempDir(), "raft.json"),
		fixture.oldSet.Members[0].MemberID, fixture.oldSet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raft.StartElection(); err != nil {
		t.Fatal(err)
	}
	if err := raft.AppendLocal(fixture.parent.Head); err != nil {
		t.Fatal(err)
	}
	if commit, err := raft.AdvanceLeaderCommit(nil); err != nil || commit != 1 {
		t.Fatalf("parent commit=%d err=%v", commit, err)
	}
	if err := raft.MarkRaftApplied(1); err != nil {
		t.Fatal(err)
	}
	barrier, err := raft.AppendLocalNoOp()
	if err != nil {
		t.Fatal(err)
	}
	if commit, err := raft.AdvanceLeaderCommit(nil); err != nil || commit != barrier.Index {
		t.Fatalf("pre-Joint current-term barrier commit=%d err=%v", commit, err)
	}
	if err := raft.MarkRaftApplied(barrier.Index); err != nil {
		t.Fatal(err)
	}
	jointBody.RaftIndex = barrier.Index + 1
	jointBody.PreviousLogEntryHash = barrier.EntryHash
	if err := raft.AppendLocalJointControlSet(jointBody, &fixture.oldSet, &fixture.newSet,
		&fixture.approval, &fixture.parent.Head); err != nil {
		t.Fatal(err)
	}
	if _, err := raft.AdvanceLeaderCommit(map[string]int64{
		fixture.newSet.Members[1].MemberID: jointBody.RaftIndex,
	}); err == nil {
		t.Fatal("stable quorum 路径提交了 Joint entry")
	}
	if commit, err := raft.AdvanceJointLeaderCommit(nil, fixture.oldSet, fixture.newSet); err != nil || commit != barrier.Index {
		t.Fatalf("new-side 单票绕过了 old/new 双多数: commit=%d err=%v", commit, err)
	}
	if err := fixture.ledger.RecordJointCommitFromRaft(raft, jointBody); err == nil {
		t.Fatal("未 committed 的 Joint entry 进入了 membership ledger")
	}
	if commit, err := raft.AdvanceJointLeaderCommit(map[string]int64{
		fixture.newSet.Members[1].MemberID: jointBody.RaftIndex,
	}, fixture.oldSet, fixture.newSet); err != nil || commit != jointBody.RaftIndex {
		t.Fatalf("Joint 双多数未提交: commit=%d err=%v", commit, err)
	}
	if applied, err := ApplyCommittedMembershipPrefix(context.Background(), raft, fixture.ledger,
		func(context.Context, wire.HeadEntryV2) (string, string, error) {
			t.Fatal("Joint apply 不应调用 Final materializer")
			return "", "", nil
		}); err != nil || applied != 1 {
		t.Fatalf("Joint apply=%d err=%v", applied, err)
	}
	if err := fixture.ledger.RecordJointCommitFromRaft(raft, jointBody); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenMembershipLedger(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Snapshot().Phase != MembershipLedgerJointCommittedNotCertified {
		t.Fatal("Joint commit→QC 崩溃恢复丢失")
	}
	if _, err := OpenRaftStorage(raft.path, fixture.oldSet.Members[0].MemberID, fixture.oldSet); err == nil {
		t.Fatal("active Joint 在重启后退回了 stable Raft")
	}
	raft, err = OpenJointRaftStorage(raft.path, fixture.oldSet.Members[0].MemberID,
		fixture.oldSet, fixture.newSet)
	if err != nil {
		t.Fatal(err)
	}
	jointHash, _ := wire.JointControlSetEntryHash(&jointBody)
	jointAttestation := wire.JointConfigAttestationForEntry(&jointBody, jointHash)
	jointSignatures := membershipConfigSignatures(t, fixture, func(member wire.ControlMemberV1,
		key ed25519.PrivateKey) (wire.ControlConfigSignatureV1, error) {
		return wire.SignJointConfigAttestation(jointAttestation, member, key)
	})
	if err := reopened.CertifyJoint(jointSignatures[:1]); err == nil ||
		reopened.Snapshot().Phase != MembershipLedgerJointCommittedNotCertified {
		t.Fatal("Joint 少数签名被认证或改变了 durable phase")
	}
	if err := reopened.CertifyJoint(jointSignatures); err != nil {
		t.Fatal(err)
	}
	finalHead := membershipFinalHead(t, fixture, reopened.Snapshot())
	if err := raft.AppendLocal(finalHead); err != nil {
		t.Fatal(err)
	}
	if _, err := raft.AdvanceLeaderCommit(map[string]int64{
		fixture.newSet.Members[1].MemberID: finalHead.Body.Payload.RaftIndex,
	}); err == nil {
		t.Fatal("stable quorum 路径提交了 Final entry")
	}
	if commit, err := raft.AdvanceJointLeaderCommit(map[string]int64{
		fixture.newSet.Members[1].MemberID: finalHead.Body.Payload.RaftIndex,
	}, fixture.oldSet, fixture.newSet); err != nil || commit != finalHead.Body.Payload.RaftIndex {
		t.Fatalf("Final 双多数未提交: commit=%d err=%v", commit, err)
	}
	if err := reopened.RecordFinalCommitFromRaft(raft, finalHead, finalHead.Body.Payload.SnapshotHash,
		finalHead.Body.Payload.EffectiveSSOTHash); err != nil {
		t.Fatal(err)
	}
	if err := raft.ActivateFinalControlSet(fixture.newSet, finalHead.EntryHash); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRaftStorage(raft.path, fixture.oldSet.Members[0].MemberID, fixture.oldSet); err == nil {
		t.Fatal("Final 激活后仍以 old ControlSet 打开 Raft storage")
	}
	reopenedRaft, err := OpenRaftStorage(raft.path, fixture.newSet.Members[0].MemberID, fixture.newSet)
	if err != nil {
		t.Fatal(err)
	}
	if applied, err := ApplyCommittedMembershipPrefix(context.Background(), reopenedRaft, reopened,
		func(_ context.Context, candidate wire.HeadEntryV2) (string, string, error) {
			if !wire.EqualCanonical(candidate, finalHead) {
				t.Fatal("materializer 收到错误 Final")
			}
			return finalHead.Body.Payload.SnapshotHash,
				finalHead.Body.Payload.EffectiveSSOTHash, nil
		}); err != nil || applied != 1 {
		t.Fatalf("Final apply=%d err=%v", applied, err)
	}
	if reopenedRaft.SnapshotRaft().ControlSetHash != finalHead.Body.Payload.ControlSetHash {
		t.Fatal("Final ControlSet authority 未耐久恢复")
	}
	reopened, err = OpenMembershipLedger(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Snapshot().Phase != MembershipLedgerFinalCommittedNotCertified {
		t.Fatal("Final commit→QC 崩溃恢复丢失")
	}
	finalSignatures := membershipConfigSignatures(t, fixture, func(member wire.ControlMemberV1,
		key ed25519.PrivateKey) (wire.ControlConfigSignatureV1, error) {
		return wire.SignHeadAttestation(wire.AttestationForHead(&finalHead), member, key)
	})
	if _, err := reopened.CertifyFinal(finalSignatures[:1]); err == nil ||
		reopened.Snapshot().Phase != MembershipLedgerFinalCommittedNotCertified {
		t.Fatal("Final 少数签名被认证或改变了 durable phase")
	}
	bundle, err := reopened.CertifyFinal(finalSignatures)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.VerifyControlSetTransitionBundle(&bundle, &fixture.parent.Head); err != nil {
		t.Fatal(err)
	}
	reopened, err = OpenMembershipLedger(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	state := reopened.Snapshot()
	if state.Phase != MembershipLedgerFinal || state.CertifiedBundle == nil || state.Final.QC == nil {
		t.Fatalf("certified Final 未耐久恢复: %#v", state)
	}
}

func TestMembershipLedgerRejectsForgedLearnerDirectoryBinding(t *testing.T) {
	inputs := membershipLedgerInputs(t)
	memberID := inputs.newSet.Members[1].MemberID
	broken := inputs.evidence[memberID]
	broken.InstalledDirectoryObjectHash = wire.HashRaw("membership-ledger-test", []byte("other-directory"))
	inputs.evidence[memberID] = broken
	if _, err := CreateMembershipLedger(filepath.Join(t.TempDir(), "membership.json"), inputs.parent, nil,
		inputs.oldSet, inputs.newSet, inputs.oldDirectory, inputs.newDirectory, inputs.approval, inputs.admin,
		inputs.evidence, inputs.identities, inputs.trustedTime); err == nil {
		t.Fatal("接受了未安装 exact private directory 的 learner")
	}
}

func TestMembershipLedgerRejectsExpiredPeerDirectoryAtPreparation(t *testing.T) {
	inputs := membershipLedgerInputs(t)
	if _, err := CreateMembershipLedger(filepath.Join(t.TempDir(), "membership.json"), inputs.parent, nil,
		inputs.oldSet, inputs.newSet, inputs.oldDirectory, inputs.newDirectory, inputs.approval, inputs.admin,
		inputs.evidence, inputs.identities, inputs.trustedTime.Add(48*time.Hour)); err == nil {
		t.Fatal("接受了在认证逻辑时间已经过期的 control-peer directory")
	}
}

func TestMembershipLedgerQuorumNeverShrinksToOnlineMembers(t *testing.T) {
	for _, count := range []int{1, 3, 5} {
		set, _ := testControlSet(t, count)
		candidate := MembershipLedgerCandidateV1{OldControlSet: set, NewControlSet: set}
		quorum, _ := wire.Quorum(count)
		members := make([]string, quorum)
		for i := range members {
			members[i] = set.Members[i].MemberID
		}
		if _, err := canonicalJointMembers(&candidate, members); err != nil {
			t.Fatalf("N=%d 的 committed quorum 被拒绝: %v", count, err)
		}
		if quorum > 1 {
			if _, err := canonicalJointMembers(&candidate, members[:quorum-1]); err == nil {
				t.Fatalf("N=%d 按在线少数派缩小了 quorum", count)
			}
		}
	}
}

type membershipLedgerInputSet struct {
	trustedTime                  time.Time
	parent                       wire.SignedCurrentV2
	oldSet, newSet               wire.ControlSetV1
	oldConfigKeys, newConfigKeys map[string]ed25519.PrivateKey
	oldDirectory, newDirectory   wire.ControlPeerDirectoryPrivateObjectV1
	approval                     wire.ControlMembershipApprovalProofV1
	admin                        wire.VerifiedAdminOperationV1
	evidence                     map[string]CandidateEvidence
	identities                   map[string]VerifiedDeviceIdentityV1
}

func newMembershipLedgerFixture(t *testing.T) membershipLedgerFixture {
	t.Helper()
	inputs := membershipLedgerInputs(t)
	path := filepath.Join(t.TempDir(), "membership.json")
	ledger, err := CreateMembershipLedger(path, inputs.parent, nil, inputs.oldSet, inputs.newSet,
		inputs.oldDirectory, inputs.newDirectory, inputs.approval, inputs.admin, inputs.evidence,
		inputs.identities, inputs.trustedTime)
	if err != nil {
		t.Fatal(err)
	}
	return membershipLedgerFixture{path: path, ledger: ledger, parent: inputs.parent,
		oldSet: inputs.oldSet, newSet: inputs.newSet, oldConfigKeys: inputs.oldConfigKeys,
		newConfigKeys: inputs.newConfigKeys, approval: inputs.approval}
}

func membershipLedgerInputs(t *testing.T) membershipLedgerInputSet {
	t.Helper()
	trustedTime := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	oldSet, oldConfigKeys := testControlSet(t, 1)
	newSet, newConfigKeys := testControlSet(t, 3)
	oldDirectoryValue, _ := raftDirectoryFixture(t, oldSet)
	newDirectoryValue, _ := raftDirectoryFixture(t, newSet)
	newDirectoryValue.DirectoryGeneration = oldDirectoryValue.DirectoryGeneration + 1
	newNonce := make([]byte, 32)
	newNonce[len(newNonce)-1] = 1
	newDirectoryValue.HidingNonce = base64.RawURLEncoding.EncodeToString(newNonce)
	oldSetHash, _ := wire.ControlSetHash(&oldSet)
	newSetHash, _ := wire.ControlSetHash(&newSet)
	oldDirectoryHash, _ := wire.ControlPeerDirectoryHash(&oldSet, &oldDirectoryValue)
	newDirectoryHash, _ := wire.ControlPeerDirectoryHash(&newSet, &newDirectoryValue)
	oldDirectory := wire.ControlPeerDirectoryPrivateObjectV1{Schema: 1, ClusterID: oldSet.ClusterID,
		ControlSetHash: oldSetHash, ControlPeerDirectoryHash: oldDirectoryHash, Directory: oldDirectoryValue}
	newDirectory := wire.ControlPeerDirectoryPrivateObjectV1{Schema: 1, ClusterID: newSet.ClusterID,
		ControlSetHash: newSetHash, ControlPeerDirectoryHash: newDirectoryHash, Directory: newDirectoryValue}

	profile, authorization, adminKey, adminCertificate := privateAdminFixture(t, trustedTime)
	authorization.AllowedOperationKinds = []string{"control_set_transition_intent"}
	authorization.Scopes = []wire.AdminResourceScopeV1{{ScopeKind: "control_membership", ControlMembership: &struct{}{}}}
	profiles := map[string]wire.AdminCertificateProfileV1{profile.ProfileID: profile}
	authorizations := []wire.AdminAuthorizationV1{authorization}
	aclRoot, err := wire.AdminACLRoot(authorizations, profiles)
	if err != nil {
		t.Fatal(err)
	}
	parentHead := testControlHead(t, &oldSet)
	parentBody := parentHead.Body
	parentBody.Payload.AdminACLRoot = aclRoot
	parentBody.Payload.ControlPeerDirectoryHash = oldDirectoryHash
	parentHead, err = wire.NewHeadEntry(parentBody)
	if err != nil {
		t.Fatal(err)
	}
	parentSignature, err := wire.SignHeadAttestation(wire.AttestationForHead(&parentHead),
		oldSet.Members[0], oldConfigKeys[oldSet.Members[0].MemberID])
	if err != nil {
		t.Fatal(err)
	}
	parentQC, _ := wire.MarshalCanonical(wire.StableQC(&parentHead,
		[]wire.ControlConfigSignatureV1{parentSignature}))
	parent := wire.SignedCurrentV2{Schema: 2, Head: parentHead, QuorumCertificate: parentQC,
		PublishedAt: "2026-09-11T12:00:00Z"}

	intent := wire.ControlSetTransitionIntentV1{Schema: 1, ClusterID: oldSet.ClusterID,
		TransitionID: "membership-transition-1", RecoveryEpoch: parentHead.Body.Payload.RecoveryEpoch,
		RecoveryStatementHash: parentHead.Body.Payload.RecoveryStatementHash,
		RecoveryPolicyHash:    parentHead.Body.Payload.RecoveryPolicyHash,
		OldControlEpoch:       parentHead.Body.Payload.ControlEpoch, OldControlSetHash: oldSetHash,
		OldControlPeerDirectoryHash: oldDirectoryHash, TargetControlEpoch: parentHead.Body.Payload.ControlEpoch + 1,
		NewControlSetHash: newSetHash, NewControlPeerDirectoryHash: newDirectoryHash,
		ParentCertifiedHeadHash: parentHead.HeadHash, OperationID: "membership-operation-1", Reason: "add control members"}
	intentHash, _ := wire.ControlSetTransitionIntentHash(&intent)
	operation, err := wire.NewControlOperation(wire.ControlOperationBodyV1{Schema: 1, ClusterID: oldSet.ClusterID,
		OperationID: intent.OperationID, AuthorID: authorization.AdminID,
		AdminCertDigest: authorization.AdminCertificateDigest, CreatedAt: "2026-09-11T11:59:59Z",
		ExpiresAt: "2026-09-11T12:05:00Z", BaseRecoveryEpoch: intent.RecoveryEpoch,
		BaseRecoveryStatementHash: intent.RecoveryStatementHash, BaseRecoveryPolicyHash: intent.RecoveryPolicyHash,
		BaseControlEpoch: intent.OldControlEpoch, BaseControlSetHash: intent.OldControlSetHash,
		BaseControlRevision: parentHead.Body.Payload.ControlRevision, ParentHeadHash: parentHead.HeadHash,
		Kind: "control_set_transition_intent", PayloadSchema: 1, PayloadHash: intentHash, Reason: intent.Reason,
	}, adminKey, wire.OperationSchemaRegistry{"control_set_transition_intent": 1})
	if err != nil {
		t.Fatal(err)
	}
	proofs := membershipPoPs(t, newSet)
	membershipSignatures := make([]wire.ControlMembershipSignatureV1, 0, 2)
	for _, index := range []int{0, 1} {
		member := newSet.Members[index]
		signature, err := wire.SignControlMembershipApproval(intent, member, testControlKey(index+1, 0))
		if err != nil {
			t.Fatal(err)
		}
		membershipSignatures = append(membershipSignatures, signature)
	}
	sort.Slice(membershipSignatures, func(i, j int) bool {
		if membershipSignatures[i].MemberID != membershipSignatures[j].MemberID {
			return membershipSignatures[i].MemberID < membershipSignatures[j].MemberID
		}
		return membershipSignatures[i].MembershipKeyID < membershipSignatures[j].MembershipKeyID
	})
	approval := wire.ControlMembershipApprovalProofV1{Schema: 1, Intent: intent,
		AdminIntentOperation: operation, NewControlKeyPossessionProofs: proofs,
		Signatures: membershipSignatures,
		OldSignerRefs: []wire.ControlMembershipSignerRefV1{{MemberID: oldSet.Members[0].MemberID,
			MembershipKeyID: oldSet.Members[0].MembershipKeyID}},
		NewSignerRefs: []wire.ControlMembershipSignerRefV1{
			{MemberID: newSet.Members[0].MemberID, MembershipKeyID: newSet.Members[0].MembershipKeyID},
			{MemberID: newSet.Members[1].MemberID, MembershipKeyID: newSet.Members[1].MembershipKeyID},
		}}
	scope := authorization.Scopes[0]
	admin, err := wire.AuthorizeControlOperationAtHead(&operation, adminCertificate.Raw, &scope, trustedTime,
		wire.OperationSchemaRegistry{"control_set_transition_intent": 1}, &parentHead, parentQC, &oldSet, nil,
		authorizations, profiles)
	if err != nil {
		t.Fatal(err)
	}
	newObjectHash, _ := wire.ControlPeerDirectoryPrivateObjectHash(&newSet, &newDirectory)
	evidence := make(map[string]CandidateEvidence, 2)
	identities := make(map[string]VerifiedDeviceIdentityV1, 2)
	for i := 1; i < len(newSet.Members); i++ {
		member := newSet.Members[i]
		directoryMember := newDirectoryValue.Members[i]
		certificateHash := wire.HashRaw("membership-ledger-test", []byte("device-cert-"+member.MemberID))
		evidence[member.MemberID] = CandidateEvidence{DeviceID: directoryMember.DeviceID,
			DeviceCertificateHash: certificateHash, OverlayReachable: true, InstalledHeadHash: parentHead.HeadHash,
			LastLogIndex: parentHead.Body.Payload.RaftIndex, InstalledDirectoryObjectHash: newObjectHash}
		identities[directoryMember.DeviceID] = VerifiedDeviceIdentityV1{
			record: DeviceIdentityRecordV1{Schema: 1, DeviceID: directoryMember.DeviceID,
				CertificateHash: certificateHash, IdentityStatus: "active"},
			authority: DeviceIdentityAuthorityV1{Head: parentHead},
		}
	}
	return membershipLedgerInputSet{trustedTime: trustedTime, parent: parent, oldSet: oldSet, newSet: newSet,
		oldConfigKeys: oldConfigKeys, newConfigKeys: newConfigKeys, oldDirectory: oldDirectory,
		newDirectory: newDirectory, approval: approval, admin: admin, evidence: evidence, identities: identities}
}

func membershipPoPs(t *testing.T, set wire.ControlSetV1) []wire.ControlKeyPossessionProofV1 {
	t.Helper()
	proofs := make([]wire.ControlKeyPossessionProofV1, 0, len(set.Members)*3)
	setHash, _ := wire.ControlSetHash(&set)
	for i, member := range set.Members {
		for purpose, fields := range []struct {
			name, keyID, publicKey string
		}{
			{"membership", member.MembershipKeyID, member.MembershipPublicKey},
			{"config", member.ConfigKeyID, member.ConfigPublicKey},
			{"enrollment", member.EnrollmentKeyID, member.EnrollmentPublicKey},
		} {
			proof, err := wire.NewControlKeyPossessionProof(wire.ControlKeyPossessionProofBodyV1{Schema: 1,
				ClusterID: set.ClusterID, ControlSetHash: setHash, MemberID: member.MemberID,
				KeyPurpose: fields.name, KeyID: fields.keyID, PublicKey: fields.publicKey}, testControlKey(i+1, purpose))
			if err != nil {
				t.Fatal(err)
			}
			proofs = append(proofs, proof)
		}
	}
	return proofs
}

func testControlKey(memberOrdinal, purpose int) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	seed[len(seed)-2], seed[len(seed)-1] = byte(memberOrdinal), byte(purpose+1)
	return ed25519.NewKeyFromSeed(seed)
}

func membershipJointBody(t *testing.T, fixture membershipLedgerFixture) wire.JointControlSetEntryBodyV1 {
	t.Helper()
	intent := fixture.approval.Intent
	approvalHash, _ := wire.ControlMembershipApprovalProofHash(&fixture.approval)
	return wire.JointControlSetEntryBodyV1{Schema: 1, ClusterID: intent.ClusterID,
		TransitionID: intent.TransitionID, RecoveryEpoch: intent.RecoveryEpoch,
		RecoveryStatementHash: intent.RecoveryStatementHash, RecoveryPolicyHash: intent.RecoveryPolicyHash,
		OldControlEpoch: intent.OldControlEpoch, OldControlSetHash: intent.OldControlSetHash,
		OldControlPeerDirectoryHash: intent.OldControlPeerDirectoryHash,
		TargetControlEpoch:          intent.TargetControlEpoch, NewControlSetHash: intent.NewControlSetHash,
		NewControlPeerDirectoryHash: intent.NewControlPeerDirectoryHash,
		ParentCertifiedHeadHash:     intent.ParentCertifiedHeadHash, MembershipApprovalProofHash: approvalHash,
		RaftTerm: 1, RaftIndex: fixture.parent.Head.Body.Payload.RaftIndex + 1,
		PreviousLogEntryHash: fixture.parent.Head.EntryHash, OperationID: intent.OperationID, Reason: intent.Reason,
		CommittedLogicalTime: "2026-09-11T12:00:01Z"}
}

func membershipFinalHead(t *testing.T, fixture membershipLedgerFixture,
	state MembershipLedgerStateV1) wire.HeadEntryV2 {
	t.Helper()
	intent := fixture.approval.Intent
	jointProofHash, _ := wire.JointControlSetProofHash(state.Joint.Proof, &fixture.oldSet, &fixture.newSet)
	approvalHash, _ := wire.ControlMembershipApprovalProofHash(&fixture.approval)
	context, _ := wire.MarshalCanonical(wire.FinalControlSetContextV1{Schema: 1, Kind: "control_set_final",
		TransitionID: intent.TransitionID, OldControlEpoch: intent.OldControlEpoch,
		OldControlSetHash: intent.OldControlSetHash, OldControlPeerDirectoryHash: intent.OldControlPeerDirectoryHash,
		NewControlEpoch: intent.TargetControlEpoch, NewControlSetHash: intent.NewControlSetHash,
		NewControlPeerDirectoryHash: intent.NewControlPeerDirectoryHash,
		MembershipApprovalProofHash: approvalHash, JointEntryHash: state.Joint.EntryHash,
		JointProofHash: jointProofHash})
	p := fixture.parent.Head.Body.Payload
	p.HeadKind = "control_set_final"
	p.ControlEpoch = intent.TargetControlEpoch
	p.ControlSetHash = intent.NewControlSetHash
	p.ControlPeerDirectoryHash = intent.NewControlPeerDirectoryHash
	p.RaftIndex = state.Joint.Body.RaftIndex + 1
	p.ControlRevision = p.RaftIndex
	p.PreviousLogEntryHash = state.Joint.EntryHash
	p.ParentHeadHash = fixture.parent.Head.HeadHash
	p.SnapshotHash = wire.HashRaw("membership-ledger-test", []byte("snapshot-final"))
	p.EffectiveSSOTHash = wire.HashRaw("membership-ledger-test", []byte("ssot-final"))
	p.CommittedLogicalTime = "2026-09-11T12:00:02Z"
	p.TransitionContext = json.RawMessage(context)
	transitionHash, _ := wire.ControlSetTransitionProofHash(&wire.ControlSetTransitionProofV1{
		Schema: 1, JointProofHash: jointProofHash, FinalPayload: p})
	head, err := wire.NewHeadEntry(wire.HeadEntryBodyV2{Payload: p, TransitionProofHash: transitionHash})
	if err != nil {
		t.Fatal(err)
	}
	return head
}

func membershipConfigSignatures(t *testing.T, fixture membershipLedgerFixture,
	sign func(wire.ControlMemberV1, ed25519.PrivateKey) (wire.ControlConfigSignatureV1, error)) []wire.ControlConfigSignatureV1 {
	t.Helper()
	result := make([]wire.ControlConfigSignatureV1, 0, 2)
	for _, member := range fixture.newSet.Members[:2] {
		key := fixture.newConfigKeys[member.MemberID]
		signature, err := sign(member, key)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, signature)
	}
	return result
}
