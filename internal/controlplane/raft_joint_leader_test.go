package controlplane

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

type learnerRaftPeer struct {
	storage *RaftStorage
}

type grantingRaftPeer struct{}

func (grantingRaftPeer) RequestVote(_ context.Context,
	request VoteRequestV1) (VoteResultV1, error) {
	term := request.Term
	if request.PreVote {
		term--
	}
	return VoteResultV1{Term: term, Granted: true}, nil
}

func (grantingRaftPeer) AppendEntries(_ context.Context,
	request AppendEntriesRequestV1) (AppendEntriesResultV1, error) {
	return AppendEntriesResultV1{Term: request.Term, Success: true,
		MatchIndex: request.PrevLogIndex + int64(len(request.Entries))}, nil
}

func (peer learnerRaftPeer) RequestVote(_ context.Context,
	request VoteRequestV1) (VoteResultV1, error) {
	return peer.storage.HandleVote(request)
}

func (peer learnerRaftPeer) AppendEntries(_ context.Context,
	request AppendEntriesRequestV1) (AppendEntriesResultV1, error) {
	return peer.storage.HandleLearnerAppendEntries(request)
}

func TestJointRaftLeaderRecoversElectionAndCommitsFinalWithDualMajority(t *testing.T) {
	fixture := newMembershipLedgerFixture(t)
	if err := fixture.ledger.BeginLearners(); err != nil {
		t.Fatal(err)
	}
	for _, learner := range fixture.ledger.Snapshot().Candidate.Learners {
		if err := fixture.ledger.MarkLearnerCaughtUp(learner.MemberID,
			wire.HashRaw("joint-leader-test", []byte("checkpoint-"+learner.MemberID)), 1); err != nil {
			t.Fatal(err)
		}
	}

	leaderStorage, err := OpenRaftStorage(filepath.Join(t.TempDir(), "old-leader.json"),
		fixture.oldSet.Members[0].MemberID, fixture.oldSet)
	if err != nil {
		t.Fatal(err)
	}
	stableLeader, err := CampaignStableRaft(context.Background(), leaderStorage, fixture.oldSet, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaderStorage.AppendLocal(fixture.parent.Head); err != nil {
		t.Fatal(err)
	}
	if commit, err := leaderStorage.AdvanceLeaderCommit(nil); err != nil || commit != 1 {
		t.Fatalf("parent commit=%d err=%v", commit, err)
	}
	if err := leaderStorage.MarkRaftApplied(1); err != nil {
		t.Fatal(err)
	}

	learner := fixture.newSet.Members[1]
	learnerStorage, err := OpenRaftLearnerStorage(filepath.Join(t.TempDir(), "learner.json"),
		learner.MemberID, fixture.oldSet)
	if err != nil {
		t.Fatal(err)
	}
	parentRecord := recordForEntry(fixture.parent.Head)
	if result, err := learnerStorage.HandleLearnerAppendEntries(AppendEntriesRequestV1{
		Term: 1, LeaderID: fixture.oldSet.Members[0].MemberID, PrevLogHash: wire.EmptyHashV1,
		Entries: []RaftLogRecordV1{parentRecord}, LeaderCommit: 1,
	}); err != nil || !result.Success {
		t.Fatalf("learner parent catch-up=%#v err=%v", result, err)
	}
	if err := learnerStorage.MarkRaftApplied(1); err != nil {
		t.Fatal(err)
	}
	if vote, err := learnerStorage.HandleVote(VoteRequestV1{Term: 2,
		CandidateID: fixture.oldSet.Members[0].MemberID, LastLogIndex: 1, LastLogTerm: 1}); err != nil || vote.Granted {
		t.Fatalf("pre-Joint learner 参与了投票: %#v err=%v", vote, err)
	}

	jointBody := membershipJointBody(t, fixture)
	unionPeers := map[string]RaftPeer{
		learner.MemberID:                   learnerRaftPeer{learnerStorage},
		fixture.newSet.Members[2].MemberID: unavailableRaftPeer{},
	}
	jointLeader, result, err := stableLeader.ReplicateJointControlSet(context.Background(),
		fixture.ledger, fixture.newSet, unionPeers, jointBody)
	if err != nil || jointLeader == nil || result.CommitIndex != jointBody.RaftIndex {
		t.Fatalf("Joint commit=%#v leader=%#v err=%v", result, jointLeader, err)
	}
	jointHash, _ := wire.JointControlSetEntryHash(&jointBody)
	if err := learnerStorage.ActivateJointControlSet(fixture.oldSet, fixture.newSet, jointHash); err != nil {
		t.Fatal(err)
	}
	if err := learnerStorage.MarkRaftApplied(jointBody.RaftIndex); err != nil {
		t.Fatal(err)
	}
	jointAttestation := wire.JointConfigAttestationForEntry(&jointBody, jointHash)
	jointSignatures := membershipConfigSignatures(t, fixture, func(member wire.ControlMemberV1,
		key ed25519.PrivateKey) (wire.ControlConfigSignatureV1, error) {
		return wire.SignJointConfigAttestation(jointAttestation, member, key)
	})
	if err := fixture.ledger.CertifyJoint(jointSignatures); err != nil {
		t.Fatal(err)
	}
	oldOnlyPartition := map[string]RaftPeer{
		learner.MemberID:                   unavailableRaftPeer{},
		fixture.newSet.Members[2].MemberID: unavailableRaftPeer{},
	}
	if _, err := CampaignJointRaft(context.Background(), leaderStorage, fixture.oldSet,
		fixture.newSet, oldOnlyPartition); err == nil || leaderStorage.SnapshotRaft().CurrentTerm != 1 {
		t.Fatal("只有 old-side quorum 时推进了 joint election/term")
	}
	newOnlyPartition := map[string]RaftPeer{
		fixture.oldSet.Members[0].MemberID: unavailableRaftPeer{},
		fixture.newSet.Members[2].MemberID: grantingRaftPeer{},
	}
	if _, err := CampaignJointRaft(context.Background(), learnerStorage, fixture.oldSet,
		fixture.newSet, newOnlyPartition); err == nil || learnerStorage.SnapshotRaft().CurrentTerm != 1 {
		t.Fatal("只有 new-side quorum 时推进了 joint election/term")
	}

	// 原 leader 故障；new-side learner 依靠 old/new 双多数恢复为新 leader，少数
	// new-side 节点不可达不能缩小任一门槛。
	recoveryPeers := map[string]RaftPeer{
		fixture.oldSet.Members[0].MemberID: storageRaftPeer{leaderStorage},
		fixture.newSet.Members[2].MemberID: unavailableRaftPeer{},
	}
	recoveredLeader, err := CampaignJointRaft(context.Background(), learnerStorage,
		fixture.oldSet, fixture.newSet, recoveryPeers)
	if err != nil {
		t.Fatal(err)
	}
	barrierState := learnerStorage.SnapshotRaft()
	barrier := barrierState.Log[len(barrierState.Log)-1]
	if barrier.Kind != RaftRecordNoOp || barrierState.CommitIndex != barrier.Index {
		t.Fatalf("joint election 未提交 current-term barrier: %#v", barrierState)
	}
	if applied, err := ApplyCommittedMembershipPrefix(context.Background(), learnerStorage,
		fixture.ledger, func(context.Context, wire.HeadEntryV2) (string, string, error) {
			return "", "", nil
		}); err != nil || applied != 1 {
		t.Fatalf("joint barrier apply=%d err=%v", applied, err)
	}

	finalHead := membershipFinalHead(t, fixture, fixture.ledger.Snapshot())
	finalPayload := finalHead.Body.Payload
	finalPayload.RaftTerm = barrier.Term
	finalPayload.RaftIndex = barrier.Index + 1
	finalPayload.ControlRevision = finalPayload.RaftIndex
	finalPayload.PreviousLogEntryHash = barrier.EntryHash
	jointProofHash, _ := wire.JointControlSetProofHash(fixture.ledger.Snapshot().Joint.Proof,
		&fixture.oldSet, &fixture.newSet)
	transitionHash, _ := wire.ControlSetTransitionProofHash(&wire.ControlSetTransitionProofV1{
		Schema: 1, JointProofHash: jointProofHash, FinalPayload: finalPayload})
	finalHead, err = wire.NewHeadEntry(wire.HeadEntryBodyV2{Payload: finalPayload,
		TransitionProofHash: transitionHash})
	if err != nil {
		t.Fatal(err)
	}
	result, err = recoveredLeader.ReplicateFinalControlSet(context.Background(), fixture.ledger,
		finalHead, func(_ context.Context, candidate wire.HeadEntryV2) (string, string, error) {
			return candidate.Body.Payload.SnapshotHash, candidate.Body.Payload.EffectiveSSOTHash, nil
		})
	if err != nil || result.CommitIndex != finalHead.Body.Payload.RaftIndex {
		t.Fatalf("Final commit=%#v err=%v", result, err)
	}
	finalState := learnerStorage.SnapshotRaft()
	newHash, _ := wire.ControlSetHash(&fixture.newSet)
	if finalState.ControlSetHash != newHash || finalState.LastApplied != finalState.CommitIndex ||
		learnerStorage.jointSet != nil {
		t.Fatalf("Final 未原子切换 stable voter rules: %#v", finalState)
	}
}
