package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

type storageRaftPeer struct {
	storage *RaftStorage
}

func (peer storageRaftPeer) RequestVote(_ context.Context, request VoteRequestV1) (VoteResultV1, error) {
	return peer.storage.HandleVote(request)
}

func (peer storageRaftPeer) AppendEntries(_ context.Context, request AppendEntriesRequestV1) (AppendEntriesResultV1, error) {
	return peer.storage.HandleAppendEntries(request)
}

type unavailableRaftPeer struct{}

func (unavailableRaftPeer) RequestVote(context.Context, VoteRequestV1) (VoteResultV1, error) {
	return VoteResultV1{}, errors.New("unavailable")
}

func (unavailableRaftPeer) AppendEntries(context.Context, AppendEntriesRequestV1) (AppendEntriesResultV1, error) {
	return AppendEntriesResultV1{}, errors.New("unavailable")
}

func TestNewLeaderBarrierRecoversCommitNotificationCrash(t *testing.T) {
	set, configKeys := testControlSet(t, 3)
	storages := make([]*RaftStorage, len(set.Members))
	for i, member := range set.Members {
		var err error
		storages[i], err = OpenRaftStorage(filepath.Join(t.TempDir(), member.MemberID+".json"), member.MemberID, set)
		if err != nil {
			t.Fatal(err)
		}
	}
	oldVote, err := storages[0].StartElection()
	if err != nil {
		t.Fatal(err)
	}
	if result, err := storages[1].HandleVote(oldVote); err != nil || !result.Granted {
		t.Fatalf("old election vote=%#v err=%v", result, err)
	}
	head := testControlHead(t, &set)
	if err := storages[0].AppendLocal(head); err != nil {
		t.Fatal(err)
	}
	appendResult, err := storages[1].HandleAppendEntries(AppendEntriesRequestV1{
		Term: 1, LeaderID: set.Members[0].MemberID, PrevLogHash: wire.EmptyHashV1,
		Entries: []RaftLogRecordV1{recordForEntry(head)},
	})
	if err != nil || !appendResult.Success {
		t.Fatalf("old replication=%#v err=%v", appendResult, err)
	}
	if commit, err := storages[0].AdvanceLeaderCommit(map[string]int64{set.Members[1].MemberID: 1}); err != nil || commit != 1 {
		t.Fatalf("old leader commit=%d err=%v", commit, err)
	}
	// 模拟旧 leader 在 fsync commitIndex 后、发送 LeaderCommit heartbeat 前崩溃。
	if storages[1].SnapshotRaft().CommitIndex != 0 {
		t.Fatal("fixture follower 提前得知 commit")
	}
	peers := map[string]RaftPeer{
		set.Members[0].MemberID: storageRaftPeer{storages[0]},
		set.Members[2].MemberID: storageRaftPeer{storages[2]},
	}
	leader, err := CampaignStableRaft(context.Background(), storages[1], set, peers)
	if err != nil {
		t.Fatal(err)
	}
	for i, storage := range storages {
		state := storage.SnapshotRaft()
		if state.CurrentTerm != 2 || state.CommitIndex != 2 || len(state.Log) != 2 ||
			state.Log[1].Kind != RaftRecordNoOp {
			t.Fatalf("member %d 未经 barrier 恢复 committed prefix: %#v", i, state)
		}
	}
	controlPath := filepath.Join(t.TempDir(), "control.json")
	store, err := Open(controlPath, set)
	if err != nil {
		t.Fatal(err)
	}
	recomputed := 0
	applied, err := ApplyCommittedPrefix(context.Background(), storages[1], store,
		func(_ context.Context, got wire.HeadEntryV2) error {
			recomputed++
			if !wire.EqualCanonical(got, head) {
				return errors.New("wrong head")
			}
			return nil
		})
	if err != nil || applied != 2 || recomputed != 1 {
		t.Fatalf("apply committed prefix applied=%d recomputed=%d err=%v", applied, recomputed, err)
	}
	state := store.Snapshot()
	if state.Active == nil || state.Active.Phase != PhaseCommittedNotCertified ||
		state.Active.RaftCommit == nil || state.Active.RaftCommit.MemberID != set.Members[1].MemberID {
		t.Fatalf("control store 未保存 exact local Raft commit reference: %#v", state)
	}
	reopenedRaft, err := OpenRaftStorage(storages[1].path, set.Members[1].MemberID, set)
	if err != nil || reopenedRaft.SnapshotRaft().LastApplied != 2 {
		t.Fatalf("Raft apply 坐标未耐久恢复: %#v err=%v", reopenedRaft, err)
	}
	reopenedStore, err := Open(controlPath, set)
	if err != nil || reopenedStore.Snapshot().Active.RaftCommit.EntryHash != head.EntryHash {
		t.Fatalf("control commit reference 未耐久恢复: %#v err=%v", reopenedStore, err)
	}

	// barrier 占用 index=2；下一份 Head 仍直接引用前一 certified Head，
	// previous_log_entry_hash 则引用真实的 barrier。
	nextBody := head.Body
	nextBody.Payload.HeadKind = "ordinary"
	nextBody.Payload.RaftTerm = 2
	nextBody.Payload.RaftIndex = 3
	nextBody.Payload.ControlRevision = 3
	nextBody.Payload.PreviousLogEntryHash = storages[1].SnapshotRaft().Log[1].EntryHash
	nextBody.Payload.ParentHeadHash = head.HeadHash
	nextBody.Payload.CommittedLogicalTime = "2026-09-11T00:02:00Z"
	nextBody.Payload.OperationRoot = wire.HashRaw("raft-leader-test", []byte("next-operation"))
	nextBody.Payload.TransitionContext, _ = json.Marshal(wire.OrdinaryHeadContextV1{Schema: 1, Kind: "ordinary"})
	next, err := wire.NewHeadEntry(nextBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leader.ReplicateHead(context.Background(), store, next); err == nil {
		t.Fatal("前一 committed Head 尚未 certified 时追加了下一 Head")
	}
	attestation := wire.AttestationForHead(&head)
	for _, member := range set.Members[:2] {
		signature, err := wire.SignHeadAttestation(attestation, member, configKeys[member.MemberID])
		if err != nil {
			t.Fatal(err)
		}
		if err := store.AddAttestation(head.EntryHash, signature); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.MarkApplied(head.EntryHash); err != nil {
		t.Fatal(err)
	}
	result, err := leader.ReplicateHead(context.Background(), store, next)
	if err != nil || result.CommitIndex != 3 || len(result.CommitKnownMemberIDs) != 3 {
		t.Fatalf("next head commit=%#v err=%v", result, err)
	}
}

func TestCampaignDoesNotAdvanceTermWithoutPreVoteQuorum(t *testing.T) {
	set, _ := testControlSet(t, 3)
	storage, _ := OpenRaftStorage(filepath.Join(t.TempDir(), "raft.json"), set.Members[0].MemberID, set)
	peers := map[string]RaftPeer{
		set.Members[1].MemberID: unavailableRaftPeer{},
		set.Members[2].MemberID: unavailableRaftPeer{},
	}
	if _, err := CampaignStableRaft(context.Background(), storage, set, peers); err == nil {
		t.Fatal("minority pre-vote elected leader")
	}
	state := storage.SnapshotRaft()
	if state.CurrentTerm != 0 || state.VotedFor != "" {
		t.Fatalf("failed pre-vote mutated durable term: %#v", state)
	}
}

func TestStableRaftCampaignAndCommitN1AndN5(t *testing.T) {
	for _, count := range []int{1, 5} {
		t.Run(fmt.Sprintf("N%d", count), func(t *testing.T) {
			set, _ := testControlSet(t, count)
			leaderStorage, err := OpenRaftStorage(filepath.Join(t.TempDir(), "leader.json"), set.Members[0].MemberID, set)
			if err != nil {
				t.Fatal(err)
			}
			peers := make(map[string]RaftPeer, count-1)
			for index := 1; index < count; index++ {
				if count == 5 && index > 2 {
					peers[set.Members[index].MemberID] = unavailableRaftPeer{}
					continue
				}
				storage, err := OpenRaftStorage(filepath.Join(t.TempDir(), fmt.Sprintf("peer-%d.json", index)),
					set.Members[index].MemberID, set)
				if err != nil {
					t.Fatal(err)
				}
				peers[set.Members[index].MemberID] = storageRaftPeer{storage}
			}
			leader, err := CampaignStableRaft(context.Background(), leaderStorage, set, peers)
			if err != nil {
				t.Fatal(err)
			}
			store, err := Open(filepath.Join(t.TempDir(), "control.json"), set)
			if err != nil {
				t.Fatal(err)
			}
			head := testControlHead(t, &set)
			result, err := leader.ReplicateHead(context.Background(), store, head)
			if err != nil || result.CommitIndex != 1 {
				t.Fatalf("N=%d commit=%#v err=%v", count, result, err)
			}
			quorum, _ := wire.Quorum(count)
			if len(result.CommitKnownMemberIDs) != quorum {
				t.Fatalf("N=%d post-commit known=%v want quorum=%d", count, result.CommitKnownMemberIDs, quorum)
			}
		})
	}
}

func TestCommitFromRaftRejectsUncommittedAndWrongReplica(t *testing.T) {
	set, _ := testControlSet(t, 3)
	head := testControlHead(t, &set)
	store, _ := Open(filepath.Join(t.TempDir(), "control.json"), set)
	if err := store.Prepare(head); err != nil {
		t.Fatal(err)
	}
	uncommitted := committedRaftForHead(t, set, 0, head, map[string]int64{})
	if err := store.CommitFromRaft(uncommitted, head.EntryHash); err == nil {
		t.Fatal("uncommitted local log 被应用层记录为 committed")
	}
	otherSet, _ := testControlSet(t, 1)
	otherSet.ClusterID = "other-cluster"
	otherSet.Members[0].ClusterID = "other-cluster"
	other, err := OpenRaftStorage(filepath.Join(t.TempDir(), "other.json"), otherSet.Members[0].MemberID, otherSet)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitFromRaft(other, head.EntryHash); err == nil {
		t.Fatal("错误 ControlSet 的 Raft storage 被接受")
	}
}
