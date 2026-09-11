package controlplane

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

func nextOrdinaryHead(t *testing.T, parent wire.HeadEntryV2, term int64) wire.HeadEntryV2 {
	t.Helper()
	body := parent.Body
	body.Payload.HeadKind = "ordinary"
	body.Payload.RaftTerm = term
	body.Payload.RaftIndex++
	body.Payload.ControlRevision = body.Payload.RaftIndex
	body.Payload.PreviousLogEntryHash = parent.EntryHash
	body.Payload.ParentHeadHash = parent.HeadHash
	body.Payload.CommittedLogicalTime = "2026-09-11T00:01:00Z"
	body.Payload.OperationRoot = wire.HashRaw("controlplane-test", []byte("operations-2"))
	body.Payload.TransitionContext, _ = json.Marshal(wire.OrdinaryHeadContextV1{Schema: 1, Kind: "ordinary"})
	entry, err := wire.NewHeadEntry(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.ValidateHeadEntry(&entry, &parent); err != nil {
		t.Fatal(err)
	}
	return entry
}

func retermGenesis(t *testing.T, entry wire.HeadEntryV2, term int64) wire.HeadEntryV2 {
	t.Helper()
	body := entry.Body
	body.Payload.RaftTerm = term
	result, err := wire.NewHeadEntry(body)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRaftCurrentTermCommitRuleAndCrashRecovery(t *testing.T) {
	set, _ := testControlSet(t, 3)
	path := filepath.Join(t.TempDir(), "raft.json")
	storage, err := OpenRaftStorage(path, set.Members[0].MemberID, set)
	if err != nil {
		t.Fatal(err)
	}
	request, err := storage.StartElection()
	if err != nil || request.Term != 1 {
		t.Fatalf("start election: %#v %v", request, err)
	}
	first := testControlHead(t, &set)
	if err := storage.AppendLocal(first); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.StartElection(); err != nil {
		t.Fatal(err)
	}
	commit, err := storage.AdvanceLeaderCommit(map[string]int64{set.Members[1].MemberID: 1})
	if err != nil || commit != 0 {
		t.Fatalf("old-term entry advanced commit: index=%d err=%v", commit, err)
	}
	second := nextOrdinaryHead(t, first, 2)
	if err := storage.AppendLocal(second); err != nil {
		t.Fatal(err)
	}
	commit, err = storage.AdvanceLeaderCommit(map[string]int64{set.Members[1].MemberID: 2})
	if err != nil || commit != 2 {
		t.Fatalf("current-term quorum did not commit prefix: index=%d err=%v", commit, err)
	}
	if err := storage.MarkRaftApplied(2); err == nil {
		t.Fatal("allowed apply to skip index 1")
	}
	if err := storage.MarkRaftApplied(1); err != nil {
		t.Fatal(err)
	}
	if err := storage.MarkRaftApplied(2); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRaftStorage(path, set.Members[0].MemberID, set)
	if err != nil {
		t.Fatal(err)
	}
	state := reopened.SnapshotRaft()
	if state.CurrentTerm != 2 || state.CommitIndex != 2 || state.LastApplied != 2 || len(state.Log) != 2 {
		t.Fatalf("persistent Raft state lost: %#v", state)
	}
}

func TestRaftAppendEntriesRejectsCommittedConflict(t *testing.T) {
	set, _ := testControlSet(t, 3)
	follower, err := OpenRaftStorage(filepath.Join(t.TempDir(), "raft.json"), set.Members[1].MemberID, set)
	if err != nil {
		t.Fatal(err)
	}
	first := testControlHead(t, &set)
	result, err := follower.HandleAppendEntries(AppendEntriesRequestV1{
		Term: 1, LeaderID: set.Members[0].MemberID, PrevLogHash: wire.EmptyHashV1,
		Entries: []RaftLogRecordV1{recordForEntry(first)}, LeaderCommit: 1,
	})
	if err != nil || !result.Success || result.MatchIndex != 1 {
		t.Fatalf("initial append result=%#v err=%v", result, err)
	}
	conflict := retermGenesis(t, first, 2)
	_, err = follower.HandleAppendEntries(AppendEntriesRequestV1{
		Term: 2, LeaderID: set.Members[2].MemberID, PrevLogHash: wire.EmptyHashV1,
		Entries: []RaftLogRecordV1{recordForEntry(conflict)}, LeaderCommit: 1,
	})
	if err == nil {
		t.Fatal("overwrote a committed log entry")
	}
}

func TestRaftVoteUsesLogFreshnessAndOneVotePerTerm(t *testing.T) {
	set, _ := testControlSet(t, 3)
	storage, _ := OpenRaftStorage(filepath.Join(t.TempDir(), "raft.json"), set.Members[0].MemberID, set)
	if _, err := storage.HandleAppendEntries(AppendEntriesRequestV1{
		Term: 2, LeaderID: set.Members[1].MemberID, PrevLogHash: wire.EmptyHashV1,
		Entries: []RaftLogRecordV1{recordForEntry(retermGenesis(t, testControlHead(t, &set), 2))},
	}); err != nil {
		t.Fatal(err)
	}
	stale, err := storage.HandleVote(VoteRequestV1{Term: 3, CandidateID: set.Members[1].MemberID, LastLogIndex: 0, LastLogTerm: 0})
	if err != nil || stale.Granted {
		t.Fatalf("stale candidate vote=%#v err=%v", stale, err)
	}
	fresh, err := storage.HandleVote(VoteRequestV1{Term: 3, CandidateID: set.Members[1].MemberID, LastLogIndex: 1, LastLogTerm: 2})
	if err != nil || !fresh.Granted {
		t.Fatalf("fresh candidate vote=%#v err=%v", fresh, err)
	}
	second, err := storage.HandleVote(VoteRequestV1{Term: 3, CandidateID: set.Members[2].MemberID, LastLogIndex: 1, LastLogTerm: 2})
	if err != nil || second.Granted {
		t.Fatalf("double vote=%#v err=%v", second, err)
	}
}

func TestAppendEntriesCanCatchUpOlderTermsInOneBatch(t *testing.T) {
	set, _ := testControlSet(t, 3)
	follower, _ := OpenRaftStorage(filepath.Join(t.TempDir(), "raft.json"), set.Members[2].MemberID, set)
	first := testControlHead(t, &set)
	second := nextOrdinaryHead(t, first, 2)
	result, err := follower.HandleAppendEntries(AppendEntriesRequestV1{
		Term: 2, LeaderID: set.Members[0].MemberID, PrevLogHash: wire.EmptyHashV1,
		Entries: []RaftLogRecordV1{recordForEntry(first), recordForEntry(second)}, LeaderCommit: 2,
	})
	if err != nil || !result.Success || result.MatchIndex != 2 {
		t.Fatalf("follower 未接受合法的跨任期 catch-up batch: %#v, %v", result, err)
	}
}

func TestAppendEntriesRejectsWholeInvalidBatchWithoutPartialMemoryMutation(t *testing.T) {
	set, _ := testControlSet(t, 3)
	follower, _ := OpenRaftStorage(filepath.Join(t.TempDir(), "raft.json"), set.Members[2].MemberID, set)
	first := testControlHead(t, &set)
	second := nextOrdinaryHead(t, first, 1)
	broken := recordForEntry(second)
	broken.Index++

	if _, err := follower.HandleAppendEntries(AppendEntriesRequestV1{
		Term: 1, LeaderID: set.Members[0].MemberID, PrevLogHash: wire.EmptyHashV1,
		Entries: []RaftLogRecordV1{recordForEntry(first), broken},
	}); err == nil {
		t.Fatal("接受了第二条坐标无效的 AppendEntries batch")
	}
	state := follower.SnapshotRaft()
	if state.CurrentTerm != 1 || len(state.Log) != 0 {
		t.Fatalf("无效 batch 泄漏了部分内存状态: %#v", state)
	}
	reopened, err := OpenRaftStorage(follower.path, set.Members[2].MemberID, set)
	if err != nil {
		t.Fatal(err)
	}
	if disk := reopened.SnapshotRaft(); disk.CurrentTerm != 1 || len(disk.Log) != 0 {
		t.Fatalf("无效 batch 泄漏了部分磁盘状态: %#v", disk)
	}
}
