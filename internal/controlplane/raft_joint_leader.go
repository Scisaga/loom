package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"loom/internal/wire"
)

// JointRaftLeader 只在 committed Joint(old,new) 尚未被 Final 取代的任期内有效。
// election、no-op barrier 与 Final commit 都必须分别满足 old/new 多数。
type JointRaftLeader struct {
	storage *RaftStorage
	oldSet  wire.ControlSetV1
	newSet  wire.ControlSetV1
	peers   map[string]RaftPeer
	term    int64
	closed  bool
}

// ReplicateJointControlSet 把 stable leader 切入 joint phase。learner 只参与复制；
// 只有 exact union peer 的 durable match 同时达到 old/new 多数后才记录并 apply Joint。
func (leader *StableRaftLeader) ReplicateJointControlSet(ctx context.Context, ledger *MembershipLedger,
	newSet wire.ControlSetV1, unionPeers map[string]RaftPeer,
	body wire.JointControlSetEntryBodyV1) (*JointRaftLeader, StableRaftCommitResult, error) {
	if leader == nil || leader.storage == nil || ledger == nil {
		return nil, StableRaftCommitResult{}, errors.New("[joint Raft] stable leader/ledger 未初始化")
	}
	peers, err := validateJointRaftPeers(leader.storage, leader.set, newSet, unionPeers, false)
	if err != nil {
		return nil, StableRaftCommitResult{}, err
	}
	state := leader.storage.SnapshotRaft()
	ledgerState := ledger.Snapshot()
	if state.CurrentTerm != leader.term || state.VotedFor != state.MemberID ||
		state.LastApplied != state.CommitIndex || ledgerState.Phase != MembershipLedgerApproved ||
		ledgerState.Candidate.MembershipApprovalProof == nil {
		return nil, StableRaftCommitResult{}, errors.New("[joint Raft] stable leader/ledger 尚未到 Joint append 边界")
	}
	for _, learner := range ledgerState.Candidate.Learners {
		if !learner.CaughtUp {
			return nil, StableRaftCommitResult{}, fmt.Errorf("[learner] %s 尚未 catch-up", learner.MemberID)
		}
	}
	oldHash, _ := wire.ControlSetHash(&leader.set)
	ledgerOldHash, _ := wire.ControlSetHash(&ledgerState.Candidate.OldControlSet)
	newHash, _ := wire.ControlSetHash(&newSet)
	ledgerNewHash, _ := wire.ControlSetHash(&ledgerState.Candidate.NewControlSet)
	if oldHash != ledgerOldHash || newHash != ledgerNewHash {
		return nil, StableRaftCommitResult{}, errors.New("[joint Raft] leader/ledger old/new ControlSet 不一致")
	}
	if err := leader.storage.AppendLocalJointControlSet(body, &leader.set, &newSet,
		ledgerState.Candidate.MembershipApprovalProof, &ledgerState.Candidate.ParentCurrent.Head); err != nil {
		return nil, StableRaftCommitResult{}, err
	}
	result, replicateErr := replicateThroughJoint(ctx, leader.storage, leader.term, leader.set,
		newSet, peers, body.RaftIndex, leader.storage.SnapshotRaft().Log[body.RaftIndex-1].EntryHash)
	if result.CommitIndex >= body.RaftIndex {
		_, applyErr := ApplyCommittedMembershipPrefix(ctx, leader.storage, ledger,
			func(context.Context, wire.HeadEntryV2) (string, string, error) {
				return "", "", errors.New("[joint apply] Joint 阶段不应 materialize Final")
			})
		if applyErr != nil {
			return nil, result, applyErr
		}
		jointLeader := &JointRaftLeader{storage: leader.storage, oldSet: leader.set,
			newSet: newSet, peers: peers, term: leader.term}
		return jointLeader, result, replicateErr
	}
	return nil, result, replicateErr
}

// CampaignJointRaft 在重启或 leader 故障后从 committed Joint 恢复联合选举。
func CampaignJointRaft(ctx context.Context, storage *RaftStorage, oldSet, newSet wire.ControlSetV1,
	unionPeers map[string]RaftPeer) (*JointRaftLeader, error) {
	peers, err := validateJointRaftPeers(storage, oldSet, newSet, unionPeers, true)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state := storage.SnapshotRaft()
	if state.CurrentTerm == int64(^uint64(0)>>1) {
		return nil, errors.New("[joint Raft] term 溢出")
	}
	lastIndex, lastTerm := lastLogCoordinates(state.Log)
	preVote := VoteRequestV1{Term: state.CurrentTerm + 1, CandidateID: state.MemberID,
		LastLogIndex: lastIndex, LastLogTerm: lastTerm, PreVote: true}
	granted, observedTerm := collectRaftVoteMembers(ctx, preVote, peers, state.MemberID)
	if observedTerm > state.CurrentTerm {
		_, observeErr := storage.ObserveTerm(observedTerm)
		if observeErr != nil {
			return nil, observeErr
		}
		return nil, errors.New("[joint Raft] pre-vote 观察到更高任期")
	}
	if err := wire.JointQuorum(&oldSet, &newSet, granted); err != nil {
		return nil, errors.New("[joint Raft] pre-vote 未同时达到 old/new 多数")
	}
	vote, err := storage.StartElection()
	if err != nil {
		return nil, err
	}
	granted, observedTerm = collectRaftVoteMembers(ctx, vote, peers, state.MemberID)
	if observedTerm > vote.Term {
		_, observeErr := storage.ObserveTerm(observedTerm)
		if observeErr != nil {
			return nil, observeErr
		}
		return nil, errors.New("[joint Raft] election 观察到更高任期")
	}
	if err := wire.JointQuorum(&oldSet, &newSet, granted); err != nil {
		return nil, errors.New("[joint Raft] election 未同时达到 old/new 多数")
	}
	leader := &JointRaftLeader{storage: storage, oldSet: oldSet, newSet: newSet,
		peers: peers, term: vote.Term}
	barrier, err := storage.AppendLocalNoOp()
	if err != nil {
		return nil, err
	}
	if _, err := leader.replicateThrough(ctx, barrier.Index, barrier.EntryHash); err != nil {
		return nil, fmt.Errorf("[joint Raft] current-term barrier 未提交: %w", err)
	}
	return leader, nil
}

// ReplicateFinalControlSet 在 joint-finalization-only 中提交唯一 Final，随后按序
// materialize/apply 并切换本机稳定 voter rules；返回后该 joint leader 永久失效。
func (leader *JointRaftLeader) ReplicateFinalControlSet(ctx context.Context, ledger *MembershipLedger,
	head wire.HeadEntryV2, materialize MembershipFinalMaterializer) (StableRaftCommitResult, error) {
	if leader == nil || leader.storage == nil || ledger == nil || materialize == nil || leader.closed {
		return StableRaftCommitResult{}, errors.New("[joint Raft] joint leader/ledger/materializer 无效")
	}
	state := leader.storage.SnapshotRaft()
	ledgerState := ledger.Snapshot()
	if state.CurrentTerm != leader.term || state.VotedFor != state.MemberID ||
		state.LastApplied != state.CommitIndex || ledgerState.Phase != MembershipLedgerJointFinalizationOnly ||
		ledgerState.Joint == nil || ledgerState.Joint.Proof == nil ||
		ledgerState.Candidate.MembershipApprovalProof == nil {
		return StableRaftCommitResult{}, errors.New("[joint Raft] 尚未到 certified Joint→Final 边界")
	}
	snapshotHash, effectiveSSOTHash, err := materialize(ctx, head)
	if err != nil {
		return StableRaftCommitResult{}, err
	}
	if _, err := wire.VerifyControlSetFinalCandidate(&leader.oldSet, &leader.newSet,
		ledgerState.Candidate.MembershipApprovalProof, ledgerState.Joint.Proof, &head,
		&ledgerState.Candidate.ParentCurrent.Head); err != nil {
		return StableRaftCommitResult{}, err
	}
	if err := wire.VerifyControlSetTransitionMaterialization(&head, snapshotHash, effectiveSSOTHash); err != nil {
		return StableRaftCommitResult{}, err
	}
	if err := leader.storage.AppendLocal(head); err != nil {
		return StableRaftCommitResult{}, err
	}
	result, replicateErr := leader.replicateThrough(ctx, head.Body.Payload.RaftIndex, head.EntryHash)
	if result.CommitIndex >= head.Body.Payload.RaftIndex {
		if _, err := ApplyCommittedMembershipPrefix(ctx, leader.storage, ledger, materialize); err != nil {
			return result, err
		}
		leader.closed = true
	}
	return result, replicateErr
}

func (leader *JointRaftLeader) replicateThrough(ctx context.Context, index int64,
	entryHash string) (StableRaftCommitResult, error) {
	if leader == nil || leader.closed {
		return StableRaftCommitResult{}, errors.New("[joint Raft] joint leader 已失效")
	}
	return replicateThroughJoint(ctx, leader.storage, leader.term, leader.oldSet, leader.newSet,
		leader.peers, index, entryHash)
}

func replicateThroughJoint(ctx context.Context, storage *RaftStorage, term int64, oldSet,
	newSet wire.ControlSetV1, peers map[string]RaftPeer, index int64,
	entryHash string) (StableRaftCommitResult, error) {
	state := storage.SnapshotRaft()
	if state.CurrentTerm != term || state.VotedFor != state.MemberID || index < 1 ||
		index > int64(len(state.Log)) || state.Log[index-1].EntryHash != entryHash {
		return StableRaftCommitResult{}, errors.New("[joint Raft] replication target/leader term 无效")
	}
	request := AppendEntriesRequestV1{Term: term, LeaderID: state.MemberID,
		PrevLogHash: wire.EmptyHashV1, Entries: cloneRaftState(state).Log, LeaderCommit: state.CommitIndex}
	matches, observedTerm := collectRaftAppends(ctx, request, peers, int64(len(state.Log)))
	if observedTerm > term {
		_, err := storage.ObserveTerm(observedTerm)
		if err != nil {
			return StableRaftCommitResult{}, err
		}
		return StableRaftCommitResult{}, errors.New("[joint Raft] replication 观察到更高任期")
	}
	commitIndex, err := storage.AdvanceJointLeaderCommit(matches, oldSet, newSet)
	if err != nil {
		return StableRaftCommitResult{}, err
	}
	result := StableRaftCommitResult{Term: term, Index: index, EntryHash: entryHash,
		CommitIndex: commitIndex}
	if commitIndex < index {
		return result, errors.New("[joint Raft] durable replication 未同时达到 old/new 多数")
	}
	known, broadcastErr := broadcastJointCommit(ctx, storage, term, oldSet, newSet, peers)
	result.CommitKnownMemberIDs = known
	return result, broadcastErr
}

func broadcastJointCommit(ctx context.Context, storage *RaftStorage, term int64, oldSet,
	newSet wire.ControlSetV1, peers map[string]RaftPeer) ([]string, error) {
	state := storage.SnapshotRaft()
	if state.CurrentTerm != term || state.VotedFor != state.MemberID {
		return nil, errors.New("[joint Raft] leader 任期已失效")
	}
	previousIndex, previousTerm := lastLogCoordinates(state.Log)
	previousHash := wire.EmptyHashV1
	if previousIndex > 0 {
		previousHash = state.Log[previousIndex-1].EntryHash
	}
	request := AppendEntriesRequestV1{Term: term, LeaderID: state.MemberID,
		PrevLogIndex: previousIndex, PrevLogTerm: previousTerm, PrevLogHash: previousHash,
		LeaderCommit: state.CommitIndex}
	matches, observedTerm := collectRaftAppends(ctx, request, peers, previousIndex)
	if observedTerm > term {
		_, err := storage.ObserveTerm(observedTerm)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("[joint Raft] commit broadcast 观察到更高任期")
	}
	known := []string{state.MemberID}
	for memberID, index := range matches {
		if index >= previousIndex {
			known = append(known, memberID)
		}
	}
	sort.Strings(known)
	return known, nil
}

func validateJointRaftPeers(storage *RaftStorage, oldSet, newSet wire.ControlSetV1,
	peers map[string]RaftPeer, requireActive bool) (map[string]RaftPeer, error) {
	if storage == nil {
		return nil, errors.New("[joint Raft] storage 不能为空")
	}
	if err := wire.ValidateControlSet(&oldSet); err != nil {
		return nil, err
	}
	if err := wire.ValidateControlSet(&newSet); err != nil {
		return nil, err
	}
	oldHash, _ := wire.ControlSetHash(&oldSet)
	storageHash, _ := wire.ControlSetHash(&storage.set)
	state := storage.SnapshotRaft()
	if oldSet.ClusterID != newSet.ClusterID || oldHash != storageHash || state.VotingDisabled ||
		requireActive && storage.jointSet == nil || !requireActive && storage.jointSet != nil {
		return nil, errors.New("[joint Raft] storage old/new/joint phase 不一致")
	}
	if storage.jointSet != nil {
		activeHash, _ := wire.ControlSetHash(storage.jointSet)
		newHash, _ := wire.ControlSetHash(&newSet)
		if activeHash != newHash {
			return nil, errors.New("[joint Raft] active new ControlSet 不匹配")
		}
	}
	union := make(map[string]struct{}, len(oldSet.Members)+len(newSet.Members))
	for _, set := range []*wire.ControlSetV1{&oldSet, &newSet} {
		for _, member := range set.Members {
			union[member.MemberID] = struct{}{}
		}
	}
	if _, exists := union[state.MemberID]; !exists || len(peers) != len(union)-1 {
		return nil, errors.New("[joint Raft] peer map 未 exact-cover Joint union remotes")
	}
	result := make(map[string]RaftPeer, len(peers))
	for memberID := range union {
		if memberID == state.MemberID {
			if _, exists := peers[memberID]; exists {
				return nil, errors.New("[joint Raft] peer map 不能包含本机")
			}
			continue
		}
		peer, exists := peers[memberID]
		if !exists || peer == nil {
			return nil, errors.New("[joint Raft] peer map 缺 Joint union remote")
		}
		result[memberID] = peer
	}
	return result, nil
}

func collectRaftVoteMembers(ctx context.Context, request VoteRequestV1,
	peers map[string]RaftPeer, selfID string) ([]string, int64) {
	type voteResult struct {
		memberID string
		result   VoteResultV1
		err      error
	}
	results := make(chan voteResult, len(peers))
	for memberID, peer := range peers {
		memberID, peer := memberID, peer
		go func() {
			result, err := peer.RequestVote(ctx, request)
			results <- voteResult{memberID: memberID, result: result, err: err}
		}()
	}
	granted := []string{selfID}
	observedTerm := int64(0)
	for range peers {
		select {
		case response := <-results:
			if response.err != nil || response.result.Term < 0 {
				continue
			}
			if response.result.Term > observedTerm {
				observedTerm = response.result.Term
			}
			if response.result.Granted && response.result.Term <= request.Term {
				granted = append(granted, response.memberID)
			}
		case <-ctx.Done():
			sort.Strings(granted)
			return granted, observedTerm
		}
	}
	sort.Strings(granted)
	return granted, observedTerm
}
