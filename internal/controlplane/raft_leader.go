package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"loom/internal/wire"
)

// RaftPeer 是稳定配置 election/replication 所需的完整 private peer 能力。
type RaftPeer interface {
	RequestVote(context.Context, VoteRequestV1) (VoteResultV1, error)
	AppendEntries(context.Context, AppendEntriesRequestV1) (AppendEntriesResultV1, error)
}

// StableRaftLeader 只在一次已取得 committed ControlSet 多数的任期内有效；进程
// 重启后必须重新 campaign，不能从磁盘上的 self-vote 推导仍是 leader。
type StableRaftLeader struct {
	storage *RaftStorage
	set     wire.ControlSetV1
	peers   map[string]RaftPeer
	term    int64
}

type StableRaftCommitResult struct {
	Term                 int64
	Index                int64
	EntryHash            string
	CommitIndex          int64
	CommitKnownMemberIDs []string
}

// CampaignStableRaft 先做不落盘的 pre-vote，再 fsync self-vote 并取得稳定配置多数。
// 已有日志时会立即复制 current-term no-op barrier，确保旧任期 committed prefix 可由
// 新 leader 推进并恢复；空日志保留 index=1 给 bootstrap Head。
func CampaignStableRaft(ctx context.Context, storage *RaftStorage, set wire.ControlSetV1,
	peers map[string]RaftPeer) (*StableRaftLeader, error) {
	validated, err := validateStableRaftPeers(storage, set, peers)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot := storage.SnapshotRaft()
	if snapshot.CurrentTerm == int64(^uint64(0)>>1) {
		return nil, errors.New("[Raft] term 溢出")
	}
	lastIndex, lastTerm := lastLogCoordinates(snapshot.Log)
	preVote := VoteRequestV1{Term: snapshot.CurrentTerm + 1, CandidateID: snapshot.MemberID,
		LastLogIndex: lastIndex, LastLogTerm: lastTerm, PreVote: true}
	granted, observedTerm := collectRaftVotes(ctx, preVote, validated)
	if observedTerm > snapshot.CurrentTerm {
		_, observeErr := storage.ObserveTerm(observedTerm)
		if observeErr != nil {
			return nil, observeErr
		}
		return nil, errors.New("[Raft] pre-vote 观察到更高任期")
	}
	quorum, _ := wire.Quorum(len(set.Members))
	if granted < quorum {
		return nil, errors.New("[Raft] pre-vote 未达到 committed ControlSet 多数")
	}
	vote, err := storage.StartElection()
	if err != nil {
		return nil, err
	}
	granted, observedTerm = collectRaftVotes(ctx, vote, validated)
	if observedTerm > vote.Term {
		_, observeErr := storage.ObserveTerm(observedTerm)
		if observeErr != nil {
			return nil, observeErr
		}
		return nil, errors.New("[Raft] election 观察到更高任期")
	}
	if granted < quorum {
		return nil, errors.New("[Raft] election 未达到 committed ControlSet 多数")
	}
	leader := &StableRaftLeader{storage: storage, set: set, peers: validated, term: vote.Term}
	if len(snapshot.Log) > 0 {
		barrier, err := storage.AppendLocalNoOp()
		if err != nil {
			return nil, err
		}
		if _, err := leader.replicateThrough(ctx, barrier.Index, barrier.EntryHash); err != nil {
			return nil, fmt.Errorf("[Raft] current-term barrier 未提交: %w", err)
		}
	}
	return leader, nil
}

// ReplicateHead 只追加/提交本次 leader 任期的 exact Head。返回成功即本机
// commitIndex 已 fsync；CommitKnownMemberIDs 仅表示 commit 通知传播情况，不参与提交判定。
func (leader *StableRaftLeader) ReplicateHead(ctx context.Context, store *Store,
	entry wire.HeadEntryV2) (StableRaftCommitResult, error) {
	if leader == nil || leader.storage == nil || store == nil {
		return StableRaftCommitResult{}, errors.New("[Raft] leader/control store 未初始化")
	}
	state := leader.storage.SnapshotRaft()
	if state.CurrentTerm != leader.term || state.VotedFor != state.MemberID ||
		entry.Body.Payload.RaftTerm != leader.term {
		return StableRaftCommitResult{}, errors.New("[Raft] leader 任期已失效或 Head term 不匹配")
	}
	control := store.Snapshot()
	wantSetHash, _ := wire.ControlSetHash(&leader.set)
	controlSetHash, _ := wire.ControlSetHash(&control.ControlSet)
	if wantSetHash != controlSetHash || state.LastApplied != state.CommitIndex || control.Active != nil {
		return StableRaftCommitResult{}, errors.New("[Raft] 前一 committed Head 尚未 apply/certify，禁止追加下一 Head")
	}
	// 同一 leader 在少数派超时后可重发本机尚未 committed 的 exact tail；此时
	// authority parent 是它之前的 certified Head，而不是 tail 自己。
	targetAlreadyLogged := false
	scanFrom := len(state.Log) - 1
	entryIndex := entry.Body.Payload.RaftIndex
	if entryIndex >= 1 && entryIndex <= int64(len(state.Log)) {
		record := state.Log[entryIndex-1]
		if record.Kind == RaftRecordHead && record.Head != nil && record.EntryHash == entry.EntryHash &&
			wire.EqualCanonical(*record.Head, entry) {
			targetAlreadyLogged = true
			scanFrom = int(entryIndex) - 2
		}
	}
	var lastHead *wire.HeadEntryV2
	for index := scanFrom; index >= 0; index-- {
		if state.Log[index].Kind == RaftRecordHead && state.Log[index].Head != nil {
			lastHead = state.Log[index].Head
			break
		}
	}
	if lastHead != nil && (control.CertifiedHead == nil ||
		!wire.EqualCanonical(*control.CertifiedHead, *lastHead)) {
		return StableRaftCommitResult{}, errors.New("[Raft] control store 未持有前一 certified Head")
	}
	if targetAlreadyLogged && entryIndex != int64(len(state.Log)) {
		return StableRaftCommitResult{}, errors.New("[Raft] 只允许重试 exact uncommitted tail Head")
	}
	if err := leader.storage.AppendLocal(entry); err != nil {
		return StableRaftCommitResult{}, err
	}
	return leader.replicateThrough(ctx, entry.Body.Payload.RaftIndex, entry.EntryHash)
}

func (leader *StableRaftLeader) replicateThrough(ctx context.Context, index int64,
	entryHash string) (StableRaftCommitResult, error) {
	state := leader.storage.SnapshotRaft()
	if state.CurrentTerm != leader.term || state.VotedFor != state.MemberID || index < 1 ||
		index > int64(len(state.Log)) || state.Log[index-1].EntryHash != entryHash {
		return StableRaftCommitResult{}, errors.New("[Raft] replication target/leader term 无效")
	}
	request := AppendEntriesRequestV1{Term: leader.term, LeaderID: state.MemberID,
		PrevLogHash: wire.EmptyHashV1, Entries: cloneRaftState(state).Log, LeaderCommit: state.CommitIndex}
	matches, observedTerm := collectRaftAppends(ctx, request, leader.peers, int64(len(state.Log)))
	if observedTerm > leader.term {
		_, err := leader.storage.ObserveTerm(observedTerm)
		if err != nil {
			return StableRaftCommitResult{}, err
		}
		return StableRaftCommitResult{}, errors.New("[Raft] replication 观察到更高任期")
	}
	commitIndex, err := leader.storage.AdvanceLeaderCommit(matches)
	if err != nil {
		return StableRaftCommitResult{}, err
	}
	if commitIndex < index {
		return StableRaftCommitResult{}, errors.New("[Raft] durable replication 未达到 committed ControlSet 多数")
	}
	known, err := leader.BroadcastCommit(ctx)
	result := StableRaftCommitResult{Term: leader.term, Index: index, EntryHash: entryHash,
		CommitIndex: commitIndex, CommitKnownMemberIDs: known}
	if err != nil {
		// 此时 entry 已 committed；保留结果让调用者不能把 step-down 误报成未提交。
		return result, err
	}
	return result, nil
}

// BroadcastCommit 发送无 entry 的 post-commit heartbeat。少数 follower 暂时失败
// 不撤销已提交事实；若观察到更高 term，则耐久 step-down 并返回错误。
func (leader *StableRaftLeader) BroadcastCommit(ctx context.Context) ([]string, error) {
	if leader == nil || leader.storage == nil {
		return nil, errors.New("[Raft] leader 未初始化")
	}
	state := leader.storage.SnapshotRaft()
	if state.CurrentTerm != leader.term || state.VotedFor != state.MemberID {
		return nil, errors.New("[Raft] leader 任期已失效")
	}
	previousIndex, previousTerm := lastLogCoordinates(state.Log)
	previousHash := wire.EmptyHashV1
	if previousIndex > 0 {
		previousHash = state.Log[previousIndex-1].EntryHash
	}
	request := AppendEntriesRequestV1{Term: leader.term, LeaderID: state.MemberID,
		PrevLogIndex: previousIndex, PrevLogTerm: previousTerm, PrevLogHash: previousHash,
		LeaderCommit: state.CommitIndex}
	matches, observedTerm := collectRaftAppends(ctx, request, leader.peers, previousIndex)
	if observedTerm > leader.term {
		_, err := leader.storage.ObserveTerm(observedTerm)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("[Raft] commit broadcast 观察到更高任期")
	}
	known := []string{state.MemberID}
	for _, member := range leader.set.Members {
		if matches[member.MemberID] >= previousIndex && member.MemberID != state.MemberID {
			known = append(known, member.MemberID)
		}
	}
	sort.Strings(known)
	return known, nil
}

// ApplyCommittedPrefix 严格按 Raft index 重放本机 committed prefix。Head 的
// recompute 必须幂等；control state 先记录 exact commit reference，随后才推进 last_applied，
// 因而任一写点崩溃后可安全重跑。
func ApplyCommittedPrefix(ctx context.Context, storage *RaftStorage, store *Store,
	recompute HeadRecomputer) (int, error) {
	if storage == nil || store == nil || recompute == nil {
		return 0, errors.New("[apply] storage/store/recomputer 不能为空")
	}
	applied := 0
	for {
		if err := ctx.Err(); err != nil {
			return applied, err
		}
		raft := storage.SnapshotRaft()
		if raft.LastApplied == raft.CommitIndex {
			return applied, nil
		}
		if raft.LastApplied < 0 || raft.LastApplied >= int64(len(raft.Log)) {
			return applied, errors.New("[apply] committed prefix 坐标无效")
		}
		record := raft.Log[raft.LastApplied]
		switch record.Kind {
		case RaftRecordNoOp:
			// barrier 不产生应用状态，只推进同一 durable prefix 的 apply 坐标。
		case RaftRecordHead:
			if record.Head == nil {
				return applied, errors.New("[apply] committed Head record 缺 payload")
			}
			control := store.Snapshot()
			if control.Active != nil && control.Active.Entry.EntryHash != record.EntryHash {
				return applied, errors.New("[apply] 前一 committed Head 尚未取得 QC，冻结后续 Head")
			}
			alreadyFinished := control.Active == nil && control.CertifiedHead != nil &&
				control.CertifiedHead.EntryHash == record.EntryHash
			if !alreadyFinished {
				if err := recompute(ctx, *record.Head); err != nil {
					return applied, fmt.Errorf("[apply] deterministic recompute 拒绝 committed Head: %w", err)
				}
				if err := store.Prepare(*record.Head); err != nil {
					return applied, err
				}
				if err := store.CommitFromRaft(storage, record.EntryHash); err != nil {
					return applied, err
				}
			}
		default:
			return applied, errors.New("[apply] committed prefix 含未知 record kind")
		}
		if err := storage.MarkRaftApplied(record.Index); err != nil {
			return applied, err
		}
		applied++
	}
}

func validateStableRaftPeers(storage *RaftStorage, set wire.ControlSetV1,
	peers map[string]RaftPeer) (map[string]RaftPeer, error) {
	if storage == nil {
		return nil, errors.New("[Raft] storage 不能为空")
	}
	if err := wire.ValidateControlSet(&set); err != nil {
		return nil, err
	}
	state := storage.SnapshotRaft()
	wantHash, _ := wire.ControlSetHash(&set)
	storageHash, _ := wire.ControlSetHash(&storage.set)
	if state.VotingDisabled || storage.jointSet != nil || state.ClusterID != set.ClusterID || wantHash != storageHash ||
		len(peers) != len(set.Members)-1 {
		return nil, errors.New("[Raft] peer map 必须精确覆盖 committed ControlSet remotes")
	}
	result := make(map[string]RaftPeer, len(peers))
	for _, member := range set.Members {
		if member.MemberID == state.MemberID {
			if _, exists := peers[member.MemberID]; exists {
				return nil, errors.New("[Raft] peer map 不能把本机伪装成 remote")
			}
			continue
		}
		peer, exists := peers[member.MemberID]
		if !exists || peer == nil {
			return nil, errors.New("[Raft] peer map 缺 committed remote")
		}
		result[member.MemberID] = peer
	}
	return result, nil
}

func collectRaftVotes(ctx context.Context, request VoteRequestV1,
	peers map[string]RaftPeer) (int, int64) {
	type voteResult struct {
		result VoteResultV1
		err    error
	}
	results := make(chan voteResult, len(peers))
	for _, peer := range peers {
		peer := peer
		go func() {
			result, err := peer.RequestVote(ctx, request)
			results <- voteResult{result: result, err: err}
		}()
	}
	granted := 1 // self pre-vote/self-vote
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
				granted++
			}
		case <-ctx.Done():
			return granted, observedTerm
		}
	}
	return granted, observedTerm
}

func collectRaftAppends(ctx context.Context, request AppendEntriesRequestV1,
	peers map[string]RaftPeer, wantMatch int64) (map[string]int64, int64) {
	type appendResult struct {
		memberID string
		result   AppendEntriesResultV1
		err      error
	}
	results := make(chan appendResult, len(peers))
	for memberID, peer := range peers {
		memberID, peer := memberID, peer
		go func() {
			result, err := peer.AppendEntries(ctx, request)
			results <- appendResult{memberID: memberID, result: result, err: err}
		}()
	}
	matches := make(map[string]int64, len(peers))
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
			if response.result.Success && response.result.Term <= request.Term && response.result.MatchIndex == wantMatch {
				matches[response.memberID] = response.result.MatchIndex
			}
		case <-ctx.Done():
			return matches, observedTerm
		}
	}
	return matches, observedTerm
}
