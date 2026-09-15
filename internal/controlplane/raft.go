package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"loom/internal/wire"
)

const (
	RaftRecordHead            = "head"
	RaftRecordJointControlSet = "joint_control_set"
	RaftRecordNoOp            = "no_op"
	raftNoOpDomain            = "loom-raft-no-op-entry-v1"
)

// RaftNoOpEntryV1 是新 leader 用来提交旧任期 prefix 的私有 current-term barrier；
// 它不产生 Head，但其 hash 仍进入下一条日志的 previous_log_entry_hash。
type RaftNoOpEntryV1 struct {
	Schema               int    `json:"schema"`
	ClusterID            string `json:"cluster_id"`
	RaftTerm             int64  `json:"raft_term"`
	RaftIndex            int64  `json:"raft_index"`
	PreviousLogEntryHash string `json:"previous_log_entry_hash"`
}

// RaftLogRecordV1 保存 exact tagged entry 与 Raft 坐标的冗余绑定，加载时会全部重算。
type RaftLogRecordV1 struct {
	Term            int64                            `json:"term"`
	Index           int64                            `json:"index"`
	EntryHash       string                           `json:"entry_hash"`
	Kind            string                           `json:"kind"`
	Head            *wire.HeadEntryV2                `json:"head,omitempty"`
	JointControlSet *wire.JointControlSetEntryBodyV1 `json:"joint_control_set,omitempty"`
	NoOp            *RaftNoOpEntryV1                 `json:"no_op,omitempty"`
}

type RaftPersistentStateV1 struct {
	Schema         int               `json:"schema"`
	ClusterID      string            `json:"cluster_id"`
	MemberID       string            `json:"member_id"`
	ControlSetHash string            `json:"control_set_hash"`
	VotingDisabled bool              `json:"voting_disabled"`
	CurrentTerm    int64             `json:"current_term"`
	VotedFor       string            `json:"voted_for,omitempty"`
	Log            []RaftLogRecordV1 `json:"log"`
	CommitIndex    int64             `json:"commit_index"`
	LastApplied    int64             `json:"last_applied"`
}

type VoteRequestV1 struct {
	Term         int64  `json:"term"`
	CandidateID  string `json:"candidate_id"`
	LastLogIndex int64  `json:"last_log_index"`
	LastLogTerm  int64  `json:"last_log_term"`
	PreVote      bool   `json:"pre_vote"`
}

type VoteResultV1 struct {
	Term    int64 `json:"term"`
	Granted bool  `json:"granted"`
}

type AppendEntriesRequestV1 struct {
	Term         int64             `json:"term"`
	LeaderID     string            `json:"leader_id"`
	PrevLogIndex int64             `json:"prev_log_index"`
	PrevLogTerm  int64             `json:"prev_log_term"`
	PrevLogHash  string            `json:"prev_log_hash"`
	Entries      []RaftLogRecordV1 `json:"entries"`
	LeaderCommit int64             `json:"leader_commit"`
}

type AppendEntriesResultV1 struct {
	Term       int64 `json:"term"`
	Success    bool  `json:"success"`
	MatchIndex int64 `json:"match_index"`
}

// RaftStorage 提供持久状态机边界；网络层只传递以上消息，不能绕过这里写日志。
type RaftStorage struct {
	mu       sync.Mutex
	path     string
	set      wire.ControlSetV1
	jointSet *wire.ControlSetV1
	state    RaftPersistentStateV1
}

func OpenRaftStorage(path, memberID string, set wire.ControlSetV1) (*RaftStorage, error) {
	if path == "" || memberID == "" {
		return nil, errors.New("[Raft] storage path/member ID 不能为空")
	}
	if err := wire.ValidateControlSet(&set); err != nil {
		return nil, err
	}
	storage := &RaftStorage{path: path, set: set, state: RaftPersistentStateV1{
		Schema: 3, ClusterID: set.ClusterID, MemberID: memberID, Log: []RaftLogRecordV1{},
	}}
	storage.state.ControlSetHash, _ = wire.ControlSetHash(&set)
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if !controlSetContains(&set, memberID) {
			return nil, errors.New("[Raft] 新 storage 的本机 member 不在 committed ControlSet")
		}
		return storage, nil
	}
	if err != nil {
		return nil, err
	}
	var state RaftPersistentStateV1
	if _, err := wire.DecodeStrict(body, 64<<20, &state); err != nil {
		return nil, fmt.Errorf("[Raft] persistent state 解码失败: %w", err)
	}
	if state.Schema == 2 && state.ControlSetHash == "" {
		state.Schema = 3
		state.ControlSetHash, _ = wire.ControlSetHash(&set)
		if err := validateRaftPersistentState(&state, &set); err != nil {
			return nil, err
		}
		storage.state = state
		if err := storage.persistRaftStateLocked(&state); err != nil {
			return nil, err
		}
		return storage, nil
	}
	if err := validateRaftPersistentState(&state, &set); err != nil {
		return nil, err
	}
	if activeJointRecord(&state) != nil {
		return nil, errors.New("[joint Raft] committed Joint 必须用 OpenJointRaftStorage 恢复")
	}
	if state.MemberID != memberID {
		return nil, errors.New("[Raft] 磁盘 member ID 与启动身份不一致")
	}
	storage.state = state
	return storage, nil
}

// OpenRaftLearnerStorage 创建不具投票权的新 member 存储；它只能通过 learner
// AppendEntries 追平 old stable prefix，直到 committed Joint 激活联合配置。
func OpenRaftLearnerStorage(path, memberID string, oldSet wire.ControlSetV1) (*RaftStorage, error) {
	if path == "" || memberID == "" || controlSetContains(&oldSet, memberID) {
		return nil, errors.New("[learner Raft] learner path/member 必须位于 old ControlSet 之外")
	}
	if err := wire.ValidateControlSet(&oldSet); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return nil, errors.New("[learner Raft] learner storage 已存在，必须显式恢复")
		}
		return nil, err
	}
	storage := &RaftStorage{path: path, set: oldSet, state: RaftPersistentStateV1{
		Schema: 3, ClusterID: oldSet.ClusterID, MemberID: memberID, VotingDisabled: true,
		Log: []RaftLogRecordV1{},
	}}
	storage.state.ControlSetHash, _ = wire.ControlSetHash(&oldSet)
	if err := storage.persistRaftStateLocked(&storage.state); err != nil {
		return nil, err
	}
	return storage, nil
}

// OpenJointRaftStorage 从 committed Joint record 恢复 old/new 联合投票规则；仅传入
// 一侧集合或错误 new set 都会失败关闭，不能重启后退回 old stable quorum。
func OpenJointRaftStorage(path, memberID string, oldSet, newSet wire.ControlSetV1) (*RaftStorage, error) {
	if err := wire.ValidateControlSet(&oldSet); err != nil {
		return nil, err
	}
	if err := wire.ValidateControlSet(&newSet); err != nil {
		return nil, err
	}
	if oldSet.ClusterID != newSet.ClusterID ||
		!controlSetContains(&oldSet, memberID) && !controlSetContains(&newSet, memberID) {
		return nil, errors.New("[joint Raft] local member/old/new ControlSet 无效")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state RaftPersistentStateV1
	if _, err := wire.DecodeStrict(body, 64<<20, &state); err != nil {
		return nil, fmt.Errorf("[joint Raft] persistent state 解码失败: %w", err)
	}
	joint := activeJointRecord(&state)
	oldHash, _ := wire.ControlSetHash(&oldSet)
	newHash, _ := wire.ControlSetHash(&newSet)
	if joint == nil || state.ControlSetHash != oldHash || joint.OldControlSetHash != oldHash ||
		joint.NewControlSetHash != newHash || state.MemberID != memberID {
		return nil, errors.New("[joint Raft] committed Joint 与启动 authority 不一致")
	}
	storage := &RaftStorage{path: path, set: oldSet, jointSet: cloneControlSetPointer(&newSet), state: state}
	if err := validateRaftPersistentStateWithJoint(&state, &oldSet, &newSet); err != nil {
		return nil, err
	}
	if state.VotingDisabled {
		candidate := cloneRaftState(state)
		candidate.VotingDisabled = false
		candidate.VotedFor = ""
		if err := storage.commitRaftStateLocked(candidate); err != nil {
			return nil, err
		}
	}
	return storage, nil
}

func (s *RaftStorage) SnapshotRaft() RaftPersistentStateV1 {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, _ := json.Marshal(s.state)
	var copy RaftPersistentStateV1
	_ = json.Unmarshal(body, &copy)
	return copy
}

// StartElection 原子增加 term 并先把 self-vote fsync，之后才能发送 RequestVote。
func (s *RaftStorage) StartElection() (VoteRequestV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.VotingDisabled {
		return VoteRequestV1{}, errors.New("[joint Raft] 已移除 member 禁止发起选举")
	}
	if s.state.CurrentTerm == int64(^uint64(0)>>1) {
		return VoteRequestV1{}, errors.New("[Raft] term 溢出")
	}
	candidate := cloneRaftState(s.state)
	candidate.CurrentTerm++
	candidate.VotedFor = candidate.MemberID
	if err := s.commitRaftStateLocked(candidate); err != nil {
		return VoteRequestV1{}, err
	}
	lastIndex, lastTerm := lastLogCoordinates(s.state.Log)
	return VoteRequestV1{Term: s.state.CurrentTerm, CandidateID: s.state.MemberID, LastLogIndex: lastIndex, LastLogTerm: lastTerm}, nil
}

// ObserveTerm 在任何 peer 回应更高 term 时先耐久化并清空旧 vote；调用者随后必须
// 放弃当前 campaign/leader 身份，不能继续追加或推进 commit。
func (s *RaftStorage) ObserveTerm(term int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if term < 1 {
		return false, errors.New("[Raft] observed term 无效")
	}
	if term <= s.state.CurrentTerm {
		return false, nil
	}
	candidate := cloneRaftState(s.state)
	candidate.CurrentTerm = term
	candidate.VotedFor = ""
	if err := s.commitRaftStateLocked(candidate); err != nil {
		return false, err
	}
	return true, nil
}

// HandleVote 同时承载 pre-vote；pre-vote 永远不修改 current_term/voted_for。
func (s *RaftStorage) HandleVote(request VoteRequestV1) (VoteResultV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if request.Term < 1 || request.LastLogIndex < 0 || request.LastLogTerm < 0 ||
		!raftAuthorityContains(s, request.CandidateID) {
		return VoteResultV1{}, errors.New("[Raft] vote request 字段或 candidate 无效")
	}
	if s.state.VotingDisabled {
		return VoteResultV1{Term: s.state.CurrentTerm}, nil
	}
	if request.Term < s.state.CurrentTerm || request.PreVote && request.Term < s.state.CurrentTerm+1 {
		return VoteResultV1{Term: s.state.CurrentTerm}, nil
	}
	lastIndex, lastTerm := lastLogCoordinates(s.state.Log)
	upToDate := request.LastLogTerm > lastTerm || request.LastLogTerm == lastTerm && request.LastLogIndex >= lastIndex
	if request.PreVote {
		return VoteResultV1{Term: s.state.CurrentTerm, Granted: upToDate}, nil
	}
	candidate := cloneRaftState(s.state)
	changed := false
	if request.Term > candidate.CurrentTerm {
		candidate.CurrentTerm = request.Term
		candidate.VotedFor = ""
		changed = true
	}
	granted := upToDate && (candidate.VotedFor == "" || candidate.VotedFor == request.CandidateID)
	if granted && candidate.VotedFor != request.CandidateID {
		candidate.VotedFor = request.CandidateID
		changed = true
	}
	if changed {
		if err := s.commitRaftStateLocked(candidate); err != nil {
			return VoteResultV1{}, err
		}
	}
	return VoteResultV1{Term: candidate.CurrentTerm, Granted: granted}, nil
}

// AppendLocal 只追加当前 leader 已严格构造的连续 entry；commit 仍须走 AdvanceLeaderCommit。
func (s *RaftStorage) AppendLocal(entry wire.HeadEntryV2) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.VotingDisabled {
		return errors.New("[joint Raft] 已移除 member 禁止追加日志")
	}
	if s.jointSet != nil && entry.Body.Payload.HeadKind != "control_set_final" {
		return errors.New("[joint Raft] joint-finalization-only 禁止追加普通 Head")
	}
	if entry.Body.Payload.ClusterID != s.state.ClusterID {
		return errors.New("[Raft] local entry cluster 不匹配")
	}
	entryIndex := entry.Body.Payload.RaftIndex
	if entryIndex >= 1 && entryIndex <= int64(len(s.state.Log)) {
		existing := s.state.Log[entryIndex-1]
		if existing.Kind == RaftRecordHead && existing.Head != nil && existing.EntryHash == entry.EntryHash &&
			wire.EqualCanonical(*existing.Head, entry) {
			return nil
		}
		return errors.New("[Raft] local append 与既有日志坐标冲突")
	}
	if entry.Body.Payload.RaftTerm != s.state.CurrentTerm || s.state.CurrentTerm < 1 {
		return errors.New("[Raft] leader 只能追加当前任期 entry")
	}
	lastIndex, _ := lastLogCoordinates(s.state.Log)
	if entry.Body.Payload.RaftIndex != lastIndex+1 {
		return errors.New("[Raft] local append index 不连续")
	}
	record := recordForEntry(entry)
	if err := validateRaftRecord(&record, s.state.Log); err != nil {
		return err
	}
	candidate := cloneRaftState(s.state)
	candidate.Log = append(candidate.Log, cloneRaftRecord(record))
	return s.commitRaftStateLocked(candidate)
}

// AppendLocalJointControlSet 只追加已经通过完整 membership approval/PoP/parent
// 验证的 Joint entry。它仍是普通 Raft 日志项，后续只能由 old/new 双多数推进提交。
func (s *RaftStorage) AppendLocalJointControlSet(body wire.JointControlSetEntryBodyV1,
	oldSet, newSet *wire.ControlSetV1, approval *wire.ControlMembershipApprovalProofV1,
	parent *wire.HeadEntryV2) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.VotingDisabled {
		return errors.New("[joint Raft] 已移除 member 禁止追加 Joint")
	}
	if s.jointSet != nil {
		return errors.New("[joint Raft] 已有 active Joint，禁止追加第二个 transition")
	}
	oldHash, oldErr := wire.ControlSetHash(oldSet)
	storageHash, storageErr := wire.ControlSetHash(&s.set)
	entryHash, verifyErr := wire.VerifyJointControlSetCandidate(oldSet, newSet, approval, &body, parent)
	if oldErr != nil || storageErr != nil || verifyErr != nil || oldHash != storageHash ||
		body.ClusterID != s.state.ClusterID {
		return errors.New("[joint Raft] Joint candidate/稳定 ControlSet authority 无效")
	}
	if body.RaftTerm != s.state.CurrentTerm || s.state.CurrentTerm < 1 ||
		body.RaftIndex != int64(len(s.state.Log))+1 {
		return errors.New("[joint Raft] leader 只能连续追加当前任期 Joint entry")
	}
	record := recordForJointControlSet(body, entryHash)
	if err := validateRaftRecord(&record, s.state.Log); err != nil {
		return err
	}
	candidate := cloneRaftState(s.state)
	candidate.Log = append(candidate.Log, cloneRaftRecord(record))
	return s.commitRaftStateLocked(candidate)
}

// AppendLocalNoOp 追加 current-term barrier；只由完成 quorum election 的 leader 调用。
func (s *RaftStorage) AppendLocalNoOp() (RaftLogRecordV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.VotingDisabled {
		return RaftLogRecordV1{}, errors.New("[joint Raft] 已移除 member 禁止追加 no-op")
	}
	if s.state.CurrentTerm < 1 || s.state.VotedFor != s.state.MemberID {
		return RaftLogRecordV1{}, errors.New("[Raft] 未进入本机发起的任期，禁止追加 no-op")
	}
	index := int64(len(s.state.Log)) + 1
	previous := wire.EmptyHashV1
	if len(s.state.Log) > 0 {
		previous = s.state.Log[len(s.state.Log)-1].EntryHash
	}
	body := RaftNoOpEntryV1{Schema: 1, ClusterID: s.state.ClusterID, RaftTerm: s.state.CurrentTerm,
		RaftIndex: index, PreviousLogEntryHash: previous}
	hash, err := wire.HashObject(raftNoOpDomain, body)
	if err != nil {
		return RaftLogRecordV1{}, err
	}
	record := RaftLogRecordV1{Term: body.RaftTerm, Index: body.RaftIndex, EntryHash: hash,
		Kind: RaftRecordNoOp, NoOp: &body}
	if err := validateRaftRecord(&record, s.state.Log); err != nil {
		return RaftLogRecordV1{}, err
	}
	candidate := cloneRaftState(s.state)
	candidate.Log = append(candidate.Log, record)
	if err := s.commitRaftStateLocked(candidate); err != nil {
		return RaftLogRecordV1{}, err
	}
	return cloneRaftRecord(record), nil
}

// HandleAppendEntries 实现 log matching，并禁止覆盖任何 committed prefix。
func (s *RaftStorage) HandleAppendEntries(request AppendEntriesRequestV1) (AppendEntriesResultV1, error) {
	return s.handleAppendEntries(request, false)
}

// HandleLearnerAppendEntries 只允许尚未进入 committed Joint 的 non-voter 从 old
// stable leader 复制日志；它不开放 RequestVote，也不把 learner 算入 quorum。
func (s *RaftStorage) HandleLearnerAppendEntries(request AppendEntriesRequestV1) (AppendEntriesResultV1, error) {
	return s.handleAppendEntries(request, true)
}

func (s *RaftStorage) handleAppendEntries(request AppendEntriesRequestV1,
	allowLearner bool) (AppendEntriesResultV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if request.Term < 1 || request.PrevLogIndex < 0 || request.PrevLogTerm < 0 || request.LeaderCommit < 0 ||
		!raftAuthorityContains(s, request.LeaderID) {
		return AppendEntriesResultV1{}, errors.New("[Raft] AppendEntries header/leader 无效")
	}
	if s.state.VotingDisabled && (!allowLearner || s.jointSet != nil || controlSetContains(&s.set, s.state.MemberID)) {
		return AppendEntriesResultV1{Term: s.state.CurrentTerm}, nil
	}
	if request.Term < s.state.CurrentTerm {
		return AppendEntriesResultV1{Term: s.state.CurrentTerm}, nil
	}
	termChanged := request.Term > s.state.CurrentTerm
	if termChanged {
		termState := cloneRaftState(s.state)
		termState.CurrentTerm = request.Term
		termState.VotedFor = ""
		// 高任期即使随后因日志不匹配被拒绝，也必须先耐久化，避免崩溃后在旧任期投票。
		if err := s.commitRaftStateLocked(termState); err != nil {
			return AppendEntriesResultV1{}, err
		}
	}
	if !matchesPrevious(s.state.Log, request.PrevLogIndex, request.PrevLogTerm, request.PrevLogHash) {
		return AppendEntriesResultV1{Term: s.state.CurrentTerm}, nil
	}
	candidate := cloneRaftState(s.state)
	for i := range request.Entries {
		expectedIndex := request.PrevLogIndex + int64(i) + 1
		incoming := cloneRaftRecord(request.Entries[i])
		record := &incoming
		// AppendEntries 可携本届 leader 用来补齐 follower 的旧任期 entry；只禁止
		// future term，不能错误要求整批记录都等于 RPC term（Raft）。
		if record.Index != expectedIndex || record.Term < 1 || record.Term > request.Term {
			return AppendEntriesResultV1{}, errors.New("[Raft] AppendEntries record 坐标/hash 不一致")
		}
		existingIndex := int(expectedIndex - 1)
		if existingIndex < len(candidate.Log) {
			existing := candidate.Log[existingIndex]
			if existing.Term == record.Term && existing.EntryHash == record.EntryHash && wire.EqualCanonical(existing, *record) {
				continue
			}
			if expectedIndex <= candidate.CommitIndex {
				return AppendEntriesResultV1{}, errors.New("[Raft] 禁止覆盖 committed log prefix")
			}
			candidate.Log = candidate.Log[:existingIndex]
		}
		if raftRecordClusterID(record) != s.state.ClusterID {
			return AppendEntriesResultV1{}, errors.New("[Raft] AppendEntries record cluster 不匹配")
		}
		if err := validateRaftRecord(record, candidate.Log); err != nil {
			return AppendEntriesResultV1{}, err
		}
		candidate.Log = append(candidate.Log, incoming)
	}
	lastIndex := int64(len(candidate.Log))
	if request.LeaderCommit > candidate.CommitIndex {
		candidate.CommitIndex = request.LeaderCommit
		if candidate.CommitIndex > lastIndex {
			candidate.CommitIndex = lastIndex
		}
	}
	if err := s.commitRaftStateLocked(candidate); err != nil {
		return AppendEntriesResultV1{}, err
	}
	return AppendEntriesResultV1{Term: s.state.CurrentTerm, Success: true, MatchIndex: request.PrevLogIndex + int64(len(request.Entries))}, nil
}

// AdvanceLeaderCommit 只用当前 term 的条目推进 commit；match map 不能改变 committed N。
func (s *RaftStorage) AdvanceLeaderCommit(match map[string]int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.CurrentTerm < 1 || s.state.VotingDisabled || s.jointSet != nil {
		return s.state.CommitIndex, errors.New("[Raft] 尚无当前任期")
	}
	indices := make(map[string]int64, len(match)+1)
	for memberID, index := range match {
		if !controlSetContains(&s.set, memberID) || index < 0 || index > int64(len(s.state.Log)) {
			return s.state.CommitIndex, errors.New("[Raft] match index 含未知成员或越界")
		}
		indices[memberID] = index
	}
	indices[s.state.MemberID] = int64(len(s.state.Log))
	quorum, _ := wire.Quorum(len(s.set.Members))
	for candidate := int64(len(s.state.Log)); candidate > s.state.CommitIndex; candidate-- {
		if s.state.Log[candidate-1].Term != s.state.CurrentTerm {
			continue
		}
		if requiresJointCommit(&s.state, &s.set, candidate) {
			return s.state.CommitIndex, errors.New("[joint Raft] Joint/Final 不能按 stable quorum 提交")
		}
		count := 0
		for _, index := range indices {
			if index >= candidate {
				count++
			}
		}
		if count >= quorum {
			next := cloneRaftState(s.state)
			next.CommitIndex = candidate
			if err := s.commitRaftStateLocked(next); err != nil {
				return 0, err
			}
			break
		}
	}
	return s.state.CommitIndex, nil
}

// AdvanceJointLeaderCommit 按 frozen old/new ControlSet 分别计算多数；一个同时属于
// 两侧的 member 可在两侧各计一次，但调用方不能用在线子集缩小任一门槛。
func (s *RaftStorage) AdvanceJointLeaderCommit(match map[string]int64,
	oldSet, newSet wire.ControlSetV1) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.CurrentTerm < 1 || s.state.VotingDisabled {
		return s.state.CommitIndex, errors.New("[joint Raft] 尚无当前任期")
	}
	if err := wire.ValidateControlSet(&oldSet); err != nil {
		return s.state.CommitIndex, err
	}
	if err := wire.ValidateControlSet(&newSet); err != nil {
		return s.state.CommitIndex, err
	}
	oldHash, _ := wire.ControlSetHash(&oldSet)
	storageHash, _ := wire.ControlSetHash(&s.set)
	if oldHash != storageHash || oldSet.ClusterID != newSet.ClusterID || oldSet.ClusterID != s.state.ClusterID {
		return s.state.CommitIndex, errors.New("[joint Raft] old/new/storage authority 不一致")
	}
	if s.jointSet != nil {
		activeHash, _ := wire.ControlSetHash(s.jointSet)
		newHash, _ := wire.ControlSetHash(&newSet)
		if activeHash != newHash {
			return s.state.CommitIndex, errors.New("[joint Raft] new ControlSet 与 active Joint 不一致")
		}
	}
	indices := make(map[string]int64, len(match)+1)
	for memberID, index := range match {
		if !controlSetContains(&oldSet, memberID) && !controlSetContains(&newSet, memberID) ||
			index < 0 || index > int64(len(s.state.Log)) {
			return s.state.CommitIndex, errors.New("[joint Raft] match index 含 joint union 外成员或越界")
		}
		indices[memberID] = index
	}
	if !controlSetContains(&oldSet, s.state.MemberID) && !controlSetContains(&newSet, s.state.MemberID) {
		return s.state.CommitIndex, errors.New("[joint Raft] 本机不在 frozen joint union")
	}
	indices[s.state.MemberID] = int64(len(s.state.Log))
	oldQuorum, _ := wire.Quorum(len(oldSet.Members))
	newQuorum, _ := wire.Quorum(len(newSet.Members))
	for candidate := int64(len(s.state.Log)); candidate > s.state.CommitIndex; candidate-- {
		if s.state.Log[candidate-1].Term != s.state.CurrentTerm ||
			!requiresJointCommit(&s.state, &s.set, candidate) {
			continue
		}
		oldVotes, newVotes := 0, 0
		for memberID, index := range indices {
			if index < candidate {
				continue
			}
			if controlSetContains(&oldSet, memberID) {
				oldVotes++
			}
			if controlSetContains(&newSet, memberID) {
				newVotes++
			}
		}
		if oldVotes >= oldQuorum && newVotes >= newQuorum {
			next := cloneRaftState(s.state)
			next.CommitIndex = candidate
			if err := s.commitRaftStateLocked(next); err != nil {
				return 0, err
			}
			break
		}
	}
	return s.state.CommitIndex, nil
}

func (s *RaftStorage) MarkRaftApplied(index int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index != s.state.LastApplied+1 || index > s.state.CommitIndex {
		return errors.New("[Raft] apply 必须在 committed prefix 内严格连续")
	}
	candidate := cloneRaftState(s.state)
	candidate.LastApplied = index
	return s.commitRaftStateLocked(candidate)
}

func (s *RaftStorage) CommittedAfter(index int64) ([]RaftLogRecordV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index > s.state.CommitIndex {
		return nil, errors.New("[Raft] committed read index 越界")
	}
	result := make([]RaftLogRecordV1, 0, s.state.CommitIndex-index)
	for _, record := range s.state.Log[index:s.state.CommitIndex] {
		result = append(result, cloneRaftRecord(record))
	}
	return result, nil
}

// ActivateJointControlSet 从本机 committed prefix 恢复联合配置；new learner 到此
// 才解除 voting_disabled，随后选举与提交必须同时满足 old/new 多数。
func (s *RaftStorage) ActivateJointControlSet(oldSet, newSet wire.ControlSetV1,
	jointEntryHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := wire.ValidateControlSet(&oldSet); err != nil {
		return err
	}
	if err := wire.ValidateControlSet(&newSet); err != nil {
		return err
	}
	oldHash, _ := wire.ControlSetHash(&oldSet)
	newHash, _ := wire.ControlSetHash(&newSet)
	storageHash, _ := wire.ControlSetHash(&s.set)
	joint := activeJointRecord(&s.state)
	if storageHash != oldHash || s.state.ControlSetHash != oldHash || oldSet.ClusterID != newSet.ClusterID ||
		joint == nil || joint.OldControlSetHash != oldHash || joint.NewControlSetHash != newHash {
		return errors.New("[joint Raft] committed Joint 与 old/new authority 不一致")
	}
	index := joint.RaftIndex
	if index < 1 || index > s.state.CommitIndex || index > int64(len(s.state.Log)) ||
		s.state.Log[index-1].EntryHash != jointEntryHash {
		return errors.New("[joint Raft] Joint entry/hash 尚未 committed")
	}
	if !controlSetContains(&oldSet, s.state.MemberID) && !controlSetContains(&newSet, s.state.MemberID) {
		return errors.New("[joint Raft] 本机不在 Joint union")
	}
	if s.jointSet != nil {
		activeHash, _ := wire.ControlSetHash(s.jointSet)
		if activeHash == newHash && !s.state.VotingDisabled {
			return nil
		}
		return errors.New("[joint Raft] 已激活 Joint authority 冲突")
	}
	candidate := cloneRaftState(s.state)
	candidate.VotingDisabled = false
	if candidate.VotedFor != "" && !controlSetContains(&oldSet, candidate.VotedFor) &&
		!controlSetContains(&newSet, candidate.VotedFor) {
		candidate.VotedFor = ""
	}
	if err := s.persistRaftStateForAuthorityLocked(&candidate, &oldSet, &newSet); err != nil {
		return err
	}
	s.state = candidate
	s.set = oldSet
	s.jointSet = cloneControlSetPointer(&newSet)
	return nil
}

// ActivateFinalControlSet 只在 exact Final 已由 joint quorum 提交后切换本机稳定配置。
// 被移除的节点不能调用该方法继续参选；它应在观察到 certified Final 后停止。
func (s *RaftStorage) ActivateFinalControlSet(newSet wire.ControlSetV1, finalEntryHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := wire.ValidateControlSet(&newSet); err != nil {
		return err
	}
	if newSet.ClusterID != s.state.ClusterID {
		return errors.New("[joint Raft] Final ControlSet cluster 不匹配")
	}
	newHash, _ := wire.ControlSetHash(&newSet)
	var finalIndex int64
	for index := s.state.CommitIndex; index >= 1; index-- {
		record := s.state.Log[index-1]
		if record.Kind == RaftRecordHead && record.Head != nil &&
			record.Head.Body.Payload.HeadKind == "control_set_final" {
			if record.EntryHash != finalEntryHash || record.Head.Body.Payload.ControlSetHash != newHash {
				return errors.New("[joint Raft] Final entry/hash/新 ControlSet 不匹配")
			}
			finalIndex = index
			break
		}
	}
	if finalIndex != 0 && s.state.ControlSetHash == newHash {
		wantDisabled := !controlSetContains(&newSet, s.state.MemberID)
		if s.state.VotingDisabled != wantDisabled || s.state.VotedFor != "" {
			return errors.New("[joint Raft] 已激活 Final 的本机 voting 状态冲突")
		}
		return nil
	}
	if finalIndex == 0 || !requiresJointCommit(&s.state, &s.set, finalIndex) {
		return errors.New("[joint Raft] 未找到由 joint phase 提交的 Final entry")
	}
	candidate := cloneRaftState(s.state)
	candidate.ControlSetHash = newHash
	candidate.VotedFor = ""
	candidate.VotingDisabled = !controlSetContains(&newSet, s.state.MemberID)
	if err := s.persistRaftStateForSetLocked(&candidate, &newSet); err != nil {
		return err
	}
	s.state = candidate
	s.set = newSet
	s.jointSet = nil
	return nil
}

func validateRaftPersistentState(state *RaftPersistentStateV1, set *wire.ControlSetV1) error {
	return validateRaftPersistentStateAuthority(state, set, nil)
}

func validateRaftPersistentStateWithJoint(state *RaftPersistentStateV1, oldSet,
	newSet *wire.ControlSetV1) error {
	return validateRaftPersistentStateAuthority(state, oldSet, newSet)
}

func validateRaftPersistentStateAuthority(state *RaftPersistentStateV1, set,
	jointSet *wire.ControlSetV1) error {
	setHash, setErr := wire.ControlSetHash(set)
	memberAuthorized := controlSetContains(set, state.MemberID)
	if jointSet != nil {
		jointHash, jointErr := wire.ControlSetHash(jointSet)
		joint := activeJointRecord(state)
		if jointErr != nil || joint == nil || joint.OldControlSetHash != setHash ||
			joint.NewControlSetHash != jointHash || jointSet.ClusterID != set.ClusterID {
			return errors.New("[joint Raft] persistent Joint authority 无效")
		}
		memberAuthorized = memberAuthorized || controlSetContains(jointSet, state.MemberID)
	}
	if state.Schema != 3 || setErr != nil || state.ControlSetHash != setHash ||
		state.ClusterID != set.ClusterID || !state.VotingDisabled && !memberAuthorized ||
		state.CurrentTerm < 0 || state.CommitIndex < 0 || state.LastApplied < 0 ||
		state.LastApplied > state.CommitIndex || state.CommitIndex > int64(len(state.Log)) {
		return errors.New("[Raft] persistent state header/floors 无效")
	}
	voteAuthorized := state.VotedFor == "" || controlSetContains(set, state.VotedFor) ||
		jointSet != nil && controlSetContains(jointSet, state.VotedFor)
	if state.VotingDisabled && state.VotedFor != "" || !voteAuthorized {
		return errors.New("[Raft] voted_for 不在 committed ControlSet")
	}
	for i := range state.Log {
		record := &state.Log[i]
		if record.Index != int64(i+1) {
			return errors.New("[Raft] persistent log index 不连续")
		}
		if raftRecordClusterID(record) != state.ClusterID {
			return errors.New("[Raft] persistent log cluster 不匹配")
		}
		if err := validateRaftRecord(record, state.Log[:i]); err != nil {
			return err
		}
	}
	return nil
}

func activeJointRecord(state *RaftPersistentStateV1) *wire.JointControlSetEntryBodyV1 {
	if state == nil || state.CommitIndex < 1 || state.CommitIndex > int64(len(state.Log)) {
		return nil
	}
	var joint *wire.JointControlSetEntryBodyV1
	for index := int64(1); index <= state.CommitIndex; index++ {
		record := &state.Log[index-1]
		if record.Kind == RaftRecordJointControlSet && record.JointControlSet != nil {
			copy := *record.JointControlSet
			joint = &copy
			continue
		}
		if joint != nil && record.Kind == RaftRecordHead && record.Head != nil &&
			record.Head.Body.Payload.HeadKind == "control_set_final" &&
			state.ControlSetHash == record.Head.Body.Payload.ControlSetHash {
			joint = nil
		}
	}
	return joint
}

func recordForEntry(entry wire.HeadEntryV2) RaftLogRecordV1 {
	copy := entry
	return RaftLogRecordV1{Term: entry.Body.Payload.RaftTerm, Index: entry.Body.Payload.RaftIndex,
		EntryHash: entry.EntryHash, Kind: RaftRecordHead, Head: &copy}
}

func recordForJointControlSet(body wire.JointControlSetEntryBodyV1, entryHash string) RaftLogRecordV1 {
	copy := body
	return RaftLogRecordV1{Term: body.RaftTerm, Index: body.RaftIndex, EntryHash: entryHash,
		Kind: RaftRecordJointControlSet, JointControlSet: &copy}
}

func lastLogCoordinates(log []RaftLogRecordV1) (int64, int64) {
	if len(log) == 0 {
		return 0, 0
	}
	last := log[len(log)-1]
	return last.Index, last.Term
}

func matchesPrevious(log []RaftLogRecordV1, index, term int64, hash string) bool {
	if index == 0 {
		return term == 0 && hash == wire.EmptyHashV1
	}
	if index > int64(len(log)) {
		return false
	}
	record := log[index-1]
	return record.Term == term && record.EntryHash == hash
}

func controlSetContains(set *wire.ControlSetV1, memberID string) bool {
	position := sort.Search(len(set.Members), func(i int) bool { return set.Members[i].MemberID >= memberID })
	return position < len(set.Members) && set.Members[position].MemberID == memberID
}

func raftAuthorityContains(storage *RaftStorage, memberID string) bool {
	return storage != nil && (controlSetContains(&storage.set, memberID) ||
		storage.jointSet != nil && controlSetContains(storage.jointSet, memberID))
}

func cloneRaftState(state RaftPersistentStateV1) RaftPersistentStateV1 {
	body, _ := json.Marshal(state)
	var copy RaftPersistentStateV1
	_ = json.Unmarshal(body, &copy)
	return copy
}

func cloneRaftRecord(record RaftLogRecordV1) RaftLogRecordV1 {
	body, _ := json.Marshal(record)
	var copy RaftLogRecordV1
	_ = json.Unmarshal(body, &copy)
	return copy
}

func validateRaftRecord(record *RaftLogRecordV1, prefix []RaftLogRecordV1) error {
	if record == nil || record.Term < 1 || record.Index != int64(len(prefix))+1 {
		return errors.New("[Raft] log record term/index 无效")
	}
	previousHash := wire.EmptyHashV1
	if len(prefix) > 0 {
		previousHash = prefix[len(prefix)-1].EntryHash
	}
	switch record.Kind {
	case RaftRecordHead:
		if record.Head == nil || record.JointControlSet != nil || record.NoOp != nil ||
			record.EntryHash != record.Head.EntryHash ||
			record.Term != record.Head.Body.Payload.RaftTerm || record.Index != record.Head.Body.Payload.RaftIndex ||
			record.Head.Body.Payload.PreviousLogEntryHash != previousHash {
			return errors.New("[Raft] head record tagged union/坐标/hash 无效")
		}
		var previousHead *wire.HeadEntryV2
		for index := len(prefix) - 1; index >= 0; index-- {
			if prefix[index].Kind == RaftRecordHead && prefix[index].Head != nil {
				previousHead = prefix[index].Head
				break
			}
		}
		if len(prefix) == 0 && record.Head.Body.Payload.HeadKind != "bootstrap" &&
			record.Head.Body.Payload.HeadKind != "emergency_recovery" {
			return errors.New("[Raft] 新 lineage 首项必须是 bootstrap/emergency Head")
		}
		if err := wire.ValidateHeadEntry(record.Head, previousHead); err != nil {
			return err
		}
	case RaftRecordJointControlSet:
		if len(prefix) == 0 || record.Head != nil || record.JointControlSet == nil || record.NoOp != nil {
			return errors.New("[joint Raft] Joint record tagged union 无效")
		}
		body := record.JointControlSet
		wantHash, err := wire.JointControlSetEntryHash(body)
		if err != nil || record.EntryHash != wantHash || record.Term != body.RaftTerm ||
			record.Index != body.RaftIndex || body.PreviousLogEntryHash != previousHash {
			return errors.New("[joint Raft] Joint record 坐标/hash/lineage 无效")
		}
		var previousHead *wire.HeadEntryV2
		for index := len(prefix) - 1; index >= 0; index-- {
			if prefix[index].Kind == RaftRecordHead && prefix[index].Head != nil {
				previousHead = prefix[index].Head
				break
			}
		}
		if previousHead == nil || body.ParentCertifiedHeadHash != previousHead.HeadHash ||
			body.RecoveryEpoch != previousHead.Body.Payload.RecoveryEpoch ||
			body.RecoveryStatementHash != previousHead.Body.Payload.RecoveryStatementHash ||
			body.RecoveryPolicyHash != previousHead.Body.Payload.RecoveryPolicyHash ||
			body.OldControlEpoch != previousHead.Body.Payload.ControlEpoch ||
			body.OldControlSetHash != previousHead.Body.Payload.ControlSetHash ||
			body.OldControlPeerDirectoryHash != previousHead.Body.Payload.ControlPeerDirectoryHash {
			return errors.New("[joint Raft] Joint record 未绑定最近 certified Head authority")
		}
	case RaftRecordNoOp:
		if len(prefix) == 0 || record.NoOp == nil || record.Head != nil || record.JointControlSet != nil ||
			record.NoOp.Schema != 1 ||
			record.NoOp.ClusterID == "" || record.NoOp.ClusterID != prefixClusterID(prefix, record.NoOp.ClusterID) ||
			record.Term != record.NoOp.RaftTerm || record.Index != record.NoOp.RaftIndex ||
			record.NoOp.PreviousLogEntryHash != previousHash {
			return errors.New("[Raft] no-op record tagged union/坐标/hash 无效")
		}
		wantHash, err := wire.HashObject(raftNoOpDomain, *record.NoOp)
		if err != nil || wantHash != record.EntryHash {
			return errors.New("[Raft] no-op entry hash 无效")
		}
	default:
		return errors.New("[Raft] 未知 log record kind")
	}
	return nil
}

func prefixClusterID(prefix []RaftLogRecordV1, fallback string) string {
	for _, record := range prefix {
		if record.Head != nil {
			return record.Head.Body.Payload.ClusterID
		}
		if record.JointControlSet != nil {
			return record.JointControlSet.ClusterID
		}
		if record.NoOp != nil {
			return record.NoOp.ClusterID
		}
	}
	return fallback
}

func raftRecordClusterID(record *RaftLogRecordV1) string {
	if record == nil {
		return ""
	}
	if record.Head != nil {
		return record.Head.Body.Payload.ClusterID
	}
	if record.JointControlSet != nil {
		return record.JointControlSet.ClusterID
	}
	if record.NoOp != nil {
		return record.NoOp.ClusterID
	}
	return ""
}

func requiresJointCommit(state *RaftPersistentStateV1, set *wire.ControlSetV1, through int64) bool {
	if state == nil || through < 1 {
		return false
	}
	if through > int64(len(state.Log)) {
		through = int64(len(state.Log))
	}
	setHash, _ := wire.ControlSetHash(set)
	joint := false
	for index := int64(1); index <= through; index++ {
		record := state.Log[index-1]
		if record.Kind == RaftRecordJointControlSet {
			joint = true
			continue
		}
		if joint && record.Kind == RaftRecordHead && record.Head != nil &&
			record.Head.Body.Payload.HeadKind == "control_set_final" && index <= state.CommitIndex &&
			setHash == record.Head.Body.Payload.ControlSetHash {
			joint = false
		}
	}
	return joint
}

// commitRaftStateLocked 先完整落盘候选状态，再切换内存视图；写失败时调用方仍能
// 继续观察最后一个 durable 状态，不能看到半批 AppendEntries。
func (s *RaftStorage) commitRaftStateLocked(candidate RaftPersistentStateV1) error {
	if err := s.persistRaftStateLocked(&candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

func (s *RaftStorage) persistRaftStateLocked(state *RaftPersistentStateV1) error {
	return s.persistRaftStateForAuthorityLocked(state, &s.set, s.jointSet)
}

func (s *RaftStorage) persistRaftStateForSetLocked(state *RaftPersistentStateV1,
	set *wire.ControlSetV1) error {
	return s.persistRaftStateForAuthorityLocked(state, set, nil)
}

func (s *RaftStorage) persistRaftStateForAuthorityLocked(state *RaftPersistentStateV1,
	set, jointSet *wire.ControlSetV1) error {
	if err := validateRaftPersistentStateAuthority(state, set, jointSet); err != nil {
		return err
	}
	canonical, err := wire.MarshalCanonical(state)
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, filepath.Base(s.path)+".tmp-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err = temporary.Write(canonical); err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}
