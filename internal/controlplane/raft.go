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
	RaftRecordHead = "head"
	RaftRecordNoOp = "no_op"
	raftNoOpDomain = "loom-raft-no-op-entry-v1"
)

// RaftNoOpEntryV1 是新 leader 用来提交旧任期 prefix 的私有 current-term barrier；
// 它不产生 Head，但其 hash 仍进入下一条日志的 previous_log_entry_hash（D104）。
type RaftNoOpEntryV1 struct {
	Schema               int    `json:"schema"`
	ClusterID            string `json:"cluster_id"`
	RaftTerm             int64  `json:"raft_term"`
	RaftIndex            int64  `json:"raft_index"`
	PreviousLogEntryHash string `json:"previous_log_entry_hash"`
}

// RaftLogRecordV1 保存 exact tagged entry 与 Raft 坐标的冗余绑定，加载时会全部重算。
type RaftLogRecordV1 struct {
	Term      int64             `json:"term"`
	Index     int64             `json:"index"`
	EntryHash string            `json:"entry_hash"`
	Kind      string            `json:"kind"`
	Head      *wire.HeadEntryV2 `json:"head,omitempty"`
	NoOp      *RaftNoOpEntryV1  `json:"no_op,omitempty"`
}

type RaftPersistentStateV1 struct {
	Schema      int               `json:"schema"`
	ClusterID   string            `json:"cluster_id"`
	MemberID    string            `json:"member_id"`
	CurrentTerm int64             `json:"current_term"`
	VotedFor    string            `json:"voted_for,omitempty"`
	Log         []RaftLogRecordV1 `json:"log"`
	CommitIndex int64             `json:"commit_index"`
	LastApplied int64             `json:"last_applied"`
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

// RaftStorage 实现 D104 要求的持久状态机边界；网络层只传递以上消息，不能绕过这里写日志。
type RaftStorage struct {
	mu    sync.Mutex
	path  string
	set   wire.ControlSetV1
	state RaftPersistentStateV1
}

func OpenRaftStorage(path, memberID string, set wire.ControlSetV1) (*RaftStorage, error) {
	if path == "" || memberID == "" {
		return nil, errors.New("[D104 Raft] storage path/member ID 不能为空")
	}
	if err := wire.ValidateControlSet(&set); err != nil {
		return nil, err
	}
	if !controlSetContains(&set, memberID) {
		return nil, errors.New("[D104 Raft] 本机 member 不在 committed ControlSet")
	}
	storage := &RaftStorage{path: path, set: set, state: RaftPersistentStateV1{
		Schema: 2, ClusterID: set.ClusterID, MemberID: memberID, Log: []RaftLogRecordV1{},
	}}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return storage, nil
	}
	if err != nil {
		return nil, err
	}
	var state RaftPersistentStateV1
	if _, err := wire.DecodeStrict(body, 64<<20, &state); err != nil {
		return nil, fmt.Errorf("[D104 Raft] persistent state 解码失败: %w", err)
	}
	if err := validateRaftPersistentState(&state, &set); err != nil {
		return nil, err
	}
	if state.MemberID != memberID {
		return nil, errors.New("[D104 Raft] 磁盘 member ID 与启动身份不一致")
	}
	storage.state = state
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
	if s.state.CurrentTerm == int64(^uint64(0)>>1) {
		return VoteRequestV1{}, errors.New("[D104 Raft] term 溢出")
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
// 放弃当前 campaign/leader 身份，不能继续追加或推进 commit（D104）。
func (s *RaftStorage) ObserveTerm(term int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if term < 1 {
		return false, errors.New("[D104 Raft] observed term 无效")
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
	if request.Term < 1 || request.LastLogIndex < 0 || request.LastLogTerm < 0 || !controlSetContains(&s.set, request.CandidateID) {
		return VoteResultV1{}, errors.New("[D104 Raft] vote request 字段或 candidate 无效")
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
	if entry.Body.Payload.ClusterID != s.state.ClusterID {
		return errors.New("[D104 Raft] local entry cluster 不匹配")
	}
	entryIndex := entry.Body.Payload.RaftIndex
	if entryIndex >= 1 && entryIndex <= int64(len(s.state.Log)) {
		existing := s.state.Log[entryIndex-1]
		if existing.Kind == RaftRecordHead && existing.Head != nil && existing.EntryHash == entry.EntryHash &&
			wire.EqualCanonical(*existing.Head, entry) {
			return nil
		}
		return errors.New("[D104 Raft] local append 与既有日志坐标冲突")
	}
	if entry.Body.Payload.RaftTerm != s.state.CurrentTerm || s.state.CurrentTerm < 1 {
		return errors.New("[D104 Raft] leader 只能追加当前任期 entry")
	}
	lastIndex, _ := lastLogCoordinates(s.state.Log)
	if entry.Body.Payload.RaftIndex != lastIndex+1 {
		return errors.New("[D104 Raft] local append index 不连续")
	}
	record := recordForEntry(entry)
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
	if s.state.CurrentTerm < 1 || s.state.VotedFor != s.state.MemberID {
		return RaftLogRecordV1{}, errors.New("[D104 Raft] 未进入本机发起的任期，禁止追加 no-op")
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if request.Term < 1 || request.PrevLogIndex < 0 || request.PrevLogTerm < 0 || request.LeaderCommit < 0 ||
		!controlSetContains(&s.set, request.LeaderID) {
		return AppendEntriesResultV1{}, errors.New("[D104 Raft] AppendEntries header/leader 无效")
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
		// future term，不能错误要求整批记录都等于 RPC term（D104 Raft）。
		if record.Index != expectedIndex || record.Term < 1 || record.Term > request.Term {
			return AppendEntriesResultV1{}, errors.New("[D104 Raft] AppendEntries record 坐标/hash 不一致")
		}
		existingIndex := int(expectedIndex - 1)
		if existingIndex < len(candidate.Log) {
			existing := candidate.Log[existingIndex]
			if existing.Term == record.Term && existing.EntryHash == record.EntryHash && wire.EqualCanonical(existing, *record) {
				continue
			}
			if expectedIndex <= candidate.CommitIndex {
				return AppendEntriesResultV1{}, errors.New("[D104 Raft] 禁止覆盖 committed log prefix")
			}
			candidate.Log = candidate.Log[:existingIndex]
		}
		if raftRecordClusterID(record) != s.state.ClusterID {
			return AppendEntriesResultV1{}, errors.New("[D104 Raft] AppendEntries record cluster 不匹配")
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
	if s.state.CurrentTerm < 1 {
		return s.state.CommitIndex, errors.New("[D104 Raft] 尚无当前任期")
	}
	indices := make(map[string]int64, len(match)+1)
	for memberID, index := range match {
		if !controlSetContains(&s.set, memberID) || index < 0 || index > int64(len(s.state.Log)) {
			return s.state.CommitIndex, errors.New("[D104 Raft] match index 含未知成员或越界")
		}
		indices[memberID] = index
	}
	indices[s.state.MemberID] = int64(len(s.state.Log))
	quorum, _ := wire.Quorum(len(s.set.Members))
	for candidate := int64(len(s.state.Log)); candidate > s.state.CommitIndex; candidate-- {
		if s.state.Log[candidate-1].Term != s.state.CurrentTerm {
			continue
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

func (s *RaftStorage) MarkRaftApplied(index int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index != s.state.LastApplied+1 || index > s.state.CommitIndex {
		return errors.New("[D104 Raft] apply 必须在 committed prefix 内严格连续")
	}
	candidate := cloneRaftState(s.state)
	candidate.LastApplied = index
	return s.commitRaftStateLocked(candidate)
}

func (s *RaftStorage) CommittedAfter(index int64) ([]RaftLogRecordV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index > s.state.CommitIndex {
		return nil, errors.New("[D104 Raft] committed read index 越界")
	}
	result := make([]RaftLogRecordV1, 0, s.state.CommitIndex-index)
	for _, record := range s.state.Log[index:s.state.CommitIndex] {
		result = append(result, cloneRaftRecord(record))
	}
	return result, nil
}

func validateRaftPersistentState(state *RaftPersistentStateV1, set *wire.ControlSetV1) error {
	if state.Schema != 2 || state.ClusterID != set.ClusterID || !controlSetContains(set, state.MemberID) ||
		state.CurrentTerm < 0 || state.CommitIndex < 0 || state.LastApplied < 0 ||
		state.LastApplied > state.CommitIndex || state.CommitIndex > int64(len(state.Log)) {
		return errors.New("[D104 Raft] persistent state header/floors 无效")
	}
	if state.VotedFor != "" && !controlSetContains(set, state.VotedFor) {
		return errors.New("[D104 Raft] voted_for 不在 committed ControlSet")
	}
	for i := range state.Log {
		record := &state.Log[i]
		if record.Index != int64(i+1) {
			return errors.New("[D104 Raft] persistent log index 不连续")
		}
		if raftRecordClusterID(record) != state.ClusterID {
			return errors.New("[D104 Raft] persistent log cluster 不匹配")
		}
		if err := validateRaftRecord(record, state.Log[:i]); err != nil {
			return err
		}
	}
	return nil
}

func recordForEntry(entry wire.HeadEntryV2) RaftLogRecordV1 {
	copy := entry
	return RaftLogRecordV1{Term: entry.Body.Payload.RaftTerm, Index: entry.Body.Payload.RaftIndex,
		EntryHash: entry.EntryHash, Kind: RaftRecordHead, Head: &copy}
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
		return errors.New("[D104 Raft] log record term/index 无效")
	}
	previousHash := wire.EmptyHashV1
	if len(prefix) > 0 {
		previousHash = prefix[len(prefix)-1].EntryHash
	}
	switch record.Kind {
	case RaftRecordHead:
		if record.Head == nil || record.NoOp != nil || record.EntryHash != record.Head.EntryHash ||
			record.Term != record.Head.Body.Payload.RaftTerm || record.Index != record.Head.Body.Payload.RaftIndex ||
			record.Head.Body.Payload.PreviousLogEntryHash != previousHash {
			return errors.New("[D104 Raft] head record tagged union/坐标/hash 无效")
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
			return errors.New("[D104 Raft] 新 lineage 首项必须是 bootstrap/emergency Head")
		}
		if err := wire.ValidateHeadEntry(record.Head, previousHead); err != nil {
			return err
		}
	case RaftRecordNoOp:
		if len(prefix) == 0 || record.NoOp == nil || record.Head != nil || record.NoOp.Schema != 1 ||
			record.NoOp.ClusterID == "" || record.NoOp.ClusterID != prefixClusterID(prefix, record.NoOp.ClusterID) ||
			record.Term != record.NoOp.RaftTerm || record.Index != record.NoOp.RaftIndex ||
			record.NoOp.PreviousLogEntryHash != previousHash {
			return errors.New("[D104 Raft] no-op record tagged union/坐标/hash 无效")
		}
		wantHash, err := wire.HashObject(raftNoOpDomain, *record.NoOp)
		if err != nil || wantHash != record.EntryHash {
			return errors.New("[D104 Raft] no-op entry hash 无效")
		}
	default:
		return errors.New("[D104 Raft] 未知 log record kind")
	}
	return nil
}

func prefixClusterID(prefix []RaftLogRecordV1, fallback string) string {
	for _, record := range prefix {
		if record.Head != nil {
			return record.Head.Body.Payload.ClusterID
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
	if record.NoOp != nil {
		return record.NoOp.ClusterID
	}
	return ""
}

// commitRaftStateLocked 先完整落盘候选状态，再切换内存视图；写失败时调用方仍能
// 继续观察最后一个 durable 状态，不能看到半批 AppendEntries（D104）。
func (s *RaftStorage) commitRaftStateLocked(candidate RaftPersistentStateV1) error {
	if err := s.persistRaftStateLocked(&candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

func (s *RaftStorage) persistRaftStateLocked(state *RaftPersistentStateV1) error {
	if err := validateRaftPersistentState(state, &s.set); err != nil {
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
