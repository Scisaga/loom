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

// RaftLogRecordV1 保存协议 entry 与 Raft 坐标的冗余绑定，加载时会全部重算。
type RaftLogRecordV1 struct {
	Term      int64            `json:"term"`
	Index     int64            `json:"index"`
	EntryHash string           `json:"entry_hash"`
	Entry     wire.HeadEntryV2 `json:"entry"`
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
		Schema: 1, ClusterID: set.ClusterID, MemberID: memberID, Log: []RaftLogRecordV1{},
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
	if entry.Body.Payload.RaftTerm != s.state.CurrentTerm || s.state.CurrentTerm < 1 {
		return errors.New("[D104 Raft] leader 只能追加当前任期 entry")
	}
	lastIndex, _ := lastLogCoordinates(s.state.Log)
	if entry.Body.Payload.RaftIndex != lastIndex+1 {
		return errors.New("[D104 Raft] local append index 不连续")
	}
	var parent *wire.HeadEntryV2
	if len(s.state.Log) > 0 {
		parent = &s.state.Log[len(s.state.Log)-1].Entry
	}
	if err := wire.ValidateHeadEntry(&entry, parent); err != nil {
		return err
	}
	candidate := cloneRaftState(s.state)
	candidate.Log = append(candidate.Log, recordForEntry(entry))
	return s.commitRaftStateLocked(candidate)
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
		record := &request.Entries[i]
		// AppendEntries 可携本届 leader 用来补齐 follower 的旧任期 entry；只禁止
		// future term，不能错误要求整批记录都等于 RPC term（D104 Raft）。
		if record.Index != expectedIndex || record.Term < 1 || record.Term > request.Term || record.EntryHash != record.Entry.EntryHash ||
			record.Entry.Body.Payload.RaftIndex != record.Index || record.Entry.Body.Payload.RaftTerm != record.Term {
			return AppendEntriesResultV1{}, errors.New("[D104 Raft] AppendEntries record 坐标/hash 不一致")
		}
		var parent *wire.HeadEntryV2
		if expectedIndex > 1 {
			if int(expectedIndex-2) >= len(candidate.Log) {
				return AppendEntriesResultV1{}, errors.New("[D104 Raft] AppendEntries 缺 parent")
			}
			parent = &candidate.Log[expectedIndex-2].Entry
		}
		if err := wire.ValidateHeadEntry(&record.Entry, parent); err != nil {
			return AppendEntriesResultV1{}, err
		}
		existingIndex := int(expectedIndex - 1)
		if existingIndex < len(candidate.Log) {
			existing := candidate.Log[existingIndex]
			if existing.Term == record.Term && existing.EntryHash == record.EntryHash {
				continue
			}
			if expectedIndex <= candidate.CommitIndex {
				return AppendEntriesResultV1{}, errors.New("[D104 Raft] 禁止覆盖 committed log prefix")
			}
			candidate.Log = candidate.Log[:existingIndex]
		}
		candidate.Log = append(candidate.Log, *record)
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
	result := append([]RaftLogRecordV1(nil), s.state.Log[index:s.state.CommitIndex]...)
	return result, nil
}

func validateRaftPersistentState(state *RaftPersistentStateV1, set *wire.ControlSetV1) error {
	if state.Schema != 1 || state.ClusterID != set.ClusterID || !controlSetContains(set, state.MemberID) ||
		state.CurrentTerm < 0 || state.CommitIndex < 0 || state.LastApplied < 0 ||
		state.LastApplied > state.CommitIndex || state.CommitIndex > int64(len(state.Log)) {
		return errors.New("[D104 Raft] persistent state header/floors 无效")
	}
	if state.VotedFor != "" && !controlSetContains(set, state.VotedFor) {
		return errors.New("[D104 Raft] voted_for 不在 committed ControlSet")
	}
	for i := range state.Log {
		record := &state.Log[i]
		if record.Index != int64(i+1) || record.Term < 1 || record.EntryHash != record.Entry.EntryHash ||
			record.Entry.Body.Payload.RaftIndex != record.Index || record.Entry.Body.Payload.RaftTerm != record.Term {
			return errors.New("[D104 Raft] persistent log 坐标/hash 无效")
		}
		var parent *wire.HeadEntryV2
		if i > 0 {
			parent = &state.Log[i-1].Entry
		}
		if err := wire.ValidateHeadEntry(&record.Entry, parent); err != nil {
			return err
		}
	}
	return nil
}

func recordForEntry(entry wire.HeadEntryV2) RaftLogRecordV1 {
	return RaftLogRecordV1{Term: entry.Body.Payload.RaftTerm, Index: entry.Body.Payload.RaftIndex, EntryHash: entry.EntryHash, Entry: entry}
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
	copy := state
	copy.Log = append([]RaftLogRecordV1(nil), state.Log...)
	return copy
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
