// Package controlplane 提供 v2 控制日志在单机/多副本协调层之上的耐久状态边界。
// Raft transport 负责形成 durable committed prefix；本包只允许 committed entry 经确定性
// apply/recompute 后收集 replication attestation，避免把落盘或 CRDT arrival 当生效。
package controlplane

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"loom/internal/wire"
)

type Phase string

const (
	PhasePending               Phase = "pending"
	PhaseCommittedNotCertified Phase = "committed_not_certified"
	PhaseCertified             Phase = "certified"
	PhaseReconciled            Phase = "reconciled"
	PhaseApplied               Phase = "applied"
)

type OperationState struct {
	Entry             wire.HeadEntryV2                `json:"entry"`
	Phase             Phase                           `json:"phase"`
	RaftCommit        *RaftCommitReferenceV1          `json:"raft_commit,omitempty"`
	Signatures        []wire.ControlConfigSignatureV1 `json:"signatures"`
	QC                *wire.StableHeadReplicationQCV1 `json:"qc,omitempty"`
	ReconcileEvidence []string                        `json:"reconcile_evidence,omitempty"`
}

// RaftCommitReferenceV1 是应用状态对本机 durable Raft committed prefix 的精确引用。
// Raft 自身的 term/log/commitIndex 已证明提交；应用层不得另收一份可伪造的 ack 名单。
type RaftCommitReferenceV1 struct {
	Schema    int    `json:"schema"`
	ClusterID string `json:"cluster_id"`
	MemberID  string `json:"member_id"`
	Term      int64  `json:"term"`
	Index     int64  `json:"index"`
	EntryHash string `json:"entry_hash"`
}

type State struct {
	Schema        int                             `json:"schema"`
	ControlSet    wire.ControlSetV1               `json:"control_set"`
	Active        *OperationState                 `json:"active,omitempty"`
	CertifiedHead *wire.HeadEntryV2               `json:"certified_head,omitempty"`
	CertifiedQC   *wire.StableHeadReplicationQCV1 `json:"certified_qc,omitempty"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	state State
}

func Open(path string, set wire.ControlSetV1) (*Store, error) {
	if path == "" {
		return nil, errors.New("[Raft] control state path 不能为空")
	}
	if err := wire.ValidateControlSet(&set); err != nil {
		return nil, err
	}
	store := &Store{path: path, state: State{Schema: 2, ControlSet: set}}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var state State
	if _, err := wire.DecodeStrict(body, 16<<20, &state); err != nil {
		return nil, fmt.Errorf("[Raft] 耐久 control state 无效: %w", err)
	}
	if err := validateState(&state); err != nil {
		return nil, err
	}
	wantSetHash, _ := wire.ControlSetHash(&set)
	gotSetHash, _ := wire.ControlSetHash(&state.ControlSet)
	if wantSetHash != gotSetHash {
		return nil, errors.New("[ControlSet] 磁盘 ControlSet 与启动参数不一致")
	}
	store.state = state
	return store, nil
}

func (s *Store) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, _ := json.Marshal(s.state)
	var copy State
	_ = json.Unmarshal(body, &copy)
	return copy
}

// Prepare 保存已完成 candidate validation/render 的精确 head，但不赋予权限。
func (s *Store) Prepare(entry wire.HeadEntryV2) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.CertifiedHead != nil && s.state.CertifiedHead.EntryHash == entry.EntryHash && wire.EqualCanonical(*s.state.CertifiedHead, entry) {
		return nil
	}
	if err := wire.ValidateHeadEntry(&entry, s.state.CertifiedHead); err != nil {
		return err
	}
	setHash, _ := wire.ControlSetHash(&s.state.ControlSet)
	if entry.Body.Payload.ControlSetHash != setHash {
		return errors.New("[Raft] candidate 使用了错误 ControlSet")
	}
	if s.state.Active != nil {
		if s.state.Active.Entry.HeadHash == entry.HeadHash {
			return nil
		}
		return errors.New("[Raft] 前一 HeadEntry 尚未 certified/applied，禁止跳过")
	}
	candidate := cloneState(s.state)
	candidate.Active = &OperationState{Entry: entry, Phase: PhasePending, Signatures: []wire.ControlConfigSignatureV1{}}
	if err := s.persistLocked(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

// CommitFromRaft 只接受本机 RaftStorage 已耐久提交的 exact log record。quorum 是
// Raft 推进 commitIndex 时已执行的协议事实，不能由调用者在崩溃后重新拼一组 member ID。
func (s *Store) CommitFromRaft(storage *RaftStorage, entryHash string) error {
	if storage == nil {
		return errors.New("[Raft] commit 必须绑定本机 Raft storage")
	}
	raft := storage.SnapshotRaft()
	control := s.Snapshot()
	setHash, err := wire.ControlSetHash(&control.ControlSet)
	if err != nil {
		return err
	}
	storageSetHash, err := wire.ControlSetHash(&storage.set)
	if err != nil || storageSetHash != setHash || raft.ClusterID != control.ControlSet.ClusterID ||
		!controlSetContains(&control.ControlSet, raft.MemberID) {
		return errors.New("[Raft] control store 与 Raft storage authority 不一致")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	active, err := s.active(entryHash)
	if err != nil {
		return err
	}
	index := active.Entry.Body.Payload.RaftIndex
	if index < 1 || index > raft.CommitIndex || index > int64(len(raft.Log)) {
		return errors.New("[Raft] active entry 不在本机 committed prefix")
	}
	record := raft.Log[index-1]
	if record.Kind != RaftRecordHead || record.Head == nil || record.Index != index ||
		record.Term != active.Entry.Body.Payload.RaftTerm || record.EntryHash != entryHash ||
		!wire.EqualCanonical(*record.Head, active.Entry) {
		return errors.New("[Raft] committed record 与 active entry 不一致")
	}
	reference := &RaftCommitReferenceV1{Schema: 1, ClusterID: raft.ClusterID,
		MemberID: raft.MemberID, Term: record.Term, Index: record.Index, EntryHash: record.EntryHash}
	if active.Phase != PhasePending && active.Phase != PhaseCommittedNotCertified {
		if active.RaftCommit != nil && wire.EqualCanonical(*active.RaftCommit, *reference) {
			return nil
		}
		return errors.New("[Raft] 已提交 entry 的 Raft reference 不能被改写")
	}
	if active.RaftCommit != nil && !wire.EqualCanonical(*active.RaftCommit, *reference) {
		return errors.New("[Raft] committed entry 的 Raft reference 冲突")
	}
	candidate := cloneState(s.state)
	candidate.Active.RaftCommit = reference
	candidate.Active.Phase = PhaseCommittedNotCertified
	if err := s.persistLocked(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

// AddAttestation 只在 commit 之后接受签名；达到门槛才公开 certified head。
func (s *Store) AddAttestation(entryHash string, signature wire.ControlConfigSignatureV1) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	active, err := s.active(entryHash)
	if err != nil {
		return err
	}
	if active.Phase == PhasePending {
		return errors.New("[QC] 未 committed 的 entry 禁止 attestation")
	}
	for _, existing := range active.Signatures {
		if existing.MemberID == signature.MemberID {
			if wire.EqualCanonical(existing, signature) {
				return nil
			}
			return errors.New("[QC] 同一 signer 对同一 entry 给出冲突签名")
		}
	}
	if active.Phase != PhaseCommittedNotCertified {
		return errors.New("[QC] certified 后 signer 集合已冻结，不能改变 QC bytes")
	}
	candidate := cloneState(s.state)
	candidateActive := candidate.Active
	candidateActive.Signatures = append(candidateActive.Signatures, signature)
	sort.Slice(candidateActive.Signatures, func(i, j int) bool {
		if candidateActive.Signatures[i].MemberID != candidateActive.Signatures[j].MemberID {
			return candidateActive.Signatures[i].MemberID < candidateActive.Signatures[j].MemberID
		}
		return candidateActive.Signatures[i].ConfigKeyID < candidateActive.Signatures[j].ConfigKeyID
	})
	qc := wire.StableQC(&candidateActive.Entry, candidateActive.Signatures)
	quorum, _ := wire.Quorum(len(s.state.ControlSet.Members))
	if len(candidateActive.Signatures) >= quorum {
		if err := wire.VerifyStableHeadQC(&candidateActive.Entry, &candidate.ControlSet, &qc); err != nil {
			return err
		}
		candidateActive.QC = &qc
		candidateActive.Phase = PhaseCertified
		entry := candidateActive.Entry
		candidate.CertifiedHead = &entry
		candidate.CertifiedQC = &qc
	}
	if err := s.persistLocked(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

// RecoverCertification 只保留 N=1 bootstrap/compatibility 恢复；多成员 ControlSet
// 必须经 HeadAttestationCollector 逐 peer 取签，禁止把所有 config 私钥集中到 executor。
func (s *Store) RecoverCertification(keys map[string]ed25519.PrivateKey) error {
	s.mu.Lock()
	if s.state.Active == nil || s.state.Active.Phase != PhaseCommittedNotCertified {
		s.mu.Unlock()
		return nil
	}
	if len(s.state.ControlSet.Members) != 1 {
		s.mu.Unlock()
		return errors.New("[keys] 多成员 QC 恢复禁止集中持有 config 私钥")
	}
	entryHash := s.state.Active.Entry.EntryHash
	attestation := wire.AttestationForHead(&s.state.Active.Entry)
	set := s.state.ControlSet
	s.mu.Unlock()
	for _, member := range set.Members {
		key, ok := keys[member.MemberID]
		if !ok {
			continue
		}
		signature, err := wire.SignHeadAttestation(attestation, member, key)
		if err != nil {
			return err
		}
		if err := s.AddAttestation(entryHash, signature); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) MarkReconciled(entryHash string, evidenceHashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	active, err := s.active(entryHash)
	if err != nil {
		return err
	}
	if active.Phase == PhaseReconciled && equalStrings(active.ReconcileEvidence, evidenceHashes) {
		return nil
	}
	if active.Phase != PhaseCertified {
		return errors.New("[reconcile] 只有 certified state 能驱动外部副作用")
	}
	evidence := append([]string(nil), evidenceHashes...)
	if err := wire.CanonicalSortHashes(evidence); err != nil {
		return err
	}
	candidate := cloneState(s.state)
	candidate.Active.ReconcileEvidence = evidence
	candidate.Active.Phase = PhaseReconciled
	if err := s.persistLocked(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

func (s *Store) MarkApplied(entryHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	active, err := s.active(entryHash)
	if err != nil {
		return err
	}
	if active.Phase == PhaseApplied {
		return nil
	}
	if active.Phase != PhaseCertified && active.Phase != PhaseReconciled {
		return errors.New("[apply] 未 certified 的 state 不能标 applied")
	}
	// applied 结果已经由 CertifiedHead/QC 保留；同一次原子写清除 active，避免
	// 崩溃停在“已 applied 但仍阻塞下一 head”的中间文件。
	candidate := cloneState(s.state)
	candidate.Active = nil
	if err := s.persistLocked(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

func (s *Store) active(entryHash string) (*OperationState, error) {
	if s.state.Active == nil || s.state.Active.Entry.EntryHash != entryHash {
		if s.state.CertifiedHead != nil && s.state.CertifiedHead.EntryHash == entryHash {
			return nil, errors.New("[Raft] entry 已完成，不会产生第二个 active result")
		}
		return nil, errors.New("[Raft] active entry 不存在或 hash 不匹配")
	}
	return s.state.Active, nil
}

func (s *Store) persistLocked(candidate State) error {
	if err := validateState(&candidate); err != nil {
		return err
	}
	canonical, err := wire.MarshalCanonical(candidate)
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, filepath.Base(s.path)+".tmp-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(canonical)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporary, s.path); err != nil {
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

func cloneState(state State) State {
	body, _ := json.Marshal(state)
	var clone State
	_ = json.Unmarshal(body, &clone)
	return clone
}

func validateState(state *State) error {
	if state.Schema != 2 {
		return errors.New("[Raft] control state schema 无效")
	}
	if err := wire.ValidateControlSet(&state.ControlSet); err != nil {
		return err
	}
	if state.CertifiedHead != nil {
		if state.CertifiedQC == nil {
			return errors.New("[QC] certified head 缺 QC")
		}
		if err := wire.VerifyStableHeadQC(state.CertifiedHead, &state.ControlSet, state.CertifiedQC); err != nil {
			return err
		}
	}
	if state.Active == nil {
		return nil
	}
	parent := state.CertifiedHead
	if parent != nil && parent.HeadHash == state.Active.Entry.HeadHash {
		parent = nil
	}
	if err := wire.ValidateHeadEntry(&state.Active.Entry, parent); err != nil {
		return err
	}
	if !validPhase(state.Active.Phase) {
		return errors.New("[Raft] active phase 无效")
	}
	if state.Active.Phase == PhasePending && state.Active.RaftCommit != nil {
		return errors.New("[Raft] pending state 禁止 Raft commit reference")
	}
	if state.Active.Phase != PhasePending {
		commit := state.Active.RaftCommit
		entry := &state.Active.Entry
		if commit == nil || commit.Schema != 1 || commit.ClusterID != state.ControlSet.ClusterID ||
			!controlSetContains(&state.ControlSet, commit.MemberID) || commit.Term != entry.Body.Payload.RaftTerm ||
			commit.Index != entry.Body.Payload.RaftIndex || commit.EntryHash != entry.EntryHash {
			return errors.New("[Raft] committed state 缺 exact Raft commit reference")
		}
	}
	if state.Active.Phase == PhaseCertified || state.Active.Phase == PhaseReconciled || state.Active.Phase == PhaseApplied {
		if state.Active.QC == nil || wire.VerifyStableHeadQC(&state.Active.Entry, &state.ControlSet, state.Active.QC) != nil {
			return errors.New("[QC] certified/reconciled/applied state 缺有效 QC")
		}
	}
	return nil
}

func validPhase(phase Phase) bool {
	return phase == PhasePending || phase == PhaseCommittedNotCertified || phase == PhaseCertified || phase == PhaseReconciled || phase == PhaseApplied
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
