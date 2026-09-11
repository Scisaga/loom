// Package controlplane 提供 v2 控制日志在单机/多副本协调层之上的耐久状态边界。
// Raft transport 负责产生 committed ack；本包只允许 committed entry 经确定性
// apply/recompute 后收集 replication attestation，避免把落盘或 CRDT arrival 当生效（D104）。
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
	CommitAcks        []string                        `json:"commit_acks"`
	Signatures        []wire.ControlConfigSignatureV1 `json:"signatures"`
	QC                *wire.StableHeadReplicationQCV1 `json:"qc,omitempty"`
	ReconcileEvidence []string                        `json:"reconcile_evidence,omitempty"`
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
		return nil, errors.New("[D104 Raft] control state path 不能为空")
	}
	if err := wire.ValidateControlSet(&set); err != nil {
		return nil, err
	}
	store := &Store{path: path, state: State{Schema: 1, ControlSet: set}}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var state State
	if _, err := wire.DecodeStrict(body, 16<<20, &state); err != nil {
		return nil, fmt.Errorf("[D104 Raft] 耐久 control state 无效: %w", err)
	}
	if err := validateState(&state); err != nil {
		return nil, err
	}
	wantSetHash, _ := wire.ControlSetHash(&set)
	gotSetHash, _ := wire.ControlSetHash(&state.ControlSet)
	if wantSetHash != gotSetHash {
		return nil, errors.New("[D112 ControlSet] 磁盘 ControlSet 与启动参数不一致")
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
		return errors.New("[D104 Raft] candidate 使用了错误 ControlSet")
	}
	if s.state.Active != nil {
		if s.state.Active.Entry.HeadHash == entry.HeadHash {
			return nil
		}
		return errors.New("[D104 Raft] 前一 HeadEntry 尚未 certified/applied，禁止跳过")
	}
	candidate := cloneState(s.state)
	candidate.Active = &OperationState{Entry: entry, Phase: PhasePending, CommitAcks: []string{}, Signatures: []wire.ControlConfigSignatureV1{}}
	if err := s.persistLocked(candidate); err != nil {
		return err
	}
	s.state = candidate
	return nil
}

// Commit 只接收 Raft 层已经 fsync 的 ack 身份，并始终按 committed ControlSet 算多数。
func (s *Store) Commit(entryHash string, ackMemberIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	active, err := s.active(entryHash)
	if err != nil {
		return err
	}
	acks := append([]string(nil), ackMemberIDs...)
	sort.Strings(acks)
	if active.Phase != PhasePending && active.Phase != PhaseCommittedNotCertified {
		if equalStrings(active.CommitAcks, acks) {
			return nil
		}
		return errors.New("[D104 Raft] 已提交 entry 的 durable ack 集合不能被改写")
	}
	members := make(map[string]struct{}, len(s.state.ControlSet.Members))
	for _, member := range s.state.ControlSet.Members {
		members[member.MemberID] = struct{}{}
	}
	for i, ack := range acks {
		if _, ok := members[ack]; !ok || i > 0 && acks[i-1] == ack {
			return errors.New("[D104 Raft] commit ack 含未知/重复成员")
		}
	}
	quorum, _ := wire.Quorum(len(s.state.ControlSet.Members))
	if len(acks) < quorum {
		return errors.New("[D104 Raft] 未达到 committed ControlSet 多数，不能 commit")
	}
	candidate := cloneState(s.state)
	candidate.Active.CommitAcks = acks
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
		return errors.New("[D104 QC] 未 committed 的 entry 禁止 attestation")
	}
	for _, existing := range active.Signatures {
		if existing.MemberID == signature.MemberID {
			if wire.EqualCanonical(existing, signature) {
				return nil
			}
			return errors.New("[D104 QC] 同一 signer 对同一 entry 给出冲突签名")
		}
	}
	if active.Phase != PhaseCommittedNotCertified {
		return errors.New("[D104 QC] certified 后 signer 集合已冻结，不能改变 QC bytes")
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
		return errors.New("[D102 keys] 多成员 QC 恢复禁止集中持有 config 私钥")
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
		return errors.New("[D108 reconcile] 只有 certified state 能驱动外部副作用")
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
		return errors.New("[D104 apply] 未 certified 的 state 不能标 applied")
	}
	// applied 结果已经由 CertifiedHead/QC 保留；同一次原子写清除 active，避免
	// 崩溃停在“已 applied 但仍阻塞下一 head”的中间文件（D104）。
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
			return nil, errors.New("[D104 Raft] entry 已完成，不会产生第二个 active result")
		}
		return nil, errors.New("[D104 Raft] active entry 不存在或 hash 不匹配")
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
	if state.Schema != 1 {
		return errors.New("[D104 Raft] control state schema 无效")
	}
	if err := wire.ValidateControlSet(&state.ControlSet); err != nil {
		return err
	}
	if state.CertifiedHead != nil {
		if state.CertifiedQC == nil {
			return errors.New("[D104 QC] certified head 缺 QC")
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
		return errors.New("[D104 Raft] active phase 无效")
	}
	if state.Active.Phase == PhasePending && len(state.Active.CommitAcks) != 0 {
		return errors.New("[D104 Raft] pending state 禁止 commit acks")
	}
	if state.Active.Phase != PhasePending {
		quorum, _ := wire.Quorum(len(state.ControlSet.Members))
		if len(state.Active.CommitAcks) < quorum {
			return errors.New("[D104 Raft] committed state 缺 durable quorum acks")
		}
	}
	if state.Active.Phase == PhaseCertified || state.Active.Phase == PhaseReconciled || state.Active.Phase == PhaseApplied {
		if state.Active.QC == nil || wire.VerifyStableHeadQC(&state.Active.Entry, &state.ControlSet, state.Active.QC) != nil {
			return errors.New("[D104 QC] certified/reconciled/applied state 缺有效 QC")
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
