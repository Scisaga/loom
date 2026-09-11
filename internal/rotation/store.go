package rotation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"loom/internal/wire"
)

type TransitionRecordV1 struct {
	Schema             int        `json:"schema"`
	Sequence           int64      `json:"sequence"`
	PreviousStateHash  string     `json:"previous_state_hash"`
	Transition         Transition `json:"transition"`
	ResultingState     StateV1    `json:"resulting_state"`
	ResultingStateHash string     `json:"resulting_state_hash"`
}

type DurableStateV1 struct {
	Schema  int                  `json:"schema"`
	Intent  *IntentV1            `json:"intent,omitempty"`
	Current *StateV1             `json:"current,omitempty"`
	History []TransitionRecordV1 `json:"history"`
}

// CertifiedAuthorityVerifier 由 controlplane 注入，必须验证 transition 所引
// certified head/QC；rotation store 不允许用布尔参数替代 authority（D104、D120）。
type CertifiedAuthorityVerifier func(intent *IntentV1, current *StateV1, transition *Transition) error

type Store struct {
	mu     sync.Mutex
	path   string
	verify CertifiedAuthorityVerifier
	state  DurableStateV1
}

func OpenStore(path string, verify CertifiedAuthorityVerifier) (*Store, error) {
	if path == "" || verify == nil {
		return nil, errors.New("[D120 rotation] durable store path/authority verifier 缺失")
	}
	store := &Store{path: path, verify: verify, state: DurableStateV1{Schema: 1, History: []TransitionRecordV1{}}}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var state DurableStateV1
	if _, err := wire.DecodeStrict(body, 16<<20, &state); err != nil {
		return nil, fmt.Errorf("[D120 rotation] durable state 损坏: %w", err)
	}
	if err := validateDurableState(&state, verify); err != nil {
		return nil, err
	}
	store.state = state
	return store, nil
}

func (s *Store) Snapshot() DurableStateV1 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneDurableState(s.state)
}

// Begin 原子固定 operation、port 与全部 dependency bytes；重启/接管后只会
// 读回同一 intent，不会因查询最新资源而重新分配（D127）。
func (s *Store) Begin(intent IntentV1, transition Transition) (StateV1, error) {
	transition = normalizeTransition(transition)
	if err := validateAllocationTransition(&transition); err != nil {
		return StateV1{}, err
	}
	if err := s.verify(&intent, nil, &transition); err != nil {
		return StateV1{}, fmt.Errorf("[D120 rotation] allocation head 未获 certified authority: %w", err)
	}
	result, err := Allocate(intent, transition.CertifiedHeadHash)
	if err != nil {
		return StateV1{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Intent != nil {
		if wire.EqualCanonical(*s.state.Intent, intent) && wire.EqualCanonical(s.state.History[0].Transition, transition) {
			return *cloneDurableState(s.state).Current, nil
		}
		return StateV1{}, errors.New("[D127 rotation] durable store 已固定另一 rotation intent")
	}
	record, err := newTransitionRecord(1, wire.EmptyHashV1, transition, result)
	if err != nil {
		return StateV1{}, err
	}
	candidate := DurableStateV1{Schema: 1, Intent: &intent, Current: &result, History: []TransitionRecordV1{record}}
	if err := s.persistLocked(candidate); err != nil {
		return StateV1{}, err
	}
	s.state = candidate
	return result, nil
}

func (s *Store) Advance(transition Transition) (StateV1, error) {
	transition = normalizeTransition(transition)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Intent == nil || s.state.Current == nil || len(s.state.History) == 0 {
		return StateV1{}, errors.New("[D120 rotation] rotation 尚未 durable allocate")
	}
	last := s.state.History[len(s.state.History)-1]
	// 相同 certified transition 重放只返回 first result；同 head 不能改写 phase/evidence。
	if last.Transition.CertifiedHeadHash == transition.CertifiedHeadHash {
		if wire.EqualCanonical(last.Transition, transition) {
			return last.ResultingState, nil
		}
		return StateV1{}, errors.New("[D120 rotation] 同一 certified head 对应冲突 transition")
	}
	if err := s.verify(s.state.Intent, s.state.Current, &transition); err != nil {
		return StateV1{}, fmt.Errorf("[D120 rotation] transition head 未获 certified authority: %w", err)
	}
	result, err := Advance(*s.state.Intent, *s.state.Current, transition)
	if err != nil {
		return StateV1{}, err
	}
	record, err := newTransitionRecord(last.Sequence+1, last.ResultingStateHash, transition, result)
	if err != nil {
		return StateV1{}, err
	}
	candidate := cloneDurableState(s.state)
	candidate.History = append(candidate.History, record)
	candidate.Current = &result
	if err := s.persistLocked(candidate); err != nil {
		return StateV1{}, err
	}
	s.state = candidate
	return result, nil
}

func newTransitionRecord(sequence int64, previousHash string, transition Transition, result StateV1) (TransitionRecordV1, error) {
	hash, err := wire.HashObject(DomainState, result)
	if err != nil {
		return TransitionRecordV1{}, err
	}
	return TransitionRecordV1{
		Schema: 1, Sequence: sequence, PreviousStateHash: previousHash,
		Transition: transition, ResultingState: result, ResultingStateHash: hash,
	}, nil
}

func validateDurableState(state *DurableStateV1, verify CertifiedAuthorityVerifier) error {
	if state == nil || state.Schema != 1 || state.History == nil ||
		(state.Intent == nil) != (state.Current == nil) || (state.Intent == nil) != (len(state.History) == 0) {
		return errors.New("[D120 rotation] durable state shape 无效")
	}
	if state.Intent == nil {
		return nil
	}
	if err := ValidateIntent(state.Intent); err != nil {
		return err
	}
	var replay StateV1
	previousHash := wire.EmptyHashV1
	for i := range state.History {
		record := &state.History[i]
		if record.Schema != 1 || record.Sequence != int64(i+1) || record.PreviousStateHash != previousHash ||
			!wire.EqualCanonical(record.Transition, normalizeTransition(record.Transition)) {
			return errors.New("[D120 rotation] transition history sequence/canonical form 无效")
		}
		if i == 0 {
			if err := validateAllocationTransition(&record.Transition); err != nil {
				return err
			}
			if err := verify(state.Intent, nil, &record.Transition); err != nil {
				return err
			}
			var err error
			replay, err = Allocate(*state.Intent, record.Transition.CertifiedHeadHash)
			if err != nil {
				return err
			}
		} else {
			if err := verify(state.Intent, &replay, &record.Transition); err != nil {
				return err
			}
			var err error
			replay, err = Advance(*state.Intent, replay, record.Transition)
			if err != nil {
				return err
			}
		}
		hash, err := wire.HashObject(DomainState, replay)
		if err != nil || hash != record.ResultingStateHash || !wire.EqualCanonical(replay, record.ResultingState) {
			return errors.New("[D120 rotation] transition history result/hash 无效")
		}
		previousHash = hash
	}
	if !wire.EqualCanonical(replay, *state.Current) {
		return errors.New("[D120 rotation] current state 不等于 history replay 结果")
	}
	return nil
}

func validateAllocationTransition(transition *Transition) error {
	if transition == nil || transition.NextPhase != "allocated" || transition.CertifiedAt == "" || transition.ReaderFloor != 0 ||
		transition.Guard != nil || transition.Emergency || len(transition.EvidenceRefs) != 0 ||
		transition.LocalVerificationEvidenceHash != "" || transition.ExternalVerificationEvidenceHash != "" {
		return errors.New("[D120 rotation] initial allocation transition shape 无效")
	}
	if _, err := wire.ParseTimeZ(transition.CertifiedAt); err != nil {
		return err
	}
	return requireHash(transition.CertifiedHeadHash)
}

func (s *Store) persistLocked(state DurableStateV1) error {
	if err := validateDurableState(&state, s.verify); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(state)
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
		_, err = file.Write(body)
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

func normalizeTransition(transition Transition) Transition {
	transition.EvidenceRefs = append([]string(nil), transition.EvidenceRefs...)
	sort.Strings(transition.EvidenceRefs)
	return transition
}

func cloneDurableState(state DurableStateV1) DurableStateV1 {
	body, _ := wire.MarshalCanonical(state)
	var clone DurableStateV1
	_, _ = wire.DecodeStrict(body, 16<<20, &clone)
	return clone
}
