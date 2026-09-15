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

type executionPlanRecordV1 struct {
	RotationID string          `json:"rotation_id"`
	IntentHash string          `json:"intent_hash"`
	Intent     IntentV1        `json:"intent"`
	PlanHash   string          `json:"plan_hash"`
	Plan       ExecutionPlanV1 `json:"plan"`
}

type executionPlanStateV1 struct {
	Schema  int                     `json:"schema"`
	Records []executionPlanRecordV1 `json:"records"`
}

// FrozenExecutionPlanV1 的字段故意不导出；只有 ExecutionPlanStore 的耐久
// first-result 才能构造 reconciler 接受的 plan capability。
type FrozenExecutionPlanV1 struct {
	plan     ExecutionPlanV1
	planHash string
}

func (frozen FrozenExecutionPlanV1) Plan() ExecutionPlanV1 {
	return cloneExecutionPlan(frozen.plan)
}

func (frozen FrozenExecutionPlanV1) PlanHash() string {
	return frozen.planHash
}

type ExecutionPlanStore struct {
	mu    sync.Mutex
	path  string
	state executionPlanStateV1
}

func OpenExecutionPlanStore(path string) (*ExecutionPlanStore, error) {
	if path == "" {
		return nil, errors.New("[rotation] execution plan store path 不能为空")
	}
	store := &ExecutionPlanStore{path: path,
		state: executionPlanStateV1{Schema: 1, Records: []executionPlanRecordV1{}}}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var state executionPlanStateV1
	if _, err := wire.DecodeStrict(body, 16<<20, &state); err != nil {
		return nil, fmt.Errorf("[rotation] execution plan store 非规范或损坏: %w", err)
	}
	if err := validateExecutionPlanState(&state); err != nil {
		return nil, err
	}
	store.state = state
	return store, nil
}

func (store *ExecutionPlanStore) Freeze(intent IntentV1,
	plan ExecutionPlanV1) (FrozenExecutionPlanV1, error) {
	if store == nil {
		return FrozenExecutionPlanV1{}, errors.New("[rotation] execution plan store 不能为空")
	}
	if err := ValidateIntent(&intent); err != nil {
		return FrozenExecutionPlanV1{}, err
	}
	planHash, err := ExecutionPlanHash(&intent, &plan)
	if err != nil {
		return FrozenExecutionPlanV1{}, err
	}
	intentHash, err := wire.HashObject(DomainIntent, intent)
	if err != nil {
		return FrozenExecutionPlanV1{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	index := sort.Search(len(store.state.Records), func(index int) bool {
		return store.state.Records[index].RotationID >= intent.RotationID
	})
	if index < len(store.state.Records) && store.state.Records[index].RotationID == intent.RotationID {
		existing := store.state.Records[index]
		if existing.IntentHash != intentHash || existing.PlanHash != planHash ||
			!wire.EqualCanonical(existing.Plan, plan) {
			return FrozenExecutionPlanV1{}, errors.New("[rotation] rotation ID 已冻结另一 execution plan")
		}
		return frozenExecutionPlan(existing.Plan, existing.PlanHash), nil
	}
	record := executionPlanRecordV1{RotationID: intent.RotationID, IntentHash: intentHash, Intent: intent,
		PlanHash: planHash, Plan: cloneExecutionPlan(plan)}
	candidate := cloneExecutionPlanState(store.state)
	candidate.Records = append(candidate.Records, executionPlanRecordV1{})
	copy(candidate.Records[index+1:], candidate.Records[index:])
	candidate.Records[index] = record
	if err := store.persistLocked(candidate); err != nil {
		return FrozenExecutionPlanV1{}, err
	}
	store.state = candidate
	return frozenExecutionPlan(plan, planHash), nil
}

func validateExecutionPlanState(state *executionPlanStateV1) error {
	if state == nil || state.Schema != 1 || state.Records == nil {
		return errors.New("[rotation] execution plan store schema 无效")
	}
	for index := range state.Records {
		record := &state.Records[index]
		if record.RotationID == "" || record.RotationID != record.Plan.RotationID ||
			index > 0 && state.Records[index-1].RotationID >= record.RotationID {
			return errors.New("[rotation] execution plans identity/order 无效")
		}
		if err := ValidateIntent(&record.Intent); err != nil {
			return err
		}
		if record.Intent.RotationID != record.RotationID {
			return errors.New("[rotation] stored execution intent identity 不匹配")
		}
		intentHash, err := wire.HashObject(DomainIntent, record.Intent)
		if err != nil || intentHash != record.IntentHash {
			return errors.New("[rotation] stored execution intent hash 不匹配")
		}
		if err := ValidateExecutionPlan(&record.Intent, &record.Plan); err != nil {
			return err
		}
		planHash, err := wire.HashObject(DomainExecutionPlan, record.Plan)
		if err != nil || planHash != record.PlanHash {
			return errors.New("[rotation] stored execution plan hash 不匹配")
		}
	}
	return nil
}

func (store *ExecutionPlanStore) persistLocked(candidate executionPlanStateV1) error {
	if err := validateExecutionPlanState(&candidate); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(candidate)
	if err != nil {
		return err
	}
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, filepath.Base(store.path)+".tmp-")
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
	if err := os.Rename(temporary, store.path); err != nil {
		return err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = directoryHandle.Sync()
	closeErr = directoryHandle.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func frozenExecutionPlan(plan ExecutionPlanV1, planHash string) FrozenExecutionPlanV1 {
	return FrozenExecutionPlanV1{plan: cloneExecutionPlan(plan), planHash: planHash}
}

func cloneExecutionPlan(plan ExecutionPlanV1) ExecutionPlanV1 {
	body, _ := wire.MarshalCanonical(plan)
	var clone ExecutionPlanV1
	_, _ = wire.DecodeStrict(body, 4<<20, &clone)
	return clone
}

func cloneExecutionPlanState(state executionPlanStateV1) executionPlanStateV1 {
	body, _ := wire.MarshalCanonical(state)
	var clone executionPlanStateV1
	_, _ = wire.DecodeStrict(body, 16<<20, &clone)
	return clone
}
