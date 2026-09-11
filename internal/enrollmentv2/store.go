package enrollmentv2

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"loom/internal/wire"
)

// DurableRecord 只保存可复制的稳定摘要；raw token、challenge、CSR 正文和 PoP
// 签名字节都不得越过私有请求验证边界进入事务日志（D129、D130）。
type DurableRecord struct {
	InviteID        string             `json:"invite_id"`
	TokenCommitment string             `json:"token_commitment"`
	State           TransactionStateV2 `json:"state"`
}

type durableState struct {
	Schema  int             `json:"schema"`
	Records []DurableRecord `json:"records"`
}

// Store 为 Enrollment reducer 提供原子耐久 CAS。相同稳定 claim 重放返回同一
// state；同一 Invite/token 的不同 core/key/request 永久冲突（D130）。
type Store struct {
	mu    sync.Mutex
	path  string
	state durableState
}

func OpenStore(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("[D130 Enrollment] transaction store path 不能为空")
	}
	store := &Store{path: path, state: durableState{Schema: 1, Records: []DurableRecord{}}}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var state durableState
	if _, err := wire.DecodeStrict(body, 32<<20, &state); err != nil {
		return nil, fmt.Errorf("[D130 Enrollment] transaction store 非规范或损坏: %w", err)
	}
	if err := validateDurableState(&state); err != nil {
		return nil, err
	}
	store.state = state
	return store, nil
}

func (s *Store) Snapshot(inviteID string) (TransactionStateV2, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, found := findRecord(s.state.Records, inviteID)
	if !found {
		return TransactionStateV2{}, false
	}
	return s.state.Records[index].State, true
}

func (s *Store) Reserve(invite InviteContext, operation ClaimOperationV2, admission *wire.StableEnrollmentAdmissionQCV1, set *wire.ControlSetV1, committedAt string) (TransactionStateV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := Reserve(invite, operation, admission, set, committedAt)
	if err != nil {
		return TransactionStateV2{}, err
	}
	index, found := findRecord(s.state.Records, invite.InviteID)
	if found {
		existing := s.state.Records[index]
		if existing.TokenCommitment == invite.TokenCommitment && sameStableClaim(existing.State, next) {
			return existing.State, nil
		}
		return TransactionStateV2{}, errors.New("[D130 Enrollment] 同一 Invite/token 已被不同 request/core/key 耐久预留")
	}
	for _, existing := range s.state.Records {
		if existing.TokenCommitment == invite.TokenCommitment {
			return TransactionStateV2{}, errors.New("[D130 Enrollment] token commitment 已绑定另一 Invite")
		}
	}
	candidate := cloneDurableState(s.state)
	candidate.Records = append(candidate.Records, DurableRecord{InviteID: invite.InviteID, TokenCommitment: invite.TokenCommitment, State: next})
	sort.Slice(candidate.Records, func(i, j int) bool { return candidate.Records[i].InviteID < candidate.Records[j].InviteID })
	if err := s.persistLocked(candidate); err != nil {
		return TransactionStateV2{}, err
	}
	s.state = candidate
	return next, nil
}

func (s *Store) RecordProvisional(operation ProvisionalIssuanceOperationV1) (TransactionStateV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, found := findRecord(s.state.Records, operation.InviteID)
	if !found {
		return TransactionStateV2{}, errors.New("[D130 Enrollment] provisional issuance 缺耐久 reservation")
	}
	current := s.state.Records[index].State
	if current.Status == "issued_provisional" || current.Status == "completed" {
		operationHash, err := wire.HashObject(DomainProvisionalOperation, operation)
		if err == nil && current.ProvisionalIssuanceOperationHash == operationHash {
			return current, nil
		}
		return TransactionStateV2{}, errors.New("[D130 Enrollment] 同一 claim 已有不同 provisional first-result")
	}
	next, err := RecordProvisional(current, operation)
	if err != nil {
		return TransactionStateV2{}, err
	}
	candidate := cloneDurableState(s.state)
	candidate.Records[index].State = next
	if err := s.persistLocked(candidate); err != nil {
		return TransactionStateV2{}, err
	}
	s.state = candidate
	return next, nil
}

func (s *Store) Complete(operation CompletionOperationV2, approval *wire.StableEnrollmentApprovalQCV2, set *wire.ControlSetV1) (TransactionStateV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, found := findRecord(s.state.Records, operation.InviteID)
	if !found {
		return TransactionStateV2{}, errors.New("[D130 Enrollment] completion 缺耐久 provisional issuance")
	}
	current := s.state.Records[index].State
	if current.Status == "completed" {
		operationHash, err := wire.HashObject(DomainCompletionOperation, operation)
		if err == nil && current.CompletionOperationHash == operationHash {
			return current, nil
		}
		return TransactionStateV2{}, errors.New("[D130 Enrollment] completed transaction 不接受不同 completion")
	}
	next, err := Complete(current, operation, approval, set)
	if err != nil {
		return TransactionStateV2{}, err
	}
	candidate := cloneDurableState(s.state)
	candidate.Records[index].State = next
	if err := s.persistLocked(candidate); err != nil {
		return TransactionStateV2{}, err
	}
	s.state = candidate
	return next, nil
}

func (s *Store) persistLocked(candidate durableState) error {
	if err := validateDurableState(&candidate); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(candidate)
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
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, s.path); err != nil {
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

func cloneDurableState(state durableState) durableState {
	return durableState{Schema: state.Schema, Records: append([]DurableRecord(nil), state.Records...)}
}

func validateDurableState(state *durableState) error {
	if state == nil || state.Schema != 1 || state.Records == nil {
		return errors.New("[D130 Enrollment] transaction store schema 无效")
	}
	seenTokens := make(map[string]struct{}, len(state.Records))
	for index := range state.Records {
		record := &state.Records[index]
		if record.InviteID == "" || record.InviteID != record.State.InviteID || index > 0 && state.Records[index-1].InviteID >= record.InviteID {
			return errors.New("[D130 Enrollment] transaction records 未按 Invite ID 严格排序")
		}
		if _, err := wire.ParseHash(record.TokenCommitment); err != nil {
			return err
		}
		if _, duplicate := seenTokens[record.TokenCommitment]; duplicate {
			return errors.New("[D130 Enrollment] transaction store 含重复 token commitment")
		}
		seenTokens[record.TokenCommitment] = struct{}{}
		if _, err := TransactionHash(record.State); err != nil {
			return err
		}
	}
	return nil
}

func findRecord(records []DurableRecord, inviteID string) (int, bool) {
	index := sort.Search(len(records), func(i int) bool { return records[i].InviteID >= inviteID })
	return index, index < len(records) && records[index].InviteID == inviteID
}

func sameStableClaim(left, right TransactionStateV2) bool {
	return left.ClusterID == right.ClusterID && left.InviteID == right.InviteID && left.RequestID == right.RequestID &&
		left.ClaimCoreHash == right.ClaimCoreHash && left.IdentityKeyHash == right.IdentityKeyHash &&
		left.WrappingKeyHash == right.WrappingKeyHash && left.ClaimOperationHash == right.ClaimOperationHash
}
