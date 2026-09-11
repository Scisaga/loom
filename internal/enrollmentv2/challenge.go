package enrollmentv2

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"loom/internal/wire"
)

type ChallengeReplayEntryV1 struct {
	ChallengeHash string `json:"challenge_hash"`
	ExpiresAt     string `json:"expires_at"`
}

type ChallengeReplayStateV1 struct {
	Schema  int                      `json:"schema"`
	Entries []ChallengeReplayEntryV1 `json:"entries"`
}

// ChallengeReplayStore 在 admission attestation 前原子消费 server nonce challenge，崩溃后仍拒绝重放。
type ChallengeReplayStore struct {
	mu    sync.Mutex
	path  string
	state ChallengeReplayStateV1
}

func OpenChallengeReplayStore(path string) (*ChallengeReplayStore, error) {
	if path == "" {
		return nil, errors.New("[D129 Enrollment] challenge replay path 不能为空")
	}
	store := &ChallengeReplayStore{path: path, state: ChallengeReplayStateV1{Schema: 1, Entries: []ChallengeReplayEntryV1{}}}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var state ChallengeReplayStateV1
	if _, err := wire.DecodeStrict(body, 16<<20, &state); err != nil {
		return nil, err
	}
	if err := validateChallengeReplayState(&state); err != nil {
		return nil, err
	}
	store.state = state
	return store, nil
}

func (store *ChallengeReplayStore) Consume(challengeHash, expiresAt string, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, err := wire.ParseHash(challengeHash); err != nil || now.IsZero() {
		return errors.New("[D129 Enrollment] challenge hash/可信时间无效")
	}
	expires, err := wire.ParseTimeZ(expiresAt)
	if err != nil || !now.UTC().Before(expires) {
		return errors.New("[D129 Enrollment] challenge 已过期")
	}
	kept := make([]ChallengeReplayEntryV1, 0, len(store.state.Entries)+1)
	for _, entry := range store.state.Entries {
		entryExpiry, _ := wire.ParseTimeZ(entry.ExpiresAt)
		if now.UTC().Before(entryExpiry) {
			kept = append(kept, entry)
		}
	}
	position := sort.Search(len(kept), func(i int) bool { return kept[i].ChallengeHash >= challengeHash })
	if position < len(kept) && kept[position].ChallengeHash == challengeHash {
		return errors.New("[D129 Enrollment] challenge 已被消费，拒绝重放")
	}
	kept = append(kept, ChallengeReplayEntryV1{})
	copy(kept[position+1:], kept[position:])
	kept[position] = ChallengeReplayEntryV1{ChallengeHash: challengeHash, ExpiresAt: expiresAt}
	candidate := ChallengeReplayStateV1{Schema: 1, Entries: kept}
	if err := store.persistLocked(candidate); err != nil {
		return err
	}
	store.state = candidate
	return nil
}

func validateChallengeReplayState(state *ChallengeReplayStateV1) error {
	if state == nil || state.Schema != 1 {
		return errors.New("[D129 Enrollment] challenge replay state schema 无效")
	}
	for i, entry := range state.Entries {
		if _, err := wire.ParseHash(entry.ChallengeHash); err != nil {
			return err
		}
		if _, err := wire.ParseTimeZ(entry.ExpiresAt); err != nil {
			return err
		}
		if i > 0 && state.Entries[i-1].ChallengeHash >= entry.ChallengeHash {
			return errors.New("[D129 Enrollment] challenge replay entries 未严格排序")
		}
	}
	return nil
}

func (store *ChallengeReplayStore) persistLocked(candidate ChallengeReplayStateV1) error {
	if err := validateChallengeReplayState(&candidate); err != nil {
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
	temporary, err := os.CreateTemp(directory, ".challenge-replay-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	_, err = temporary.Write(body)
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
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
