package enrollmentv2

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestChallengeConsumeWriteFailureDoesNotConsumeInMemory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "blocked")
	store, err := OpenChallengeReplayStore(filepath.Join(directory, "replay.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(directory, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	hash := wire.HashRaw("challenge-test", []byte("write-failure"))
	if err := store.Consume(hash, now.Add(time.Minute).Format(time.RFC3339), now); err == nil {
		t.Fatal("不可写 store 错误地报告 consume 成功")
	}
	if len(store.state.Entries) != 0 {
		t.Fatalf("写失败后 challenge 已在内存中被消费: %#v", store.state)
	}
}

func TestChallengeReplayConsumptionSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "challenges.json")
	store, err := OpenChallengeReplayStore(path)
	if err != nil {
		t.Fatal(err)
	}
	challengeHash := wire.HashRaw("challenge-replay-test-v1", []byte("challenge"))
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	if err := store.Consume(challengeHash, "2026-09-11T12:01:00Z", now); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenChallengeReplayStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Consume(challengeHash, "2026-09-11T12:01:00Z", now); err == nil {
		t.Fatal("accepted replayed challenge after restart")
	}
	other := wire.HashRaw("challenge-replay-test-v1", []byte("other"))
	if err := reopened.Consume(other, "2026-09-11T12:00:00Z", now); err == nil {
		t.Fatal("accepted challenge at exclusive expiry")
	}
}
