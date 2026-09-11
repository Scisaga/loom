package rotation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/wire"
)

func certifiedTransition(phase, at, label string) Transition {
	return Transition{NextPhase: phase, CertifiedAt: at, CertifiedHeadHash: wire.HashRaw("test-rotation-head-v1", []byte(label)), EvidenceRefs: []string{}}
}

func TestDurableRotationReplaysSameOperationAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rotation.json")
	verify := func(_ *IntentV1, _ *StateV1, transition *Transition) error {
		return requireHash(transition.CertifiedHeadHash)
	}
	store, err := OpenStore(path, verify)
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent(t)
	allocated, err := store.Begin(intent, certifiedTransition("allocated", "2026-01-01T00:00:00Z", "allocate"))
	if err != nil || allocated.Phase != "allocated" {
		t.Fatalf("allocate=%#v err=%v", allocated, err)
	}
	preparedTransition := certifiedTransition("prepared", "2026-01-01T00:00:00Z", "prepared")
	prepared, err := store.Advance(preparedTransition)
	if err != nil || prepared.Phase != "prepared" {
		t.Fatalf("prepared=%#v err=%v", prepared, err)
	}
	reopened, err := OpenStore(path, verify)
	if err != nil || reopened.Snapshot().Current.Phase != "prepared" {
		t.Fatalf("restart lost phase: %#v err=%v", reopened, err)
	}
	if replay, err := reopened.Advance(preparedTransition); err != nil || !wire.EqualCanonical(replay, prepared) {
		t.Fatalf("same certified transition did not return first result: %#v err=%v", replay, err)
	}
	conflict := preparedTransition
	conflict.NextPhase = "advertised"
	conflict.LocalVerificationEvidenceHash = wire.HashRaw("test-evidence-v1", []byte("local"))
	conflict.ExternalVerificationEvidenceHash = wire.HashRaw("test-evidence-v1", []byte("external"))
	if _, err := reopened.Advance(conflict); err == nil {
		t.Fatal("同一 certified head 被改写为另一 transition")
	}
	advertised := certifiedTransition("advertised", "2026-01-01T00:00:00Z", "advertised")
	advertised.LocalVerificationEvidenceHash = wire.HashRaw("test-evidence-v1", []byte("local"))
	advertised.ExternalVerificationEvidenceHash = wire.HashRaw("test-evidence-v1", []byte("external"))
	state, err := reopened.Advance(advertised)
	if err != nil || state.Phase != "advertised" {
		t.Fatalf("advertise=%#v err=%v", state, err)
	}
	if got := reopened.Snapshot(); len(got.History) != 3 || got.Intent.FrozenDependencies.TargetListenerGeneration != 2 {
		t.Fatalf("durable history/port changed: %#v", got)
	}
}

func TestDurableRotationRejectsTamperedHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rotation.json")
	verify := func(_ *IntentV1, _ *StateV1, transition *Transition) error {
		return requireHash(transition.CertifiedHeadHash)
	}
	store, err := OpenStore(path, verify)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin(testIntent(t), certifiedTransition("allocated", "2026-01-01T00:00:00Z", "allocate")); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(body), `"phase":"allocated"`, `"phase":"preferred"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(path, verify); err == nil {
		t.Fatal("篡改 resulting state 后仍能恢复 rotation")
	}
}
