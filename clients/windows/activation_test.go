package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"loom/internal/clientruntime"
)

func activationFixture(t *testing.T, marker string) *clientActivation {
	t.Helper()
	hex := strings.Repeat(marker, 64)
	return &clientActivation{
		Version: clientruntime.CandidateVersion{
			Generation: 1, PayloadSHA256: strings.Repeat("a", 64), Snapshot: strings.Repeat("b", 12),
			BundleSHA256: strings.Repeat("c", 64), ConfigSHA256: hex,
		},
		SlotID: marker + "-slot", Executable: filepath.Join(t.TempDir(), "sing-box"),
		Config: []byte("config-" + marker), RuntimeDir: filepath.Join(t.TempDir(), "runtime"),
		Profile: clientruntime.WindowsInstalledProfile, CAPath: clientruntime.WindowsInstalledCAPath,
	}
}

type activationHarness struct {
	mu        sync.Mutex
	starts    []string
	stops     []string
	failStart map[string]error
	crash     map[string]chan error
	preflight map[string]error
}

func (harness *activationHarness) preflightActivation(_ context.Context, activation *clientActivation) error {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	return harness.preflight[activation.key()]
}

func (harness *activationHarness) runActivation(ctx context.Context, activation *clientActivation) error {
	key := activation.key()
	harness.mu.Lock()
	harness.starts = append(harness.starts, key)
	fail := harness.failStart[key]
	crash := harness.crash[key]
	harness.mu.Unlock()
	if fail != nil {
		return fail
	}
	if crash != nil {
		select {
		case err := <-crash:
			return err
		case <-ctx.Done():
		}
	} else {
		<-ctx.Done()
	}
	harness.mu.Lock()
	harness.stops = append(harness.stops, key)
	harness.mu.Unlock()
	return nil
}

func (harness *activationHarness) counts() (starts, stops int) {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	return len(harness.starts), len(harness.stops)
}

func (harness *activationHarness) setStartFailure(key string, err error) {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	harness.failStart[key] = err
}

func (harness *activationHarness) setCrash(key string, crash chan error) {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	harness.crash[key] = crash
}

func (harness *activationHarness) setPreflightFailure(key string, err error) {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	harness.preflight[key] = err
}

func newActivationHarnessManager(t *testing.T, harness *activationHarness) *activationManager {
	t.Helper()
	if harness.failStart == nil {
		harness.failStart = map[string]error{}
	}
	if harness.crash == nil {
		harness.crash = map[string]chan error{}
	}
	if harness.preflight == nil {
		harness.preflight = map[string]error{}
	}
	manager, err := newActivationManager(harness.preflightActivation, harness.runActivation, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestActivationManagerAvoidsRestartForSameCoordinates(t *testing.T) {
	harness := &activationHarness{}
	manager := newActivationHarnessManager(t, harness)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := activationFixture(t, "1")
	if changed, err := manager.Replace(ctx, first); err != nil || !changed {
		t.Fatalf("initial activation changed=%t err=%v", changed, err)
	}
	duplicate := activationFixture(t, "1")
	if changed, err := manager.Replace(ctx, duplicate); err != nil || changed {
		t.Fatalf("duplicate activation changed=%t err=%v", changed, err)
	}
	if duplicate.Config != nil {
		t.Fatal("discarded duplicate retained hydrated config")
	}
	if starts, stops := harness.counts(); starts != 1 || stops != 0 {
		t.Fatalf("duplicate activation starts/stops = %d/%d", starts, stops)
	}
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestActivationManagerRestoresPreviousWhenReplacementFailsToStart(t *testing.T) {
	harness := &activationHarness{}
	manager := newActivationHarnessManager(t, harness)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	previous := activationFixture(t, "2")
	if _, err := manager.Replace(ctx, previous); err != nil {
		t.Fatal(err)
	}
	replacement := activationFixture(t, "3")
	harness.setStartFailure(replacement.key(), errors.New("fixture launch failure"))
	if _, err := manager.Replace(ctx, replacement); err == nil || !strings.Contains(err.Error(), "previous data plane restored") {
		t.Fatalf("replacement failure = %v", err)
	}
	if manager.active == nil || manager.active.spec.key() != previous.key() {
		t.Fatal("previous activation was not restored")
	}
	if replacement.Config != nil {
		t.Fatal("failed replacement retained hydrated config")
	}
	if starts, stops := harness.counts(); starts != 3 || stops != 1 {
		t.Fatalf("failed replacement starts/stops = %d/%d, want 3/1", starts, stops)
	}
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestActivationManagerRecoversPreviousAfterRuntimeCrash(t *testing.T) {
	harness := &activationHarness{}
	manager := newActivationHarnessManager(t, harness)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	previous := activationFixture(t, "4")
	if _, err := manager.Replace(ctx, previous); err != nil {
		t.Fatal(err)
	}
	replacement := activationFixture(t, "5")
	crash := make(chan error, 1)
	harness.setCrash(replacement.key(), crash)
	if _, err := manager.Replace(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	crash <- errors.New("fixture runtime crash")
	var activeErr error
	select {
	case activeErr = <-manager.Done():
	case <-time.After(time.Second):
		t.Fatal("replacement did not report its runtime failure")
	}
	if err := manager.Recover(ctx, activeErr); err != nil {
		t.Fatal(err)
	}
	if manager.active == nil || manager.active.spec.key() != previous.key() {
		t.Fatal("previous activation was not recovered after runtime failure")
	}
	if replacement.Config != nil {
		t.Fatal("crashed replacement retained hydrated config")
	}
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestActivationManagerPreflightFailureLeavesCurrentRunning(t *testing.T) {
	harness := &activationHarness{}
	manager := newActivationHarnessManager(t, harness)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	current := activationFixture(t, "6")
	if _, err := manager.Replace(ctx, current); err != nil {
		t.Fatal(err)
	}
	rejected := activationFixture(t, "7")
	harness.setPreflightFailure(rejected.key(), errors.New("fixture preflight failure"))
	if _, err := manager.Replace(ctx, rejected); err == nil {
		t.Fatal("preflight failure was accepted")
	}
	if manager.active == nil || manager.active.spec.key() != current.key() {
		t.Fatal("preflight failure stopped the current activation")
	}
	if starts, stops := harness.counts(); starts != 1 || stops != 0 {
		t.Fatalf("preflight failure starts/stops = %d/%d", starts, stops)
	}
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
}
