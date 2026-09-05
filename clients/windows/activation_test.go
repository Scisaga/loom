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
	duplicate.Version.Snapshot = "0123456789ab"
	if changed, err := manager.Replace(ctx, duplicate); err != nil || changed {
		t.Fatalf("duplicate activation changed=%t err=%v", changed, err)
	}
	if duplicate.Config != nil {
		t.Fatal("discarded duplicate retained hydrated config")
	}
	if manager.active.spec.Version.Snapshot != "0123456789ab" {
		t.Fatal("identical data plane did not advance its authenticated snapshot metadata")
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
	var states []clientRuntimeState
	manager.observe = func(state clientRuntimeState) { states = append(states, state) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	previous := activationFixture(t, "2")
	if _, err := manager.Replace(ctx, previous); err != nil {
		t.Fatal(err)
	}
	replacement := activationFixture(t, "3")
	replacement.Version.Snapshot = "222222222222"
	harness.setStartFailure(replacement.key(), errors.New("fixture launch failure"))
	if _, err := manager.Replace(ctx, replacement); err == nil || !strings.Contains(err.Error(), "previous data plane restored") {
		t.Fatalf("replacement failure = %v", err)
	}
	if manager.active == nil || manager.active.spec.key() != previous.key() {
		t.Fatal("previous activation was not restored")
	}
	last := states[len(states)-1]
	if !last.Ready || last.Applied != previous.Version.Snapshot {
		t.Fatal("rollback did not report the restored snapshot")
	}
	for _, state := range states {
		if state.Ready && state.Applied == replacement.Version.Snapshot {
			t.Fatal("failed replacement became applied evidence")
		}
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
	var reported clientRuntimeState
	manager.observe = func(state clientRuntimeState) { reported = state }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	previous := activationFixture(t, "4")
	if _, err := manager.Replace(ctx, previous); err != nil {
		t.Fatal(err)
	}
	replacement := activationFixture(t, "5")
	replacement.Version.Snapshot = "222222222222"
	crash := make(chan error, 1)
	harness.setCrash(replacement.key(), crash)
	if _, err := manager.Replace(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	if !reported.active() || reported.Applied != replacement.Version.Snapshot {
		t.Fatal("successful replacement did not report its snapshot")
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
	if !reported.active() || reported.Applied != previous.Version.Snapshot {
		t.Fatal("recovery retained the failed replacement's snapshot")
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
	var reported clientRuntimeState
	manager.observe = func(state clientRuntimeState) { reported = state }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	current := activationFixture(t, "6")
	if _, err := manager.Replace(ctx, current); err != nil {
		t.Fatal(err)
	}
	rejected := activationFixture(t, "7")
	rejected.Version.Snapshot = "222222222222"
	harness.setPreflightFailure(rejected.key(), errors.New("fixture preflight failure"))
	if _, err := manager.Replace(ctx, rejected); err == nil {
		t.Fatal("preflight failure was accepted")
	}
	if manager.active == nil || manager.active.spec.key() != current.key() {
		t.Fatal("preflight failure stopped the current activation")
	}
	if !reported.active() || reported.Applied != current.Version.Snapshot {
		t.Fatal("unactivated candidate replaced the active snapshot in reports")
	}
	if starts, stops := harness.counts(); starts != 1 || stops != 0 {
		t.Fatalf("preflight failure starts/stops = %d/%d", starts, stops)
	}
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestActivationStatusWaitsForProcessAndDetectsExit(t *testing.T) {
	start := make(chan struct{})
	crash := make(chan struct{})
	states := make(chan clientRuntimeState, 12)
	manager, err := newActivationManager(func(context.Context, *clientActivation) error { return nil },
		func(ctx context.Context, activation *clientActivation) error {
			select {
			case <-ctx.Done():
				return nil
			case <-start:
			}
			activation.Started()
			select {
			case <-ctx.Done():
				return nil
			case <-crash:
				return errors.New("fixture process crash")
			}
		}, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	manager.observe = func(state clientRuntimeState) { states <- state }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	activation := activationFixture(t, "1")
	activation.WaitForStart = true
	done := make(chan error, 1)
	go func() { _, err := manager.Replace(ctx, activation); done <- err }()
	if initial := <-states; initial.Ready || initial.Applied != "" {
		t.Fatal("startup claimed a running snapshot")
	}
	select {
	case <-done:
		t.Fatal("activation completed before the process started")
	case <-time.After(30 * time.Millisecond):
	}
	close(start)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ready := <-states
	if !ready.Ready || ready.Applied != activation.Version.Snapshot || !ready.active() {
		t.Fatal("stable process was not reported with its applied snapshot")
	}
	close(crash)
	activeErr := <-manager.Done()
	if ready.active() {
		t.Fatal("process exit still appears healthy before the manager handles recovery")
	}
	if err := manager.Recover(ctx, activeErr); err == nil {
		t.Fatal("crash without standby should fail")
	}
	failed := <-states
	if failed.Ready || failed.Applied != "" {
		t.Fatal("crash still claimed a running snapshot or remained healthy")
	}
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
}
