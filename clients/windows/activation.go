package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"loom/internal/clientruntime"
)

type clientActivation struct {
	Version      clientruntime.CandidateVersion
	SlotID       string
	Executable   string
	Config       []byte
	RuntimeDir   string
	Profile      clientruntime.WindowsRuntimeProfile
	CAPath       string
	WaitForStart bool
	Started      func()
	Health       *clientruntime.WindowsHealthPlan
}

func (activation *clientActivation) key() string {
	if activation == nil {
		return ""
	}
	return activation.Version.ConfigSHA256 + "\x00" + activation.SlotID + "\x00" + string(activation.Profile)
}

func (activation *clientActivation) validate() error {
	if activation == nil {
		return errors.New("activation is nil")
	}
	if err := activation.Version.Validate(); err != nil {
		return err
	}
	if activation.SlotID == "" || activation.Executable == "" || !filepath.IsAbs(activation.Executable) ||
		filepath.Clean(activation.Executable) != activation.Executable {
		return errors.New("activation has invalid component coordinates")
	}
	if len(activation.Config) == 0 || activation.RuntimeDir == "" || !filepath.IsAbs(activation.RuntimeDir) ||
		filepath.Clean(activation.RuntimeDir) != activation.RuntimeDir {
		return errors.New("activation has invalid config or runtime directory")
	}
	return nil
}

func (activation *clientActivation) clear() {
	if activation != nil {
		clear(activation.Config)
		activation.Config = nil
	}
}

type activationPreflight func(context.Context, *clientActivation) error
type activationRunner func(context.Context, *clientActivation) error

type runningActivation struct {
	spec   *clientActivation
	cancel context.CancelFunc
	done   chan error
	exited <-chan struct{}
}

// activationManager serializes data-plane ownership. A replacement is fully
// preflighted while the old child is still active, then the old child is
// stopped before the new one may bind ports or routes. If the replacement
// exits during its startup grace period, the previous activation is restored.
type activationManager struct {
	preflight    activationPreflight
	run          activationRunner
	startupGrace time.Duration
	active       *runningActivation
	standby      *clientActivation
	observe      func(clientRuntimeState)
}

func (manager *activationManager) report(ready bool, exited <-chan struct{}) {
	if manager.observe == nil {
		return
	}
	state := clientRuntimeState{Ready: ready, Exited: exited}
	if ready && manager.active != nil {
		state.Applied = manager.active.spec.Version.Snapshot
		state.Health = manager.active.spec.Health
	}
	manager.observe(state)
}

func newActivationManager(preflight activationPreflight, run activationRunner, startupGrace time.Duration) (*activationManager, error) {
	if preflight == nil || run == nil || startupGrace <= 0 {
		return nil, errors.New("invalid data-plane activation manager configuration")
	}
	return &activationManager{preflight: preflight, run: run, startupGrace: startupGrace}, nil
}

func (manager *activationManager) Replace(ctx context.Context, next *clientActivation) (bool, error) {
	if ctx == nil {
		if next != nil {
			next.clear()
		}
		return false, errors.New("activation context is nil")
	}
	if err := next.validate(); err != nil {
		if next != nil {
			next.clear()
		}
		return false, err
	}
	if manager.active != nil && manager.active.spec.key() == next.key() {
		// 相同数据面也可能属于新的已验证快照；复制元数据，避免修改 runner 正在读的 spec。
		updated := *manager.active.spec
		updated.Version = next.Version
		manager.active.spec = &updated
		manager.report(true, manager.active.exited)
		next.clear()
		return false, nil
	}
	if err := manager.preflight(ctx, next); err != nil {
		next.clear()
		return false, fmt.Errorf("preflight replacement data plane: %w", err)
	}

	previous := manager.active
	if previous != nil {
		if err := stopRunning(previous); err != nil {
			next.clear()
			manager.active = nil
			if ctx.Err() != nil {
				previous.spec.clear()
				return false, fmt.Errorf("stop previous data plane: %w", err)
			}
			if restoreErr := manager.start(ctx, previous.spec); restoreErr != nil {
				previous.spec.clear()
				return false, errors.Join(fmt.Errorf("stop previous data plane: %w", err),
					fmt.Errorf("restart previous data plane: %w", restoreErr))
			}
			return false, fmt.Errorf("replacement abandoned; previous data plane restarted after stop error: %w", err)
		}
		manager.active = nil
	}
	if err := manager.start(ctx, next); err != nil {
		next.clear()
		if previous == nil || ctx.Err() != nil {
			return false, fmt.Errorf("start data plane: %w", err)
		}
		if restoreErr := manager.start(ctx, previous.spec); restoreErr != nil {
			previous.spec.clear()
			return false, errors.Join(fmt.Errorf("start replacement data plane: %w", err),
				fmt.Errorf("restore previous data plane: %w", restoreErr))
		}
		return false, fmt.Errorf("replacement rejected; previous data plane restored: %w", err)
	}

	if manager.standby != nil {
		manager.standby.clear()
	}
	if previous != nil {
		manager.standby = previous.spec
	} else {
		manager.standby = nil
	}
	return true, nil
}

func (manager *activationManager) start(ctx context.Context, activation *clientActivation) error {
	manager.report(false, nil)
	childContext, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	exited := make(chan struct{})
	started := make(chan struct{})
	activation.Started = func() { close(started) }
	go func() {
		err := manager.run(childContext, activation)
		close(exited)
		done <- err
	}()
	if activation.WaitForStart {
		select {
		case <-started:
		case err := <-done:
			cancel()
			if err == nil {
				err = errors.New("data plane exited before process start")
			}
			return err
		case <-ctx.Done():
			cancel()
			<-done
			return ctx.Err()
		}
	}
	timer := time.NewTimer(manager.startupGrace)
	defer timer.Stop()
	select {
	case err := <-done:
		cancel()
		if err == nil {
			return errors.New("data plane exited during startup without an error")
		}
		return err
	case <-ctx.Done():
		cancel()
		<-done
		return ctx.Err()
	case <-timer.C:
		select {
		case err := <-done:
			cancel()
			if err == nil {
				err = errors.New("data plane exited during startup")
			}
			return err
		default:
		}
		manager.active = &runningActivation{spec: activation, cancel: cancel, done: done, exited: exited}
		manager.report(true, exited)
		return nil
	}
}

func (manager *activationManager) Done() <-chan error {
	if manager == nil || manager.active == nil {
		return nil
	}
	return manager.active.done
}

// Recover handles an active child that exited after the startup grace period.
// Only a previously healthy in-memory activation may be restored; no unsigned
// file or merely cached candidate is promoted here.
func (manager *activationManager) Recover(ctx context.Context, activeErr error) error {
	if manager == nil || manager.active == nil {
		return errors.New("no active data plane to recover")
	}
	failed := manager.active.spec
	manager.active.cancel()
	manager.active = nil
	manager.report(false, nil)
	if activeErr == nil {
		activeErr = errors.New("data plane exited unexpectedly without an error")
	}
	if manager.standby == nil {
		failed.clear()
		return activeErr
	}
	standby := manager.standby
	manager.standby = nil
	if err := manager.preflight(ctx, standby); err != nil {
		failed.clear()
		standby.clear()
		return errors.Join(activeErr, fmt.Errorf("preflight previous data plane: %w", err))
	}
	if err := manager.start(ctx, standby); err != nil {
		failed.clear()
		standby.clear()
		return errors.Join(activeErr, fmt.Errorf("restore previous data plane: %w", err))
	}
	failed.clear()
	return nil
}

func (manager *activationManager) Stop() error {
	if manager == nil {
		return nil
	}
	var err error
	manager.report(false, nil)
	if manager.active != nil {
		err = stopRunning(manager.active)
		manager.active.spec.clear()
		manager.active = nil
	}
	if manager.standby != nil {
		manager.standby.clear()
		manager.standby = nil
	}
	return err
}

func stopRunning(running *runningActivation) error {
	if running == nil {
		return nil
	}
	running.cancel()
	return <-running.done
}
