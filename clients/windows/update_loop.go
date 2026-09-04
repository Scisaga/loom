package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"loom/internal/clientupdate"
)

type updatePuller interface {
	PullOnce(context.Context) (clientupdate.Result, error)
}

const dataPlaneStartupGrace = 2 * time.Second

func runActiveUpdateLoop(ctx context.Context, updater updatePuller, interval time.Duration,
	initial *clientActivation, prepareActivation func() (*clientActivation, error),
	preflight activationPreflight, run activationRunner, startupGrace time.Duration) (retErr error) {
	if updater == nil || interval <= 0 || prepareActivation == nil {
		if initial != nil {
			initial.clear()
		}
		return errors.New("invalid active update loop configuration")
	}
	manager, err := newActivationManager(preflight, run, startupGrace)
	if err != nil {
		if initial != nil {
			initial.clear()
		}
		return err
	}
	defer func() {
		if err := manager.Stop(); err != nil && retErr == nil {
			retErr = fmt.Errorf("stop Windows data plane: %w", err)
		}
	}()
	if initial != nil {
		if _, err := manager.Replace(ctx, initial); err != nil {
			return fmt.Errorf("activate restored Windows candidate: %w", err)
		}
		logActivation("activated restored Windows candidate", manager.active.spec)
	}

	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case activeErr := <-manager.Done():
			if err := manager.Recover(ctx, activeErr); err != nil {
				return fmt.Errorf("active Windows data plane failed: %w", err)
			}
			logActivation("restored previous Windows data plane after runtime failure", manager.active.spec)
		case <-timer.C:
			result, err := updater.PullOnce(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				log.Printf("signed configuration update failed: %v", err)
			} else {
				for _, warning := range result.Warnings {
					log.Printf("distribution mirror warning: %s", warning)
				}
				log.Printf("verified configuration generation=%d snapshot=%s changed=%t",
					result.Generation, result.Snapshot, result.Changed)
				activation, err := prepareActivation()
				if err != nil {
					log.Printf("verified configuration is not a usable Windows activation: %v", err)
				} else {
					changed, activateErr := manager.Replace(ctx, activation)
					if activateErr != nil {
						// Replace preflights before stopping the current child and
						// restores it when a new child dies during startup.
						log.Printf("Windows candidate activation rejected: %v", activateErr)
					} else if changed {
						logActivation("activated Windows candidate", manager.active.spec)
					}
				}
			}
			timer.Reset(interval)
		}
	}
}

func logActivation(message string, activation *clientActivation) {
	if activation == nil {
		return
	}
	configID := activation.Version.ConfigSHA256
	if len(configID) > 12 {
		configID = configID[:12]
	}
	slotID := activation.SlotID
	if len(slotID) > 12 {
		slotID = slotID[:12]
	}
	log.Printf("%s snapshot=%s config=%s slot=%s profile=%s", message,
		activation.Version.Snapshot, configID, slotID, activation.Profile)
}
