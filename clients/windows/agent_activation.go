package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"loom/internal/agent"
	"loom/internal/clientruntime"
)

// §5.5：Agent 和数据面是一个激活单位；先 cancel/join Agent，才允许停止或替换 sing-box。
func runWindowsAgentActivation(ctx context.Context, a *clientActivation) error {
	return runAgentDataPlane(ctx, a, clientruntime.RunWindowsDataPlaneProfileStarted)
}

type dataPlaneStarter func(context.Context, string, []byte, string, clientruntime.WindowsRuntimeProfile, string, func()) error

func runAgentDataPlane(ctx context.Context, a *clientActivation, start dataPlaneStarter, readiness ...func(context.Context, *agent.Config) error) error {
	wait := clientruntime.WaitWindowsAgentAPI
	if len(readiness) > 0 {
		wait = readiness[0]
	}
	planeCtx, planeCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer planeCancel()
	planeDone := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		planeDone <- start(planeCtx, a.Executable, a.Config, a.RuntimeDir, a.Profile, a.CAPath, func() { close(started) })
	}()
	stopPlane := func() error { planeCancel(); return <-planeDone }
	select {
	case <-ctx.Done():
		_ = stopPlane()
		return nil
	case err := <-planeDone:
		return err
	case <-started:
	}
	// Direct 沿用授权 direct 候选的数据面行为，完全没有 Agent 或另一个 selector writer。
	cfg := a.AgentConfig
	if cfg == nil && a.Policy != nil {
		cfg = a.Policy.DirectReadinessConfig()
	}
	if cfg != nil {
		if err := wait(ctx, cfg); err != nil {
			_ = stopPlane()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
	var err error
	if a.AgentConfig != nil {
		runtimeIdentity := fmt.Sprintf("windows-runtime-v1:%s:%x", a.Profile, sha256.Sum256(a.Config))
		a.AgentRuntime, err = clientruntime.StartWindowsAgent(ctx, a.AgentConfig, a.RuntimeDir, runtimeIdentity)
		if err != nil {
			_ = stopPlane()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
	if ctx.Err() != nil {
		_ = a.AgentRuntime.Stop()
		_ = stopPlane()
		return nil
	}
	if a.Started != nil {
		a.Started()
	}
	select {
	case <-ctx.Done():
		err = a.AgentRuntime.Stop()
		return errors.Join(err, stopPlane())
	case err := <-planeDone:
		return errors.Join(err, a.AgentRuntime.Stop())
	case <-a.AgentRuntime.Done():
		err = a.AgentRuntime.Stop()
		if err == nil && ctx.Err() == nil {
			err = errors.New("[§5.5] Agent 意外退出")
		}
		return errors.Join(err, stopPlane())
	}
}
