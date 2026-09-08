package main

import (
	"context"
	"loom/internal/clientcore"
	"loom/internal/clientruntime"
)

// §16.1 / D98：串行激活事务只发布成功的 active 快照；worker 不读取 manager.active。
type clientRuntimeState struct {
	Generation context.Context
	Agent      *clientruntime.WindowsAgent
	Policy     *clientruntime.WindowsSelectorPlan
	Preference clientcore.Preference
	Applied    string
	Ready      bool
	Exited     <-chan struct{}
	Health     *clientruntime.WindowsHealthPlan
}

func (state clientRuntimeState) active() bool {
	if state.Generation != nil && state.Generation.Err() != nil {
		return false
	}
	if !state.Ready || state.Applied == "" || state.Exited == nil {
		return false
	}
	select {
	case <-state.Exited:
		return false
	default:
		return true
	}
}
