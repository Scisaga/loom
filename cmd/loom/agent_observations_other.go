//go:build !linux

package main

import (
	"context"
	"errors"
	"io"

	"loom/internal/agent"
)

func startAgentDeviceObservations(context.Context, *agent.Config, string, io.Writer) (*agent.ObservationCache, func(), error) {
	return nil, func() {}, errors.New("root-owned Agent 观测交接仅用于 Linux")
}
