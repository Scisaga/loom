//go:build !windows

package clientruntime

import (
	"os"
	"os/exec"
)

type childGuard struct{ process *os.Process }

func configureRunCommand(*exec.Cmd) {}

func attachChildGuard(process *os.Process) (*childGuard, error) {
	return &childGuard{process: process}, nil
}

func (guard *childGuard) Terminate() error { return guard.process.Kill() }
func (guard *childGuard) Close() error     { return nil }
