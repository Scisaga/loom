//go:build !windows

package clientruntime

import "os/exec"

func configureCheckCommand(*exec.Cmd) {}
