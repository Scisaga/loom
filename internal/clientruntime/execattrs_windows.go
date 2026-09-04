//go:build windows

package clientruntime

import (
	"os/exec"
	"syscall"
)

func configureCheckCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
