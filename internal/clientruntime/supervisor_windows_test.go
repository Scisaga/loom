//go:build windows

package clientruntime

import (
	"io"
	"os/exec"
	"testing"
	"time"
)

func TestWindowsChildGuardTerminatesJob(t *testing.T) {
	command := exec.Command("ping.exe", "-t", "127.0.0.1")
	command.Stdout, command.Stderr = io.Discard, io.Discard
	configureRunCommand(command)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	guard, err := attachChildGuard(command.Process)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	defer guard.Close()
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	if err := guard.Terminate(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("closing the Windows Job did not terminate its process")
	}
}
