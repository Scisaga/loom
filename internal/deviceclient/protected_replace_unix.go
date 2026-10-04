//go:build !windows

package deviceclient

import (
	"os"
	"syscall"
)

func lockProtectedFile(file *os.File) error { return syscall.Flock(int(file.Fd()), syscall.LOCK_EX) }

func replaceProtectedFile(source, target string) error { return os.Rename(source, target) }

func syncProtectedDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}
