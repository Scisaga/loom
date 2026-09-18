package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"loom/internal/model"
)

func mutateDeviceSSOT(path, expected string, edit func([]byte) ([]byte, error)) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	if len(expected) != sha256.Size*2 || strings.ToLower(expected) != expected {
		return errors.New("SSOT revision must be a lowercase SHA-256 hex digest")
	}
	return withDeviceSSOTLock(path, func() error {
		current, mode, err := readDeviceSSOT(path)
		if err != nil {
			return err
		}
		if got := deviceSSOTRevision(current); got != expected {
			return fmt.Errorf("SSOT revision changed (current %s); inspect again before retrying", got)
		}
		next, err := edit(current)
		if err != nil {
			return err
		}
		if deviceSSOTRevision(next) == deviceSSOTRevision(current) {
			return nil
		}
		return writeFileAtomicDurable(path, next, mode)
	})
}

func readDeviceSSOT(path string) ([]byte, os.FileMode, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 4<<20 {
		return nil, 0, errors.New("SSOT must be a regular file no larger than 4 MiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, 0, errors.New("SSOT changed while opening; retry")
	}
	body, err := io.ReadAll(io.LimitReader(file, 4<<20+1))
	if err != nil || len(body) > 4<<20 {
		return nil, 0, errors.New("read SSOT within 4 MiB boundary failed")
	}
	if _, err := model.Load(body); err != nil {
		return nil, 0, err
	}
	return body, info.Mode().Perm(), nil
}

func withDeviceSSOTLock(path string, action func() error) error {
	lockPath := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".loom.lock")
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), lockPath)
	defer file.Close()
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	return action()
}

func deviceSSOTRevision(body []byte) string {
	digest := sha256.Sum256(body)
	return fmt.Sprintf("%x", digest[:])
}
