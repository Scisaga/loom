package enrollssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const maxKnownHostsBytes = 1 << 20

// KnownHostsStore owns the control-local known_hosts file used exclusively for
// enrollment. It never follows an existing file symlink.
type KnownHostsStore struct {
	Path    string
	Scanner Scanner
}

// ValidateKnownHostsPath checks the control-local trust-store boundary without
// creating it. A missing file is valid when its full parent chain is safe.
func ValidateKnownHostsPath(path string) error {
	_, err := readKnownHosts(path)
	return err
}

// ConfirmKnownHost re-scans after the operator has confirmed expected. A key
// change between display and commit fails closed. Only after equality is
// established is the key atomically installed with mode 0600.
func (s KnownHostsStore) ConfirmKnownHost(ctx context.Context, connection Connection, expected HostKey) (HostKey, error) {
	if err := validateLocalPath(s.Path, "known_hosts"); err != nil {
		return HostKey{}, err
	}
	if err := validateSecureParentPath(s.Path, "known_hosts", false); err != nil {
		return HostKey{}, err
	}
	if _, err := readKnownHosts(s.Path); err != nil {
		return HostKey{}, err
	}
	if err := connection.Validate(); err != nil {
		return HostKey{}, err
	}
	if err := validateHostKey(expected); err != nil {
		return HostKey{}, fmt.Errorf("invalid operator-confirmed host key: %w", err)
	}
	observed, err := s.Scanner.Scan(ctx, connection)
	if err != nil {
		return HostKey{}, fmt.Errorf("re-scan confirmed SSH host: %w", err)
	}
	if !sameHostKey(expected, observed) {
		return HostKey{}, fmt.Errorf("SSH host key changed after confirmation: expected %s, observed %s", expected.Fingerprint, observed.Fingerprint)
	}
	line := connection.knownHostPattern() + " " + observed.Algorithm + " " + observed.PublicKey
	if err := atomicMergeKnownHosts(s.Path, connection.knownHostPattern(), line); err != nil {
		return HostKey{}, err
	}
	return observed, nil
}

// ConfirmKnownHost is a convenience wrapper around KnownHostsStore.
func ConfirmKnownHost(ctx context.Context, scanner Scanner, path string, connection Connection, expected HostKey) (HostKey, error) {
	return (KnownHostsStore{Path: path, Scanner: scanner}).ConfirmKnownHost(ctx, connection, expected)
}

type knownHostsSnapshot struct {
	exists bool
	info   fs.FileInfo
	body   []byte
}

func readKnownHosts(path string) (knownHostsSnapshot, error) {
	if err := validateLocalPath(path, "control known_hosts"); err != nil {
		return knownHostsSnapshot{}, err
	}
	if err := validateSecureParentPath(path, "control known_hosts", false); err != nil {
		return knownHostsSnapshot{}, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return knownHostsSnapshot{}, nil
	}
	if err != nil {
		return knownHostsSnapshot{}, fmt.Errorf("inspect control known_hosts: %w", err)
	}
	if err := validateSecureFileMetadata(info, "control known_hosts"); err != nil {
		return knownHostsSnapshot{}, err
	}
	if info.Size() > maxKnownHostsBytes {
		return knownHostsSnapshot{}, fmt.Errorf("control known_hosts exceeds %d bytes", maxKnownHostsBytes)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return knownHostsSnapshot{}, fmt.Errorf("open control known_hosts: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return knownHostsSnapshot{}, fmt.Errorf("inspect open control known_hosts: %w", err)
	}
	if !os.SameFile(info, opened) {
		return knownHostsSnapshot{}, errors.New("control known_hosts changed while opening")
	}
	if err := validateSecureFileMetadata(opened, "control known_hosts"); err != nil {
		return knownHostsSnapshot{}, err
	}
	body, err := io.ReadAll(io.LimitReader(f, maxKnownHostsBytes+1))
	if err != nil {
		return knownHostsSnapshot{}, fmt.Errorf("read control known_hosts: %w", err)
	}
	if len(body) > maxKnownHostsBytes {
		return knownHostsSnapshot{}, fmt.Errorf("control known_hosts exceeds %d bytes", maxKnownHostsBytes)
	}
	if bytes.IndexByte(body, 0) >= 0 {
		return knownHostsSnapshot{}, errors.New("control known_hosts contains a NUL byte")
	}
	if err := validatePersistentKnownHosts(body); err != nil {
		return knownHostsSnapshot{}, err
	}
	return knownHostsSnapshot{exists: true, info: info, body: body}, nil
}

func atomicMergeKnownHosts(path, pattern, confirmedLine string) error {
	if err := validateKnownHostPattern(pattern); err != nil {
		return fmt.Errorf("invalid exact known_hosts pattern: %w", err)
	}
	fields := strings.Fields(confirmedLine)
	if len(fields) != 3 || fields[0] != pattern {
		return errors.New("confirmed known_hosts line must contain the exact requested pattern, Ed25519 algorithm, and key")
	}
	if err := validatePersistentKnownHosts([]byte(confirmedLine + "\n")); err != nil {
		return err
	}
	if err := ensureSecureParentDirectory(path, "control known_hosts"); err != nil {
		return err
	}
	lock, err := lockKnownHosts(path)
	if err != nil {
		return err
	}
	defer unlockKnownHosts(lock)

	dir := filepath.Dir(path)
	snapshot, err := readKnownHosts(path)
	if err != nil {
		return err
	}
	body := mergeKnownHosts(snapshot.body, pattern, confirmedLine)
	tmp, err := os.CreateTemp(dir, ".loom-known-hosts-*")
	if err != nil {
		return fmt.Errorf("create control known_hosts temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("set control known_hosts permissions: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		return fmt.Errorf("write control known_hosts: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync control known_hosts: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close control known_hosts: %w", err)
	}
	if err := ensureSnapshotUnchanged(path, snapshot); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("publish control known_hosts: %w", err)
	}
	removeTemp = false
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync control known_hosts directory: %w", err)
	}
	return nil
}

func lockKnownHosts(path string) (*os.File, error) {
	lockPath := path + ".lock"
	fd, err := syscall.Open(lockPath, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open control known_hosts lock without following symlinks: %w", err)
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	info, err := lock.Stat()
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("inspect control known_hosts lock: %w", err)
	}
	if err := validateSecureFileMetadata(info, "control known_hosts lock"); err != nil {
		_ = lock.Close()
		return nil, err
	}
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("lock control known_hosts: %w", err)
	}
	return lock, nil
}

func unlockKnownHosts(lock *os.File) {
	if lock == nil {
		return
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = lock.Close()
}

func ensureSnapshotUnchanged(path string, snapshot knownHostsSnapshot) error {
	current, err := os.Lstat(path)
	if !snapshot.exists {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reinspect control known_hosts: %w", err)
		}
		return errors.New("control known_hosts appeared during update; retry")
	}
	if err != nil {
		return fmt.Errorf("reinspect control known_hosts: %w", err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(snapshot.info, current) {
		return errors.New("control known_hosts changed during update; retry")
	}
	return nil
}

func mergeKnownHosts(existing []byte, pattern, confirmedLine string) []byte {
	lines := strings.Split(string(existing), "\n")
	out := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if fields[0] != pattern {
			out = append(out, line)
		}
	}
	out = append(out, confirmedLine)
	return []byte(strings.Join(out, "\n") + "\n")
}

func validatePersistentKnownHosts(body []byte) error {
	for lineNumber, line := range strings.Split(string(body), "\n") {
		if line == "" {
			continue
		}
		if strings.TrimSpace(line) != line {
			return fmt.Errorf("control known_hosts line %d has leading or trailing whitespace", lineNumber+1)
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return fmt.Errorf("control known_hosts line %d is not an exact package-owned Ed25519 entry", lineNumber+1)
		}
		if err := validateKnownHostPattern(fields[0]); err != nil {
			return fmt.Errorf("control known_hosts line %d: %w", lineNumber+1, err)
		}
		if fields[1] != "ssh-ed25519" {
			return fmt.Errorf("control known_hosts line %d must use ssh-ed25519", lineNumber+1)
		}
		if _, err := hostKeyForBlob(fields[2]); err != nil {
			return fmt.Errorf("control known_hosts line %d has an invalid Ed25519 key: %w", lineNumber+1, err)
		}
	}
	return nil
}

func validateKnownHostPattern(pattern string) error {
	if pattern == "" || strings.ContainsAny(pattern, "*?!|,@ ") {
		return errors.New("hashed, wildcard, marker, list, and empty host patterns are not accepted")
	}
	if strings.HasPrefix(pattern, "[") {
		close := strings.LastIndex(pattern, "]:")
		if close <= 1 || close+2 >= len(pattern) {
			return errors.New("invalid bracketed host and port")
		}
		host := pattern[1:close]
		if err := validateHost(host); err != nil {
			return err
		}
		port, err := strconv.Atoi(pattern[close+2:])
		if err != nil || port < 1 || port > 65535 || port == 22 {
			return errors.New("bracketed known_hosts port must be 1-65535 and not 22")
		}
		return nil
	}
	return validateHost(pattern)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
