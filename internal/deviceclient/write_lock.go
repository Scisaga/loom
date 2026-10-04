package deviceclient

import (
	"errors"
	"os"
	"path/filepath"
)

// Serialize replacement and durable reads of the one authority file across
// separate CLI/runtime handles. The empty lock file contains no identity,
// floor, or recovery state.
func lockStateFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	entry, entryErr := os.Lstat(path + ".lock")
	if statErr != nil || entryErr != nil || !info.Mode().IsRegular() || entry.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, entry) {
		_ = file.Close()
		return nil, errors.New("device state lock is not a regular owned file")
	}
	if err := lockProtectedFile(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
