//go:build linux

package control

import (
	"encoding/binary"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const receptionAttribute = "user.loom.received_at"
const coverageAttribute = "user.loom.reception_since"

// The annotation belongs to the same protected inode as the immutable original.
// It is local evidence only, never part of a signature or an authorization.
func fileReception(path, attribute string) (time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return time.Time{}, err
	}
	defer f.Close()
	entry, err := os.Lstat(path)
	if err != nil {
		return time.Time{}, err
	}
	info, err := f.Stat()
	if err != nil || !os.SameFile(entry, info) || (!info.Mode().IsRegular() && !info.IsDir()) || entry.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return time.Time{}, errors.New("unprotected reception annotation")
	}
	var raw [8]byte
	n, err := unix.Fgetxattr(int(f.Fd()), attribute, raw[:])
	if errors.Is(err, unix.ENODATA) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	if n != len(raw) || binary.BigEndian.Uint64(raw[:]) > uint64(1<<63-1) || binary.BigEndian.Uint64(raw[:]) == 0 {
		return time.Time{}, errors.New("invalid reception annotation")
	}
	return time.Unix(0, int64(binary.BigEndian.Uint64(raw[:]))).UTC(), nil
}

func annotateReception(f *os.File, attribute string, at time.Time) error {
	if at.UnixNano() <= 0 {
		return errors.New("invalid reception time")
	}
	return unix.Fsetxattr(int(f.Fd()), attribute, binary.BigEndian.AppendUint64(nil, uint64(at.UnixNano())), unix.XATTR_CREATE)
}

func ensureFileCoverage(root string) error {
	since, err := fileReception(root, coverageAttribute)
	if err != nil || !since.IsZero() {
		return err
	}
	f, err := os.Open(root)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := annotateReception(f, coverageAttribute, time.Now()); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return f.Sync()
}

func annotateOriginal(f *os.File) error { return annotateReception(f, receptionAttribute, time.Now()) }
