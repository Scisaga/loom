package clientdist

import (
	"errors"
	"golang.org/x/sys/unix"
)

func packageWorkFilesystem(root string) error {
	var info unix.Statfs_t
	if err := unix.Statfs(root, &info); err != nil {
		return err
	}
	if info.Type == unix.TMPFS_MAGIC || info.Type == unix.RAMFS_MAGIC {
		return errors.New("package work directory must use a disk filesystem")
	}
	return nil
}
