package clientrelease

import (
	"errors"
	"golang.org/x/sys/unix"
)

func downloadWorkFilesystem(path string) error {
	var info unix.Statfs_t
	if err := unix.Statfs(path, &info); err != nil {
		return err
	}
	if info.Type == unix.TMPFS_MAGIC || info.Type == unix.RAMFS_MAGIC {
		return errors.New("release captures require a disk filesystem")
	}
	return nil
}
