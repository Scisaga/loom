package clientrelease

import (
	"errors"
	"os"
)

func prepareDownloadWork(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	entry, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 || entry.Mode().Perm() != 0700 {
		return errors.New("release capture root must be a private directory")
	}
	return downloadWorkFilesystem(path)
}
