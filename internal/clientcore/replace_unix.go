//go:build !windows

package clientcore

import (
	"os"
)

func replaceFile(from, to string) error { return os.Rename(from, to) }

func syncParent(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
