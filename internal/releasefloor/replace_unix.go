//go:build !windows

package releasefloor

import "os"

func replaceFile(source, target string) error {
	return os.Rename(source, target)
}

func syncParent(path string) error {
	parent, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := parent.Sync(); err != nil {
		_ = parent.Close()
		return err
	}
	return parent.Close()
}
