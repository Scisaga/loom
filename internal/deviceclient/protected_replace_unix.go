//go:build !windows

package deviceclient

import "os"

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
