//go:build !windows

package control

import "os"

func replaceControlFile(source, target string) error { return os.Rename(source, target) }

func syncControlDirectory(path string) error {
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
