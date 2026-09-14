//go:build !windows

package enrollmentv2

import "os"

func replaceDurableFile(source, target string) error { return os.Rename(source, target) }

func syncDurableDirectory(path string) error {
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
