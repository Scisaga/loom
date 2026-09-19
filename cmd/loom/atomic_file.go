package main

import (
	"os"
	"path/filepath"
)

// writeFileAtomicDurable writes an authoritative local file by syncing both
// the new inode and its containing directory before returning.
func writeFileAtomicDurable(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".loom-atomic-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}
