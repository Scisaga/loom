//go:build windows

package clientcore

import "golang.org/x/sys/windows"

func replaceFile(from, to string) error {
	fromName, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toName, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(fromName, toName,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// MoveFileEx with WRITE_THROUGH flushes the replacement before returning.
// Windows does not expose the Unix directory-fsync contract through os.File.
func syncParent(string) error { return nil }
