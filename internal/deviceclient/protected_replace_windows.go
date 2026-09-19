//go:build windows

package deviceclient

import "golang.org/x/sys/windows"

func replaceProtectedFile(source, target string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// MoveFileEx with MOVEFILE_WRITE_THROUGH supplies the closest Windows
// equivalent to syncing the containing directory. Opening a directory and
// calling FlushFileBuffers through os.File.Sync returns access denied.
func syncProtectedDirectory(string) error { return nil }
