//go:build windows

package releasefloor

import "golang.org/x/sys/windows"

func replaceFile(source, target string) error {
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

// Windows does not expose portable directory fsync semantics. MOVEFILE_WRITE_THROUGH
// provides the strongest replacement durability available through this API.
func syncParent(string) error { return nil }
