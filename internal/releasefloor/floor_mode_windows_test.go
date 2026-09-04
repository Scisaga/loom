//go:build windows

package releasefloor

import (
	"os"
	"testing"
)

func assertFloorFileSecurity(t *testing.T, info os.FileInfo) {
	t.Helper()
	// Windows FileMode does not expose the NTFS DACL and reports ordinary files
	// as 0666. The installer must apply the ProgramData ACL; this unit test can
	// still reject a non-regular state object.
	if !info.Mode().IsRegular() {
		t.Fatalf("floor state is not a regular file: %v", info.Mode())
	}
}
