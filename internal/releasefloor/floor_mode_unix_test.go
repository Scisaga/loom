//go:build !windows

package releasefloor

import (
	"os"
	"testing"
)

func assertFloorFileSecurity(t *testing.T, info os.FileInfo) {
	t.Helper()
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("floor permissions = %#o, want 0600", got)
	}
}
