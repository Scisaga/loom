//go:build linux

package control

import (
	"context"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrepareReportMaintenanceDoesNotCreateAuthorityCoverage(t *testing.T) {
	root, socket, _, _ := reportIndexFixture(t)
	if err := unix.Removexattr(root, coverageAttribute); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []ReportIndexOptions{{Verify: true}, {Rebuild: true}} {
		if err := PrepareReportIndex(context.Background(), root, socket, mode); err != nil {
			t.Fatal(err)
		}
		at, err := fileReception(root, coverageAttribute)
		if err != nil || !at.IsZero() {
			t.Fatal("report maintenance created authority coverage evidence", err)
		}
	}
}
