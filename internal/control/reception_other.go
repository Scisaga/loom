//go:build !linux

package control

import (
	"os"
	"time"
)

const receptionAttribute = "user.loom.received_at"
const coverageAttribute = "user.loom.reception_since"

// Non-Linux clients do not host the control original store. No reception time
// is synthesized from their clocks or file modification times.
func fileReception(string, string) (time.Time, error) { return time.Time{}, nil }
func ensureFileCoverage(string) error                 { return nil }
func annotateOriginal(*os.File) error                 { return nil }
