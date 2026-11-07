package protocol

import (
	"crypto/sha256"
	"encoding/hex"
)

// EchoDiagnosticID correlates an existing echo challenge without exposing its
// raw nonce. It is diagnostic metadata, never identity or authorization.
func EchoDiagnosticID(nonce [16]byte) string {
	digest := sha256.Sum256(nonce[:])
	return hex.EncodeToString(digest[:])
}
