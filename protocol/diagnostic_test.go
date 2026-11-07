package protocol

import "testing"

func TestEchoDiagnosticIDUsesTheExistingChallenge(t *testing.T) {
	nonce := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	const expected = "be45cb2605bf36bebde684841a28f0fd43c69850a3dce5fedba69928ee3a8991"
	if EchoDiagnosticID(nonce) != expected {
		t.Fatal("echo correlation differs from the canonical SHA256 of its challenge")
	}
}
