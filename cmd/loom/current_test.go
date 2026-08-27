package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/publish"
)

func TestCurrentInspectVerifiesEnvelopeAndNodeSelection(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	current := &publish.DeploymentCurrent{
		Schema: publish.DeploymentCurrentSchema, Generation: 7,
		Snapshot: "aaaaaaaaaaaa", PublishedAt: "2026-08-27T12:00:00Z",
		Assignments: []publish.DeploymentAssignment{{Node: "hz01", Snapshot: "bbbbbbbbbbbb"}},
	}
	if err := current.Sign(priv); err != nil {
		t.Fatal(err)
	}
	body, err := current.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	currentPath := filepath.Join(dir, "current.json")
	pubPath := filepath.Join(dir, "platform.pub")
	if err := os.WriteFile(currentPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdCurrentInspect([]string{"-file", currentPath, "-pubkey", pubPath, "-node", "hz01"}); err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), body...)
	tampered[len(tampered)/2] ^= 1
	if err := os.WriteFile(currentPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdCurrentInspect([]string{"-file", currentPath, "-pubkey", pubPath}); err == nil {
		t.Fatal("被篡改的 signed current 仍通过 inspect")
	}
}
