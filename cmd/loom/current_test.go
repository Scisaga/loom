package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
		Assignments: []publish.DeploymentAssignment{{Node: "demo-c", Snapshot: "bbbbbbbbbbbb"}},
	}
	payload, err := json.Marshal(struct {
		Schema      int                            `json:"schema"`
		Generation  uint64                         `json:"generation"`
		Snapshot    string                         `json:"snapshot"`
		Assignments []publish.DeploymentAssignment `json:"assignments,omitempty"`
		PublishedAt string                         `json:"published_at"`
	}{current.Schema, current.Generation, current.Snapshot, current.Assignments, current.PublishedAt})
	if err != nil {
		t.Fatal(err)
	}
	current.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte("loom-current-v1\x00"), payload...)))
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
	if err := cmdCurrentInspect([]string{"-file", currentPath, "-pubkey", pubPath, "-node", "demo-c"}); err != nil {
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
