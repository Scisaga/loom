package clientrelease

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/control"
)

func TestArtifactCaptureSeparatesVerifiedBytesFromMutableInput(t *testing.T) {
	root := t.TempDir()
	if err := downloadWorkFilesystem(root); err != nil {
		t.Skip("disk-backed scratch required for artifact capture")
	}
	store, err := New(root, make(ed25519.PublicKey, ed25519.PublicKeySize))
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("demo-package"), 10000)
	artifact := control.ReleaseArtifact{Name: "loom-client-linux-amd64.tar.gz", Digest: control.ReleaseDigest(body), Size: control.U64(len(body)), Audience: "public", MediaType: "application/gzip"}
	name := filepath.Join(root, digestPath("bin", artifact.Digest, ""))
	if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, body, 0644); err != nil {
		t.Fatal(err)
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	input, err := store.captureArtifact(context.Background(), opened, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, bytes.Repeat([]byte("x"), len(body)), 0644); err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(input)
	if err != nil || !bytes.Equal(actual, body) {
		t.Fatalf("verified capture changed: %v", err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	remaining, err := os.ReadDir(store.workRoot)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("capture retained: %v", err)
	}
	for _, changed := range [][]byte{body[:len(body)-1], append(append([]byte(nil), body...), 0), bytes.Repeat([]byte("x"), len(body))} {
		if err := os.WriteFile(name, changed, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.captureArtifact(context.Background(), opened, artifact); err == nil {
			t.Fatal("changed original accepted")
		}
	}
}

func TestDownloadWorkRejectsSymlinkAndSharedDirectory(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	if err := os.Mkdir(shared, 0755); err != nil {
		t.Fatal(err)
	}
	if err := prepareDownloadWork(shared); err == nil {
		t.Fatal("shared directory accepted")
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(shared, alias); err != nil {
		t.Fatal(err)
	}
	if err := prepareDownloadWork(alias); err == nil {
		t.Fatal("symlink accepted")
	}
}
