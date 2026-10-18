package clientrelease

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/control"
)

// Observe the real disk boundary before cancelling the underlying context.
// This avoids timing a cancellation against a machine-dependent copy speed.
type artifactCancellationContext struct {
	context.Context
	cancel context.CancelFunc
	ready  func() bool
}

func (ctx artifactCancellationContext) Err() error {
	if ctx.Context.Err() == nil && ctx.ready() {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestArtifactCaptureCancellationCleansPartialCopyAndAllowsRetry(t *testing.T) {
	root := transferTestDiskRoot(t)
	store, err := New(root, make(ed25519.PublicKey, ed25519.PublicKeySize))
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("demo-package"), 10000)
	artifact := control.ReleaseArtifact{Name: "loom-client-linux-amd64.tar.gz", Digest: control.ReleaseDigest(body), Size: control.U64(len(body)), Audience: "public", MediaType: "application/gzip"}
	writeProjectionFile(t, root, digestPath("bin", artifact.Digest, ""), body)
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := artifactCancellationContext{Context: ctx, cancel: cancel, ready: func() bool {
		entries, _ := os.ReadDir(store.workRoot)
		for _, entry := range entries {
			info, err := entry.Info()
			if err == nil && info.Size() > 0 && info.Size() < int64(len(body)) {
				return true
			}
		}
		return false
	}}
	if _, err := store.captureArtifact(observed, opened, artifact); !errors.Is(err, context.Canceled) {
		t.Fatal("partial capture did not inherit cancellation", err)
	}
	if entries, err := os.ReadDir(store.workRoot); err != nil || len(entries) != 0 {
		t.Fatal("cancelled capture retained temporary bytes", err)
	}
	input, err := store.captureArtifact(context.Background(), opened, artifact)
	if err != nil {
		t.Fatal("same artifact could not be retried", err)
	}
	actual, readErr := io.ReadAll(input)
	if err := errors.Join(readErr, input.Close()); err != nil || !bytes.Equal(actual, body) {
		t.Fatal("retry changed the original bytes", err)
	}
}

func TestReviewedStoreOpenCancellationDoesNotCachePartialInspection(t *testing.T) {
	if *reviewedStore == "" || *reviewedPublic == "" {
		t.Skip("requires explicit signed package store and independent public key")
	}
	key, err := control.ReadReleasePublicKey(*reviewedPublic)
	if err != nil {
		t.Fatal(err)
	}
	workRoot := transferTestDiskRoot(t)
	store, err := NewWithWorkRoot(*reviewedStore, key, filepath.Join(workRoot, "captures"))
	if err != nil {
		t.Fatal(err)
	}
	source := store.ProjectionSource()
	set, err := source.Read()
	if err != nil {
		t.Fatal(err)
	}
	var artifact control.ReleaseArtifact
	for _, pkg := range set.Packages {
		if pkg.Entry.ComponentID == "linux-client-bootstrap" {
			artifact = pkg.Entry.Artifact
			break
		}
	}
	if artifact.Size <= 64<<10 {
		t.Fatal("reviewed catalog has no nontrivial Linux package")
	}
	for _, stage := range []string{"before capture", "during capture", "during inspection"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			observed := artifactCancellationContext{Context: ctx, cancel: cancel, ready: func() bool {
				if stage == "before capture" {
					return true
				}
				entries, _ := os.ReadDir(store.workRoot)
				for _, entry := range entries {
					if stage == "during inspection" && entry.IsDir() && strings.HasPrefix(entry.Name(), ".loom-package-") {
						return true
					}
					info, err := entry.Info()
					if stage == "during capture" && err == nil && !info.IsDir() && info.Size() > 0 && info.Size() < int64(artifact.Size) {
						return true
					}
				}
				return false
			}}
			if reader, err := source.Open(observed, set.ID, artifact); !errors.Is(err, context.Canceled) {
				if reader != nil {
					reader.Close()
				}
				t.Fatal("Open did not stop at the inherited cancellation", err)
			}
			if len(store.packages) != 0 {
				t.Fatal("cancelled inspection populated the removable package cache")
			}
			entries, err := os.ReadDir(store.workRoot)
			if err != nil && !errors.Is(err, os.ErrNotExist) || len(entries) != 0 {
				t.Fatal("cancelled Open retained an archive or unpacked package", err)
			}
		})
	}
	reader, err := source.Open(context.Background(), set.ID, artifact)
	if err != nil {
		t.Fatal("same original package could not complete after cancellation", err)
	}
	readback, err := io.ReadAll(reader)
	if err := errors.Join(err, reader.Close()); err != nil || control.ReleaseDigest(readback) != artifact.Digest || len(store.packages) != 1 {
		t.Fatal("normal retry did not fully verify the same package", err)
	}
	if entries, err := os.ReadDir(store.workRoot); err != nil || len(entries) != 0 {
		t.Fatal("successful retry retained temporary bytes", err)
	}
}

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
	if err := os.Chmod(shared, 0755); err != nil {
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
