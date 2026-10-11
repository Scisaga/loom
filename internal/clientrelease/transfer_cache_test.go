package clientrelease

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"loom/internal/control"
)

func TestReviewedTransferSharesAuthenticatedParsingAndRechecksBytes(t *testing.T) {
	if *reviewedStore == "" || *reviewedPublic == "" {
		t.Skip("requires explicit signed package store and independent public key")
	}
	key, err := control.ReadReleasePublicKey(*reviewedPublic)
	if err != nil {
		t.Fatal(err)
	}
	source, err := New(*reviewedStore, key)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	set, err := source.Read()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("initial authenticated parsing=%s", time.Since(started))
	files, err := TransferFiles(source.root, set)
	if err != nil {
		t.Fatal(err)
	}
	// Hard links are read-only fixture inputs. Every mutation below atomically
	// replaces the fixture path with a new inode, leaving originals untouched.
	fixtureRoot, err := os.MkdirTemp(filepath.Dir(source.root), ".demo-transfer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(fixtureRoot) })
	warm, err := New(fixtureRoot, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if file.Name == "current.json" {
			t.Fatal("source pointer entered the transfer plan")
		}
		path := filepath.Join(warm.root, file.Name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(source.root, file.Name), path); err != nil {
			t.Fatal(err)
		}
	}
	warm.packages = source.packages
	var workers sync.WaitGroup
	errors := make(chan error, 3)
	started = time.Now()
	for i := 0; i < 3; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			var archive bytes.Buffer
			err := warm.WriteArchive(set.ID, &archive, files)
			if err == nil && archive.Len() != 1024 {
				t.Error("fully reused catalog transferred payloads")
			}
			errors <- err
		}()
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal("shared authenticated parsing changed transfer acceptance", err)
		}
	}
	t.Logf("three concurrent warm transfers=%s", time.Since(started))
	entry := set.Catalog.Entries[0]
	for _, value := range set.Catalog.Entries {
		if value.Artifact.Size < entry.Artifact.Size {
			entry = value
		}
	}
	delete(warm.packages, packageCacheKey(entry))
	if err := warm.WriteArchive(set.ID, io.Discard, files); err != nil || len(warm.packages) != len(set.Catalog.Entries) {
		t.Fatal("deleted parse cache could not rebuild from originals", err)
	}
	for _, name := range []string{digestPath("bin", entry.Artifact.Digest, ""), digestPath("manifests", entry.ManifestDigest, "manifest.sig")} {
		original, err := os.ReadFile(filepath.Join(source.root, name))
		if err != nil {
			t.Fatal(err)
		}
		changed := bytes.Clone(original)
		changed[len(changed)/2] ^= 1
		path := filepath.Join(warm.root, name)
		if err := os.WriteFile(path+".changed", changed, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".changed", path); err != nil {
			t.Fatal(err)
		}
		if err := warm.WriteArchive(set.ID, io.Discard, files); err == nil {
			t.Fatal("shared cache concealed changed actual input", name)
		}
		actual, err := os.ReadFile(filepath.Join(source.root, name))
		if err != nil || !bytes.Equal(actual, original) {
			t.Fatal("fixture mutation affected protected originals", err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(source.root, name), path); err != nil {
			t.Fatal(err)
		}
	}
}
