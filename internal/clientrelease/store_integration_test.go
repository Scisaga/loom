package clientrelease

import (
	"bytes"
	"flag"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"loom/internal/control"
)

var reviewedStore = flag.String("release-store-dir", "", "explicit signed real-package store for integration")
var reviewedPublic = flag.String("release-pubkey", "", "independently installed public verification key")

func TestReviewedStoreRechecksBytesAndRebuildsCache(t *testing.T) {
	if *reviewedStore == "" || *reviewedPublic == "" {
		t.Skip("requires explicit signed package store and independent public key")
	}
	key, err := control.ReadReleasePublicKey(*reviewedPublic)
	if err != nil {
		t.Fatal(err)
	}
	// Every failure operates on a disposable copy, never the publication input.
	directory := t.TempDir()
	err = filepath.WalkDir(*reviewedStore, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(*reviewedStore, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.MkdirAll(filepath.Join(directory, rel), 0o755)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(directory, rel), body, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(directory, key)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := store.Read()
	if err != nil || len(initial.Packages) == 0 {
		t.Fatal("real signed store unreadable", err)
	}
	for _, pkg := range initial.Packages {
		reader, err := store.Open(initial.ID, pkg.Entry.Artifact)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || control.ReleaseDigest(body) != pkg.Entry.Artifact.Digest {
			t.Fatal("download differs from original bytes", err)
		}
		for _, component := range pkg.Components {
			apkAgent := pkg.Entry.ComponentID == "android-application" && component.ComponentID == "agent"
			if component.ArtifactDigest == pkg.Entry.Artifact.Digest && !apkAgent {
				t.Fatal("archive digest used as runtime file digest")
			}
		}
	}
	restarted, err := New(directory, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.Read()
	if err != nil || !reflect.DeepEqual(initial, got) {
		t.Fatal("cache deletion changed verified result", err)
	}
	entry := initial.Packages[0].Entry
	for _, relative := range []string{digestPath("bin", entry.Artifact.Digest, ""), digestPath("manifests", entry.ManifestDigest, "manifest.json"), digestPath("manifests", entry.ManifestDigest, "manifest.sig"), digestPath("catalogs", initial.ID, "catalog.sig")} {
		path := filepath.Join(directory, relative)
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		changed := bytes.Clone(original)
		changed[len(changed)/2] ^= 1
		if err := os.WriteFile(path, changed, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Read(); err == nil {
			t.Fatal("cached source accepted changed signed bytes", relative)
		}
		if _, err := store.Open(initial.ID, entry.Artifact); err == nil {
			t.Fatal("cached download accepted damaged source", relative)
		}
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	final, err := store.Read()
	if err != nil || !reflect.DeepEqual(initial, final) {
		t.Fatal("exact bytes could not be recovered", err)
	}
}

func TestReviewedStoreImportUsesExactCatalogAndOriginalBytes(t *testing.T) {
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
	want, err := source.Read()
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(t.TempDir(), "uploaded")
	if _, err := Import(*reviewedStore, staging, want.ID, key, ""); err != nil {
		t.Fatal(err)
	}
	// Uploads need no mutable pointer. A leftover or untrusted source pointer
	// must never select what the operator imports.
	if err := os.WriteFile(filepath.Join(staging, "current.json"), []byte("not a release pointer"), 0o644); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "distribution")
	for attempt := 0; attempt < 2; attempt++ {
		got, err := Import(staging, destination, want.ID, key, "")
		if err != nil || !reflect.DeepEqual(want, got) {
			t.Fatal("exact import or retry changed the signed release", attempt, err)
		}
	}
	// A fresh reader verifies the destination without the uploader's cache.
	reopened, err := New(destination, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Read()
	if err != nil || !reflect.DeepEqual(want, got) {
		t.Fatal("import did not persist the original signed release", err)
	}
	for _, pkg := range want.Packages {
		for _, relative := range []string{digestPath("bin", pkg.Entry.Artifact.Digest, ""), digestPath("manifests", pkg.Entry.ManifestDigest, "manifest.json"), digestPath("manifests", pkg.Entry.ManifestDigest, "manifest.sig")} {
			original, err := os.ReadFile(filepath.Join(staging, relative))
			if err != nil {
				t.Fatal(err)
			}
			copied, err := os.ReadFile(filepath.Join(destination, relative))
			if err != nil || !bytes.Equal(original, copied) {
				t.Fatal("import reinterpreted original signed bytes", err)
			}
		}
	}
	signature := filepath.Join(staging, digestPath("catalogs", want.ID, "catalog.sig"))
	body, err := os.ReadFile(signature)
	if err != nil {
		t.Fatal(err)
	}
	body[0] ^= 1
	if err := os.WriteFile(signature, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(staging, destination, want.ID, key, want.ID); err == nil {
		t.Fatal("retry accepted a corrupt upload")
	}
	got, err = reopened.Read()
	if err != nil || !reflect.DeepEqual(want, got) {
		t.Fatal("rejected upload damaged destination", err)
	}
}
