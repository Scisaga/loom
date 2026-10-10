package clientrelease

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"loom/internal/control"
)

func TestReviewedImportCacheStillChecksOriginalInputAndTarget(t *testing.T) {
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
	set, err := source.Read()
	if err != nil || len(set.Packages) == 0 {
		t.Fatal("signed source unavailable", err)
	}
	read := func(relative string) []byte {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(*reviewedStore, relative))
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	body := read(digestPath("catalogs", set.ID, "catalog.json"))
	signature := read(digestPath("catalogs", set.ID, "catalog.sig"))
	inputs := map[string]Input{}
	for _, pkg := range set.Packages {
		inputs[pkg.Entry.Artifact.Digest] = Input{Body: read(digestPath("bin", pkg.Entry.Artifact.Digest, "")), Manifest: pkg.ManifestBody, Signature: pkg.Signature}
	}
	entry := set.Packages[0].Entry
	writer := func() *Store {
		t.Helper()
		store, err := New(filepath.Join(t.TempDir(), "target"), key)
		if err != nil {
			t.Fatal(err)
		}
		// The same authenticated cache handoff as the ordinary Import entry.
		store.packages = source.packages
		return store
	}
	for _, field := range []string{"body", "truncated", "extended", "manifest", "signature", "missing-signature"} {
		t.Run(field, func(t *testing.T) {
			changed := map[string]Input{}
			for id, input := range inputs {
				changed[id] = input
			}
			value := changed[entry.Artifact.Digest]
			switch field {
			case "body":
				value.Body = bytes.Clone(value.Body)
				value.Body[len(value.Body)/2] ^= 1
			case "truncated":
				value.Body = value.Body[:len(value.Body)-1]
			case "extended":
				value.Body = append(bytes.Clone(value.Body), 0)
			case "manifest":
				value.Manifest = bytes.Clone(value.Manifest)
				value.Manifest[len(value.Manifest)/2] ^= 1
			case "signature":
				value.Signature = bytes.Clone(value.Signature)
				value.Signature[0] ^= 1
			case "missing-signature":
				value.Signature = nil
			}
			changed[entry.Artifact.Digest] = value
			store := writer()
			if _, err := publishTo(store, body, signature, changed, "", false); err == nil {
				t.Fatal("cached parse accepted changed input", field)
			}
			if _, err := os.Stat(store.root); !os.IsNotExist(err) {
				t.Fatal("rejected input modified the target", err)
			}
		})
	}
	store := writer()
	got, err := publishTo(store, body, signature, inputs, "", false)
	if err != nil || !reflect.DeepEqual(got, set) {
		t.Fatal("warm prepare changed original signed content", err)
	}
	if _, err := os.Stat(filepath.Join(store.root, "current.json")); !os.IsNotExist(err) {
		t.Fatal("prepare selected the target")
	}
	path := filepath.Join(store.root, digestPath("bin", entry.Artifact.Digest, ""))
	changed := bytes.Clone(inputs[entry.Artifact.Digest].Body)
	changed[len(changed)/2] ^= 1
	if err := os.WriteFile(path, changed, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publishTo(store, body, signature, inputs, "", true); err == nil {
		t.Fatal("warm cache hid a changed target artifact")
	}
	if _, err := os.Stat(filepath.Join(store.root, "current.json")); !os.IsNotExist(err) {
		t.Fatal("changed target advanced current")
	}
	if err := os.WriteFile(path, inputs[entry.Artifact.Digest].Body, 0o644); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(store.root, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err = reopened.ReadCatalog(set.ID)
	if err != nil || !reflect.DeepEqual(got, set) {
		t.Fatal("independent cold read differed after exact bytes were restored", err)
	}
}
