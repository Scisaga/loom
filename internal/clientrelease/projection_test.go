package clientrelease

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"loom/internal/androidrelease"
	"loom/internal/control"
)

func writeProjectionFile(t *testing.T, root, relative string, body []byte) {
	t.Helper()
	name := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSignedProjectionAuthenticatesCoordinatesWithoutArtifactsOrPackageLock(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{13}, ed25519.SeedSize))
	m := androidrelease.Manifest{Schema: 3, Kind: androidrelease.Kind, Generation: 1, ApplicationID: androidrelease.PackageID, VersionCode: 1, VersionName: "demo-version", SourceCommit: strings.Repeat("a", 40), AARSHA256: strings.Repeat("b", 64), SingBoxVersion: "demo-native", Artifact: control.ReleaseArtifact{Name: androidrelease.Name, Digest: control.ReleaseDigest([]byte("demo-missing-artifact")), Size: 100, MediaType: androidrelease.MediaType, Audience: "public"}, NativeLibraries: []androidrelease.NativeLibrary{{Arch: "amd64", Path: "lib/x86_64/libbox.so", SHA256: strings.Repeat("e", 64), Size: 10}, {Arch: "arm64", Path: "lib/arm64-v8a/libbox.so", SHA256: strings.Repeat("f", 64), Size: 11}}}
	body, err := control.CanonicalEncode(m)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(key, append([]byte("loom-release-manifest-v3\x00"), body...))
	entry := control.ReleaseEntry{ComponentID: m.Kind, Platform: "android-any", ManifestDigest: control.ReleaseDigest(body), Artifact: m.Artifact}
	store, err := New(t.TempDir(), key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	writeCatalog := func(entry control.ReleaseEntry) string {
		t.Helper()
		catalog, signed, err := control.SignReleaseCatalog(control.ReleaseCatalog{Schema: 3, Generation: 1, Entries: []control.ReleaseEntry{entry}}, key)
		if err != nil {
			t.Fatal(err)
		}
		id := control.ReleaseDigest(catalog)
		writeProjectionFile(t, store.root, digestPath("catalogs", id, "catalog.json"), catalog)
		writeProjectionFile(t, store.root, digestPath("catalogs", id, "catalog.sig"), signed)
		current, err := control.CanonicalEncode(control.ReleaseCurrent{Schema: 3, CatalogDigest: id})
		if err != nil {
			t.Fatal(err)
		}
		writeProjectionFile(t, store.root, "current.json", current)
		return id
	}
	id := writeCatalog(entry)
	manifestPath := digestPath("manifests", entry.ManifestDigest, "manifest.json")
	sigPath := digestPath("manifests", entry.ManifestDigest, "manifest.sig")
	writeProjectionFile(t, store.root, manifestPath, body)
	writeProjectionFile(t, store.root, sigPath, signature)
	source := store.ProjectionSource()
	got, err := source.Read()
	if err != nil || len(got.Packages) != 1 || !reflect.DeepEqual(got.Packages[0].Components, m.Components()) {
		t.Fatal("signed runtime coordinates unavailable", err)
	}
	// The same formal ReleaseSource must not claim the missing bytes are downloadable.
	if _, err := source.Open(id, entry.Artifact); err == nil {
		t.Fatal("missing artifact was downloadable")
	}
	if _, err := store.Read(); err == nil {
		t.Fatal("publication inspection accepted missing artifact")
	}
	store.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := source.Read(); done <- err }()
	select {
	case err := <-done:
		store.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		store.mu.Unlock()
		<-done
		t.Fatal("metadata query waited for the artifact lock")
	}
	for _, file := range []string{manifestPath, sigPath, digestPath("catalogs", id, "catalog.json"), digestPath("catalogs", id, "catalog.sig"), "current.json"} {
		original, err := os.ReadFile(filepath.Join(store.root, file))
		if err != nil {
			t.Fatal(err)
		}
		changed := bytes.Clone(original)
		changed[len(changed)/2] ^= 1
		writeProjectionFile(t, store.root, file, changed)
		if _, err := source.Read(); err == nil {
			t.Fatal("changed original metadata accepted", file)
		}
		writeProjectionFile(t, store.root, file, original)
	}
	if err := os.Remove(filepath.Join(store.root, manifestPath)); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Read(); err == nil {
		t.Fatal("missing manifest accepted from memory")
	}
	writeProjectionFile(t, store.root, manifestPath, body)
	wrong, _ := New(store.root, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{14}, 32)).Public().(ed25519.PublicKey))
	if _, err := wrong.ProjectionSource().Read(); err == nil {
		t.Fatal("independent wrong trust accepted")
	}
	crossed := entry
	crossed.Artifact.Digest = control.ReleaseDigest([]byte("demo-another-artifact"))
	writeCatalog(crossed)
	if _, err := source.Read(); err == nil {
		t.Fatal("valid catalog crossed original manifest binding")
	}
	for _, bad := range [][]byte{append([]byte(" "), body...), append([]byte(`{"unknown":true,`), body[1:]...)} {
		changed := entry
		changed.ManifestDigest = control.ReleaseDigest(bad)
		writeCatalog(changed)
		writeProjectionFile(t, store.root, digestPath("manifests", changed.ManifestDigest, "manifest.json"), bad)
		writeProjectionFile(t, store.root, digestPath("manifests", changed.ManifestDigest, "manifest.sig"), ed25519.Sign(key, append([]byte("loom-release-manifest-v3\x00"), bad...)))
		if _, err := source.Read(); err == nil {
			t.Fatal("correctly signed noncanonical or unknown manifest accepted")
		}
	}
	writeCatalog(entry)
	reopened, _ := New(store.root, key.Public().(ed25519.PublicKey))
	again, err := reopened.ProjectionSource().Read()
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatal("restart changed signed projection", err)
	}
}

func TestReviewedSignedProjectionMatchesFullInspectionAndRejectsBrokenDownloads(t *testing.T) {
	if *reviewedStore == "" || *reviewedPublic == "" {
		t.Skip("requires explicit signed original catalog and independent public key")
	}
	key, err := control.ReadReleasePublicKey(*reviewedPublic)
	if err != nil {
		t.Fatal(err)
	}
	source, err := New(*reviewedStore, key)
	if err != nil {
		t.Fatal(err)
	}
	full, err := source.Read()
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := source.ProjectionSource().Read()
	if err != nil || !reflect.DeepEqual(full, metadata) {
		t.Fatal("metadata and complete package inspection disagree", err)
	}
	for _, pkg := range metadata.Packages {
		if !reflect.DeepEqual(pkg, source.packages[packageCacheKey(pkg.Entry)]) {
			t.Fatal("signed metadata differs from independently inspected package coordinates", pkg.Entry.ComponentID)
		}
	}
	// Copy only metadata, not a second full distribution. All mutations stay here.
	target, _ := New(t.TempDir(), key)
	for _, relative := range []string{"current.json", digestPath("catalogs", full.ID, "catalog.json"), digestPath("catalogs", full.ID, "catalog.sig")} {
		body, err := os.ReadFile(filepath.Join(source.root, relative))
		if err != nil {
			t.Fatal(err)
		}
		writeProjectionFile(t, target.root, relative, body)
	}
	for _, pkg := range full.Packages {
		writeProjectionFile(t, target.root, digestPath("manifests", pkg.Entry.ManifestDigest, "manifest.json"), pkg.ManifestBody)
		writeProjectionFile(t, target.root, digestPath("manifests", pkg.Entry.ManifestDigest, "manifest.sig"), pkg.Signature)
	}
	for _, pkg := range full.Packages {
		entry := pkg.Entry
		// Populate only a previously fully inspected parse, exactly as the warm store.
		target.packages[packageCacheKey(entry)] = clonePackage(pkg)
		body, err := os.ReadFile(filepath.Join(source.root, digestPath("bin", entry.Artifact.Digest, "")))
		if err != nil {
			t.Fatal(err)
		}
		body[len(body)/2] ^= 1
		writeProjectionFile(t, target.root, digestPath("bin", entry.Artifact.Digest, ""), body)
	}
	projection := target.ProjectionSource()
	got, err := projection.Read()
	if err != nil || !reflect.DeepEqual(full, got) {
		t.Fatal("artifact damage changed authenticated coordinates", err)
	}
	if _, err := target.Read(); err == nil {
		t.Fatal("full consumer accepted damaged bytes")
	}
	if _, err := projection.Open(full.ID, full.Packages[0].Entry.Artifact); err == nil {
		t.Fatal("projection download bypassed actual byte validation")
	}
	for _, pkg := range full.Packages {
		// Validate each catalog kind's manifest digest/signature independently.
		changed := bytes.Clone(pkg.Signature)
		changed[0] ^= 1
		path := digestPath("manifests", pkg.Entry.ManifestDigest, "manifest.sig")
		writeProjectionFile(t, target.root, path, changed)
		if _, err := projection.Read(); err == nil {
			t.Fatal("changed platform manifest accepted", pkg.Entry.ComponentID)
		}
		writeProjectionFile(t, target.root, path, pkg.Signature)
	}
}
