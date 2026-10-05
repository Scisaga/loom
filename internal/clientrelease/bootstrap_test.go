package clientrelease

import (
	"bytes"
	"crypto/ed25519"
	"os/exec"
	"reflect"
	"testing"

	"loom/internal/control"
)

func demoBootstrapEntries() []control.ReleaseEntry {
	result := []control.ReleaseEntry{}
	for _, arch := range []string{"amd64", "arm64"} {
		result = append(result, control.ReleaseEntry{ComponentID: "linux-client-bootstrap", Platform: "linux-" + arch, ManifestDigest: control.ReleaseDigest([]byte("demo manifest " + arch)), Artifact: control.ReleaseArtifact{Name: "loom-client-linux-" + arch + ".tar.gz", Digest: control.ReleaseDigest([]byte("demo package " + arch)), Size: 12, MediaType: "application/gzip", Audience: "public"}})
	}
	return result
}

func TestBootstrapBindsOriginalPackagesAndExactScript(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
	entries := demoBootstrapEntries()
	one, pkg, err := BuildBootstrap(9, entries, key)
	if err != nil {
		t.Fatal(err)
	}
	two, again, err := BuildBootstrap(9, entries, key)
	if err != nil || !reflect.DeepEqual(one, two) || !reflect.DeepEqual(pkg, again) {
		t.Fatal("bootstrap generation is not deterministic", err)
	}
	command := exec.Command("sh", "-n")
	command.Stdin = bytes.NewReader(one.Body)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("shell syntax: %v %s", err, output)
	}
	for _, bad := range []Input{{Body: append(bytes.Clone(one.Body), 'x'), Manifest: one.Manifest, Signature: one.Signature}, {Body: one.Body, Manifest: one.Manifest, Signature: bytes.Repeat([]byte{0}, 64)}} {
		if _, err := InspectInput("loom-bootstrap-linux.sh", bad, key.Public().(ed25519.PublicKey)); err == nil {
			t.Fatal("changed signed script accepted")
		}
	}
	set := control.ReleaseSet{Catalog: control.ReleaseCatalog{Schema: 3, Generation: 9, Entries: append([]control.ReleaseEntry{pkg.Entry}, entries...)}, Packages: []control.ReleasePackage{pkg}}
	if err := validateBootstrapBindings(set); err != nil {
		t.Fatal(err)
	}
	set.Catalog.Entries[1].Artifact.Digest = control.ReleaseDigest([]byte("another archive"))
	if err := validateBootstrapBindings(set); err == nil {
		t.Fatal("bootstrap accepted another catalog's package")
	}
	// Identical scripts can have different signed generation metadata. Their
	// removable parse cache must not conflate those two authentic manifests.
	three, next, err := BuildBootstrap(10, entries, key)
	if err != nil || !bytes.Equal(one.Body, three.Body) || pkg.Entry.ManifestDigest == next.Entry.ManifestDigest || packageCacheKey(pkg.Entry) == packageCacheKey(next.Entry) {
		t.Fatal("content-addressed script metadata was conflated", err)
	}
}
