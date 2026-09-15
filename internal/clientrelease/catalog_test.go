package clientrelease

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) (string, Catalog, ed25519.PublicKey) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	input := filepath.Join(t.TempDir(), "demo-client.zip")
	if err := os.WriteFile(input, []byte("demo release body"), 0600); err != nil {
		t.Fatal(err)
	}
	catalog, err := Build(root, []Input{{Path: input, Title: "Demo client", Platform: "windows-desktop", Arch: "amd64", Variant: "installed", Version: "demo-version", SourceCommit: strings.Repeat("a", 40), Signing: "Preview · no Authenticode"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return root, catalog, pub
}
func TestCatalogSignatureAndTamperedArtifactFailClosed(t *testing.T) {
	root, catalog, pub := fixture(t)
	store := Store{Root: root, Key: pub}
	if _, err := store.Load(); err != nil {
		t.Fatal(err)
	}
	artifact := catalog.Artifacts[0]
	file, err := OpenVerified(root, artifact.File)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := os.WriteFile(filepath.Join(root, artifact.Path), []byte("tampered release!"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("changed package remained advertised")
	}
	if _, err := OpenVerified(root, artifact.File); err == nil {
		t.Fatal("tampered package downloaded")
	}
}
func TestCatalogUsesPinnedAuthorityAndRejectsEscapingFiles(t *testing.T) {
	root, catalog, _ := fixture(t)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := Read(root, other); err == nil {
		t.Fatal("untrusted signing authority accepted")
	}
	f := catalog.Artifacts[0].File
	outside := filepath.Join(t.TempDir(), "demo-outside")
	os.WriteFile(outside, []byte("demo release body"), 0600)
	os.Remove(filepath.Join(root, f.Path))
	os.Symlink(outside, filepath.Join(root, f.Path))
	if _, err := OpenVerified(root, f); err == nil {
		t.Fatal("release escaped root through symlink")
	}
	f.Path = "../demo-outside"
	if _, err := OpenVerified(root, f); err == nil {
		t.Fatal("traversal accepted")
	}
}
func TestCatalogOutputIsDeterministic(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	input := filepath.Join(t.TempDir(), "demo.apk")
	os.WriteFile(input, []byte("demo APK"), 0600)
	inputs := []Input{{Path: input, Platform: "android", Arch: "arm64", Variant: "debug", Version: "demo", SourceCommit: strings.Repeat("b", 40), Signing: "Debug APK"}}
	a, b := t.TempDir(), t.TempDir()
	Build(a, inputs, key)
	Build(b, inputs, key)
	left, _ := os.ReadFile(filepath.Join(a, "current.json"))
	right, _ := os.ReadFile(filepath.Join(b, "current.json"))
	if string(left) != string(right) {
		t.Fatal("same inputs changed catalog")
	}
}
