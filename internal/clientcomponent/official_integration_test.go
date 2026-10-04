package clientcomponent

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func sourceBuildFiles(t *testing.T, arch string) map[string][]byte {
	t.Helper()
	root := os.Getenv("LOOM_WINDOWS_DATAPLANE_DIR")
	if root == "" {
		t.Skip("requires reviewed source build directory")
	}
	files := map[string][]byte{}
	for _, name := range []string{"sing-box-windows-" + arch + ".exe", "LICENSE", "source-provenance.json", "domain-cache.patch", "prepare-sing-box.py", "build-dataplane.sh"} {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = body
	}
	return files
}
func pinnedWintun(t *testing.T) []byte {
	t.Helper()
	name := os.Getenv("LOOM_WINTUN_ARCHIVE")
	if name == "" {
		t.Skip("requires pinned Wintun archive")
	}
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func TestReviewedSourceBuildFromEnvironment(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x73}, ed25519.SeedSize))
	for _, arch := range []string{"amd64", "arm64"} {
		files := sourceBuildFiles(t, arch)
		wintun := pinnedWintun(t)
		artifact, err := Build(arch, 1, files, wintun, key)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := Verify(artifact.Package, key.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		if verified.Manifest.SingBox.SHA256 != reviewedBuilds[arch] {
			t.Fatal("lost exact reviewed artifact")
		}
		again, err := Build(arch, 1, files, wintun, key)
		if err != nil || !bytes.Equal(again.Package, artifact.Package) {
			t.Fatal("source package is not reproducible")
		}
	}
}
