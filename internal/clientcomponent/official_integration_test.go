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
		if verified.Manifest.SingBox.SHA256 != reviewedArtifacts[DataPlaneVersion].windows[arch] {
			t.Fatal("lost exact reviewed artifact")
		}
		again, err := Build(arch, 1, files, wintun, key)
		if err != nil || !bytes.Equal(again.Package, artifact.Package) {
			t.Fatal("source package is not reproducible")
		}
	}
}

// Existing signed schema 3 artifacts must retain their exact source meaning when
// the current writer advances. Source files from another revision cannot be paired
// with either executable, even when every individual file is reviewed.
func TestReviewedArtifactRevisionBindingFromEnvironment(t *testing.T) {
	previous := os.Getenv("LOOM_PREVIOUS_DATAPLANE_DIR")
	current := os.Getenv("LOOM_WINDOWS_DATAPLANE_DIR")
	if previous == "" || current == "" {
		t.Skip("requires both exact reviewed source builds")
	}
	read := func(root, name string) []byte {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	for _, item := range []struct{ root, version, other string }{
		{previous, "1.11.4-loom.1", DataPlaneVersion},
		{current, DataPlaneVersion, "1.11.4-loom.1"},
	} {
		inputs := map[string][]byte{}
		for name := range reviewedArtifacts[item.version].sources {
			inputs[name] = read(item.root, name)
		}
		for _, arch := range []string{"amd64", "arm64"} {
			linux, err := InspectLinuxSourceBuild(read(item.root, "sing-box-linux-"+arch), arch)
			if err != nil || linux.Version != item.version {
				t.Fatalf("Linux artifact identity changed: %v", err)
			}
			windows, err := inspectSingBox(read(item.root, "sing-box-windows-"+arch+".exe"), arch)
			if err != nil || windows.version != item.version {
				t.Fatalf("Windows artifact identity changed: %v", err)
			}
			if _, err := LinuxSourceFiles(inputs, linux.Version); err != nil {
				t.Fatal(err)
			}
			if _, err := LinuxSourceFiles(inputs, item.other); err == nil {
				t.Fatal("accepted sources from a different reviewed artifact")
			}
			if err := validateSingSource(linux.Source, item.other, arch); err == nil {
				t.Fatal("accepted cross-revision signed provenance")
			}
		}
	}
}
