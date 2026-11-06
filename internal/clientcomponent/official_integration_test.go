package clientcomponent

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestHistoricalReviewedArtifactRetainsOriginalCoordinates(t *testing.T) {
	want := reviewedArtifact{
		sources: map[string]string{
			"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
			"build-dataplane.sh":     "31fb2fc1ca3e89222273f820ff69e74775e4aa9b9edad4a1f4fdbed368c81872",
			"domain-cache.patch":     "c877a591af3ab5a10c68921bc4edccb181efff213c22b29cec2f9a0f53e9f736",
			"prepare-sing-box.py":    "55f1b60df1f5748c6962c50846e7a74b9896a53f95fc45761fb32431e533c96c",
			"source-provenance.json": "ca71fa9136f5189de74d13151aa4d5a787a37c46b38f1561479c4c573f969301",
		},
		linux: map[string]string{
			"amd64": "7ce314f2e61e6d2ac7d65143c069730010dbdf18d64e92cf64c40b15270a0606",
			"arm64": "d95a635b8ff1bb4e0391306bebf4b9c80d1f85f4af55ae4b962c4a49fe7d46f4",
		},
		windows: map[string]string{
			"amd64": "d5c9846cadda28aea902a53d4dc3634ed92d9d8ab978d1af6d9bcefc6f7df562",
			"arm64": "e7a4c592db91fff114151b2d17908fd7206238d8a697e1820cafca114311b905",
		},
	}
	if !reflect.DeepEqual(reviewedArtifacts["1.11.4-loom.26"], want) {
		t.Fatal("historical source or executable coordinates changed")
	}
}

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
	previousVersion, err := ReviewedSourceVersion(read(previous, "source-provenance.json"))
	if err != nil || previousVersion == DataPlaneVersion {
		t.Fatal("requires a distinct reviewed historical source build", err)
	}
	for _, item := range []struct{ root, version, other string }{
		{previous, previousVersion, DataPlaneVersion},
		{current, DataPlaneVersion, previousVersion},
	} {
		inputs := map[string][]byte{}
		for name := range reviewedArtifacts[item.version].sources {
			inputs[name] = read(item.root, name)
		}
		for name, original := range inputs {
			t.Run(item.version+"/changed-"+name, func(t *testing.T) {
				inputs[name] = append(bytes.Clone(original), '\n')
				if _, err := LinuxSourceFiles(inputs, item.version); err == nil {
					t.Fatal("accepted changed source bytes for reviewed artifact")
				}
				inputs[name] = original
			})
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
