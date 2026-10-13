package clientcomponent

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestReviewedLinuxReadersFromEnvironment(t *testing.T) {
	root := os.Getenv("LOOM_LINUX_DATAPLANE_DIR")
	if root == "" {
		t.Skip("requires an explicit reviewed Linux source build")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		file, err := os.Open(filepath.Join(root, "sing-box-linux-"+arch))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		entry, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		value, err := InspectLinuxSourceBuildReader(file, entry.Size(), arch)
		if err != nil || value.Version != LinuxDataPlaneVersion {
			t.Fatalf("reviewed build rejected: %v", err)
		}
		other := "amd64"
		if arch == other {
			other = "arm64"
		}
		if _, err := InspectLinuxSourceBuildReader(file, entry.Size(), other); err == nil {
			t.Fatal("wrong architecture accepted")
		}
		if _, err := InspectLinuxSourceBuildReader(file, entry.Size()-1, arch); err == nil {
			t.Fatal("truncated artifact accepted")
		}
		readers := map[string]io.Reader{}
		oldReaders := map[string]io.Reader{}
		for name := range reviewedArtifacts[value.Version].sources {
			body, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			destination := "source/" + name
			if name == "LICENSE" {
				destination = SingBoxLicense
			}
			readers[destination] = bytes.NewReader(body)
			oldReaders[destination] = bytes.NewReader(body)
		}
		readers["source/BUILD.txt"] = bytes.NewReader(linuxSourceBuildInstructions(value.Version))
		oldReaders["source/BUILD.txt"] = bytes.NewReader(linuxSourceBuildInstructions(DataPlaneVersion))
		if err := VerifyLinuxSourceFilesReaders(readers, value.Version); err != nil {
			t.Fatal(err)
		}
		if err := VerifyLinuxSourceFilesReaders(oldReaders, DataPlaneVersion); err == nil {
			t.Fatal("new source bytes reinterpreted as previous artifact")
		}
	}
}
