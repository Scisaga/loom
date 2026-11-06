package clientcomponent

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestHistoricalLinuxBuildInstructionsRetainAuthenticatedBytes(t *testing.T) {
	// This digest belongs to the source payload in the original signed Linux
	// artifact. Selecting another current build must not reinterpret that text.
	body := linuxSourceBuildInstructions("1.11.4-loom.13")
	if len(body) != 860 || fmt.Sprintf("%x", sha256.Sum256(body)) != "1cf7a8e6e3e6286fdf75f3cd394212216b00fddb9f43b1190d0f2e069b8adeb5" {
		t.Fatal("historical Linux build instructions changed")
	}
}

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
		// Historical meaning does not depend on whether current platform
		// targets happen to share one artifact coordinate.
		historical := "1.11.4-loom.15"
		oldReaders["source/BUILD.txt"] = bytes.NewReader(linuxSourceBuildInstructions(historical))
		if err := VerifyLinuxSourceFilesReaders(readers, value.Version); err != nil {
			t.Fatal(err)
		}
		if err := VerifyLinuxSourceFilesReaders(oldReaders, historical); err == nil {
			t.Fatal("new source bytes reinterpreted as previous artifact")
		}
	}
}
