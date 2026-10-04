package linuxclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/control"
)

func TestLinuxComponentReadbacksMeasureOnlyExpectedComponents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'sing-box version 1.11.4\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	view := control.DeviceView{ExpectedComponents: []control.ComponentReadback{

		{ComponentID: "sing-box", Platform: "linux-amd64", Version: "1.11.4"},
	}}
	readbacks, err := linuxComponentReadbacks(view, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(readbacks) != 1 || readbacks[0].ComponentID != "sing-box" ||
		readbacks[0].Version != "1.11.4" || !strings.HasPrefix(readbacks[0].ArtifactDigest, "sha256:") {
		t.Fatalf("readbacks=%+v", readbacks)
	}
}
