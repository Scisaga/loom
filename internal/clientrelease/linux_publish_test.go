package clientrelease

import "testing"

func TestMergeLinuxArtifactsPreservesOtherPlatformsAndReplacesBothArchitectures(t *testing.T) {
	current := Catalog{Schema: 1, Artifacts: []Artifact{
		{File: File{Name: "android.apk"}, Platform: "android", Arch: "universal"},
		{File: File{Name: "old-amd64.tar.gz"}, Platform: "linux-server", Arch: "amd64"},
		{File: File{Name: "windows.zip"}, Platform: "windows-desktop", Arch: "amd64"},
		{File: File{Name: "old-arm64.tar.gz"}, Platform: "linux-server", Arch: "arm64"},
	}}
	replacements := []Artifact{
		{File: File{Name: "new-amd64.tar.gz"}, Platform: "linux-server", Arch: "amd64"},
		{File: File{Name: "new-arm64.tar.gz"}, Platform: "linux-server", Arch: "arm64"},
	}
	merged := mergeLinuxArtifacts(current, replacements)
	if len(merged.Artifacts) != 4 || merged.Artifacts[0].Name != "android.apk" || merged.Artifacts[1].Name != "windows.zip" ||
		merged.Artifacts[2].Name != "new-amd64.tar.gz" || merged.Artifacts[3].Name != "new-arm64.tar.gz" {
		t.Fatalf("merged artifacts = %+v", merged.Artifacts)
	}
}
