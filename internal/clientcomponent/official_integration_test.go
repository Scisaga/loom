package clientcomponent

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"testing"
)

func TestOfficialPinnedArchivesFromEnvironment(t *testing.T) {
	singAMD64 := os.Getenv("LOOM_SING_BOX_AMD64_ARCHIVE")
	singARM64 := os.Getenv("LOOM_SING_BOX_ARM64_ARCHIVE")
	wintun := os.Getenv("LOOM_WINTUN_ARCHIVE")
	if singAMD64 == "" || singARM64 == "" || wintun == "" {
		t.Skip("set official archive paths to run the upstream integration probe")
	}
	wintunBody, err := os.ReadFile(wintun)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x73}, ed25519.SeedSize))
	for _, test := range []struct {
		arch string
		path string
	}{
		{arch: "amd64", path: singAMD64},
		{arch: "arm64", path: singARM64},
	} {
		singBody, err := os.ReadFile(test.path)
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := BuildOfficial(test.arch, singBody, wintunBody, key)
		if err != nil {
			t.Fatalf("build official %s package: %v", test.arch, err)
		}
		verified, err := Verify(artifact.Package, key.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatalf("verify official %s package: %v", test.arch, err)
		}
		if verified.Manifest.SingBox.Commit != officialPins[test.arch].singBoxCommit ||
			verified.Manifest.Wintun.Source.ArchiveSHA256 != officialPins[test.arch].wintunArchive {
			t.Fatalf("official %s package lost pinned provenance", test.arch)
		}
	}
}
