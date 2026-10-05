package publish

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func archiveAuthorityFixture(t *testing.T, dir string) ed25519.PublicKey {
	t.Helper()
	value, key := signedDeploymentCurrent(t)
	body, err := value.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{releaseAuthorityFile: body, releaseAuthorityMarkerFile: []byte(releaseAuthorityMarkerBody)} {
		if err = os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return key
}

func TestHistoricalAuthorityBackupRequiresExactCompleteEvidence(t *testing.T) {
	for _, name := range []string{"complete", "missing-marker", "missing-authority", "corrupt-marker", "corrupt-authority"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			key := archiveAuthorityFixture(t, dir)
			switch name {
			case "missing-marker":
				os.Remove(releaseAuthorityMarkerPath(dir))
			case "missing-authority":
				os.Remove(ReleaseAuthorityPath(dir))
			case "corrupt-marker":
				os.WriteFile(releaseAuthorityMarkerPath(dir), []byte("demo-corrupt"), 0600)
			case "corrupt-authority":
				os.WriteFile(ReleaseAuthorityPath(dir), []byte("{}"), 0600)
			}
			enabled, err := ReleaseAuthorityBackupState(dir)
			if name == "complete" {
				if err != nil || !enabled {
					t.Fatal("original backup evidence rejected", err)
				}
				if _, err = ReadReleaseAuthority(dir, key); err != nil {
					t.Fatal("original signature rejected", err)
				}
			} else if err == nil {
				t.Fatal("partial or corrupt evidence accepted as complete backup")
			}
			if name == "missing-authority" || name == "corrupt-authority" {
				if _, err = ReadReleaseAuthority(dir, key); err == nil {
					t.Fatal("damaged authority accepted")
				}
			}
		})
	}
	dir := t.TempDir()
	before, _ := os.ReadDir(dir)
	if enabled, err := ReleaseAuthorityBackupState(dir); err != nil || enabled {
		t.Fatal("empty evidence fabricated a signed era")
	}
	key, _ := deploymentCurrentKey(t)
	if value, err := ReadReleaseAuthority(dir, key); err != nil || value != nil {
		t.Fatal("empty read generated authority")
	}
	after, _ := os.ReadDir(dir)
	if len(before) != len(after) {
		t.Fatal("read-only evidence check wrote files")
	}
}
