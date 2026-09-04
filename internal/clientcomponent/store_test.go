package clientcomponent

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallAndLoadImmutableComponentSlot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture compilation is covered by cross-builds; native Windows tests use official files")
	}
	artifact, key := buildFixtureArtifact(t)
	identity := fixtureIdentity()
	verifyPackage := func(body []byte, public ed25519.PublicKey) (*Verified, error) {
		return verifyWithInspect(body, public, fixtureSingInspector(t, identity), inspectWintun)
	}
	var authenticodeChecks int
	authenticode := func(path string) error {
		authenticodeChecks++
		if filepath.Base(path) != "wintun.dll" {
			return errors.New("wrong Authenticode target")
		}
		return nil
	}
	root := filepath.Join(t.TempDir(), "Loom")
	result, err := installWithPackageVerifier(root, artifact.Package, key.Public().(ed25519.PublicKey), authenticode, verifyPackage)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !validLowerHex(result.Slot.ID, 64) || authenticodeChecks < 2 {
		t.Fatalf("unexpected first install result: %+v checks=%d", result, authenticodeChecks)
	}
	again, err := installWithPackageVerifier(root, artifact.Package, key.Public().(ed25519.PublicKey), authenticode, verifyPackage)
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed || again.Slot != result.Slot {
		t.Fatalf("idempotent install changed slot: %+v", again)
	}
	loaded, err := loadWithPackageVerifier(root, key.Public().(ed25519.PublicKey), "amd64", "1.11.4", authenticode, verifyPackage)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SlotID != result.Slot.ID || loaded.SingBox != result.Paths.SingBox || loaded.Wintun != result.Paths.Wintun {
		t.Fatalf("loaded paths do not match install: %+v", loaded)
	}
	if _, err := loadWithPackageVerifier(root, key.Public().(ed25519.PublicKey), "arm64", "1.11.4", authenticode, verifyPackage); err == nil {
		t.Fatal("wrong architecture selected a component slot")
	}
	if _, err := loadWithPackageVerifier(root, key.Public().(ed25519.PublicKey), "amd64", "1.11.5", authenticode, verifyPackage); err == nil {
		t.Fatal("wrong snapshot version selected a component slot")
	}
}

func TestInstallFailsBeforePointerOnAuthenticodeFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture compilation is covered by cross-builds; native Windows tests use official files")
	}
	artifact, key := buildFixtureArtifact(t)
	identity := fixtureIdentity()
	verifyPackage := func(body []byte, public ed25519.PublicKey) (*Verified, error) {
		return verifyWithInspect(body, public, fixtureSingInspector(t, identity), inspectWintun)
	}
	root := filepath.Join(t.TempDir(), "Loom")
	_, err := installWithPackageVerifier(root, artifact.Package, key.Public().(ed25519.PublicKey),
		func(string) error { return errors.New("untrusted publisher") }, verifyPackage)
	if err == nil || !strings.Contains(err.Error(), "Authenticode") {
		t.Fatalf("Authenticode failure = %v", err)
	}
	if state, readErr := ReadState(root); readErr != nil || state != nil {
		t.Fatalf("failed install committed state: state=%+v err=%v", state, readErr)
	}
	entries, readErr := os.ReadDir(filepath.Join(root, "components"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("failed install leaked staging entries: %v", entries)
	}
}

func TestLoadRejectsTamperedInstalledSlot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture compilation is covered by cross-builds; native Windows tests use official files")
	}
	artifact, key := buildFixtureArtifact(t)
	identity := fixtureIdentity()
	verifyPackage := func(body []byte, public ed25519.PublicKey) (*Verified, error) {
		return verifyWithInspect(body, public, fixtureSingInspector(t, identity), inspectWintun)
	}
	root := filepath.Join(t.TempDir(), "Loom")
	result, err := installWithPackageVerifier(root, artifact.Package, key.Public().(ed25519.PublicKey), func(string) error { return nil }, verifyPackage)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(result.Paths.SingBox, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWithPackageVerifier(root, key.Public().(ed25519.PublicKey), "amd64", "1.11.4", func(string) error { return nil }, verifyPackage); err == nil {
		t.Fatal("tampered immutable slot was loaded")
	}
}
