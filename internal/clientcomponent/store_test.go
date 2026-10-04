package clientcomponent

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"loom/internal/control"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
	loaded, err := loadWithPackageVerifier(root, key.Public().(ed25519.PublicKey), "amd64", DataPlaneVersion, authenticode, verifyPackage)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SlotID != result.Slot.ID || loaded.SingBox != result.Paths.SingBox || loaded.Wintun != result.Paths.Wintun {
		t.Fatalf("loaded paths do not match install: %+v", loaded)
	}
	if _, err := loadWithPackageVerifier(root, key.Public().(ed25519.PublicKey), "arm64", DataPlaneVersion, authenticode, verifyPackage); err == nil {
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
	if _, err := loadWithPackageVerifier(root, key.Public().(ed25519.PublicKey), "amd64", DataPlaneVersion, func(string) error { return nil }, verifyPackage); err == nil {
		t.Fatal("tampered immutable slot was loaded")
	}
}

func TestComponentGenerationCannotRegressOrEquivocate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native package integration runs separately")
	}
	artifact, key := buildFixtureArtifact(t)
	verify := func(body []byte, pub ed25519.PublicKey) (*Verified, error) {
		return verifyWithInspect(body, pub, fixtureSingInspector(t, fixtureIdentity()), inspectWintun)
	}
	install := func(root string, body []byte) error {
		_, err := installWithPackageVerifier(root, body, key.Public().(ed25519.PublicKey), func(string) error { return nil }, verify)
		return err
	}
	change := func(generation control.U64, equivocate bool) []byte {
		t.Helper()
		files, err := readZip(artifact.Package)
		if err != nil {
			t.Fatal(err)
		}
		manifest := artifact.Manifest
		manifest.Generation = generation
		if equivocate {
			files[SingBoxLicense] = []byte("demo other license")
			manifest.Files = append([]File(nil), manifest.Files...)
			for i := range manifest.Files {
				if manifest.Files[i].Path == SingBoxLicense {
					manifest.Files[i].Size = len(files[SingBoxLicense])
					manifest.Files[i].SHA256 = sha256Hex(files[SingBoxLicense])
				}
			}
		}
		body, err := marshalManifest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		files["manifest.json"] = body
		files["manifest.sig"] = ed25519.Sign(key, signatureMessage(body))
		result, err := buildZip(files)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	root := t.TempDir()
	if err := install(root, artifact.Package); err != nil {
		t.Fatal(err)
	}
	initial, err := os.ReadFile(statePath(root))
	if err != nil {
		t.Fatal(err)
	}
	if err := install(root, change(1, true)); err == nil {
		t.Fatal("same-generation equivocation accepted")
	}
	after, _ := os.ReadFile(statePath(root))
	if !bytes.Equal(initial, after) {
		t.Fatal("rejected write changed accepted state")
	}
	second, third := change(2, false), change(3, false)
	var group sync.WaitGroup
	group.Add(2)
	go func() { defer group.Done(); _ = install(root, second) }()
	go func() {
		defer group.Done()
		if err := install(root, third); err != nil {
			t.Error(err)
		}
	}()
	group.Wait()
	state, err := ReadState(root)
	if err != nil || state.Current.Generation != 3 {
		t.Fatalf("concurrent upgrade lost highest accepted generation: %v %v", state, err)
	}
	if err := install(root, artifact.Package); err == nil {
		t.Fatal("old signed generation accepted")
	}
	if err := install(root, third); err != nil {
		t.Fatal("same generation retry failed", err)
	}
	// A previous artifact version is data in the existing schema 3 acceptance
	// floor. Upgrading must retain that floor even if its old slot is absent.
	state.Current.Generation = 2
	state.Current.ID = strings.Repeat("b", 64)
	state.Current.SingBoxVersion = "1.11.3-loom.demo"
	body, err := control.CanonicalEncode(*state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath(root), body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := install(root, artifact.Package); err == nil {
		t.Fatal("old artifact coordinate lost its generation floor")
	}
	if err := install(root, third); err != nil {
		t.Fatal("forward component version upgrade failed", err)
	}
	old := []byte(`{"schema":1,"current":{}}`)
	if err := os.WriteFile(statePath(root), old, 0600); err != nil {
		t.Fatal(err)
	}
	if err := install(root, third); err == nil {
		t.Fatal("old state was silently migrated")
	}
	after, _ = os.ReadFile(statePath(root))
	if !bytes.Equal(old, after) {
		t.Fatal("old state bytes changed")
	}
}
