package clientcomponent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBuildPinnedIsReproducibleAndVerifiable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture compilation is covered by cross-builds; native Windows tests use the official PE files")
	}
	singBox := buildWindowsFixture(t)
	identity := fixtureIdentity()
	wintun := append([]byte(nil), singBox...)
	markPEDLL(t, wintun)
	singArchive, err := buildZip(map[string][]byte{
		"sing-box-1.11.4-windows-amd64/LICENSE":      []byte("fixture sing-box license\n"),
		"sing-box-1.11.4-windows-amd64/sing-box.exe": singBox,
	})
	if err != nil {
		t.Fatal(err)
	}
	wintunArchive, err := buildZip(map[string][]byte{
		"wintun/LICENSE.txt":          []byte("fixture Wintun license\n"),
		"wintun/bin/amd64/wintun.dll": wintun,
	})
	if err != nil {
		t.Fatal(err)
	}
	pin := releasePin{
		arch: "amd64", singBoxVersion: identity.version, singBoxCommit: identity.commit,
		singBoxReleaseID: 1, singBoxAssetID: 2,
		singBoxURL:     "https://github.com/SagerNet/sing-box/releases/download/v1.11.4/sing-box-1.11.4-windows-amd64.zip",
		singBoxArchive: sha256Hex(singArchive), wintunVersion: "0.14.1", wintunArchive: sha256Hex(wintunArchive),
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	one, err := buildPinnedWithInspect(pin, singArchive, wintunArchive, privateKey, fixtureSingInspector(t, identity), inspectWintun)
	if err != nil {
		t.Fatal(err)
	}
	two, err := buildPinnedWithInspect(pin, singArchive, wintunArchive, privateKey, fixtureSingInspector(t, identity), inspectWintun)
	if err != nil {
		t.Fatal(err)
	}
	if one.Name != "loom-windows-dataplane-1.11.4-amd64.zip" || !bytes.Equal(one.Package, two.Package) || one.SHA256 != two.SHA256 {
		t.Fatal("same pinned inputs did not produce an identical Windows package")
	}
	verified, err := verifyWithInspect(one.Package, privateKey.Public().(ed25519.PublicKey), fixtureSingInspector(t, identity), inspectWintun)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Manifest.Arch != "amd64" || verified.Manifest.Wintun.Source.AuthenticodePublisher != wintunPublisher ||
		!bytes.Equal(verified.Files[SingBoxPath], singBox) || !bytes.Equal(verified.Files[WintunPath], wintun) {
		t.Fatalf("unexpected verified package: %+v", verified.Manifest)
	}
}

func TestVerifyRejectsTamperWrongKeyAndUnsafeSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture compilation is covered by cross-builds; native Windows tests use the official PE files")
	}
	artifact, key := buildFixtureArtifact(t)
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))
	if _, err := Verify(artifact.Package, wrong.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("package signed by a different platform key was accepted")
	}
	files, err := readZip(artifact.Package)
	if err != nil {
		t.Fatal(err)
	}
	files[WintunPath][len(files[WintunPath])/2] ^= 1
	tampered, err := buildZip(files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(tampered, key.Public().(ed25519.PublicKey)); err == nil || !strings.Contains(err.Error(), "does not match signed manifest") {
		t.Fatalf("tampered package error = %v", err)
	}
	manifest := artifact.Manifest
	manifest.SingBox.Source.URL = "https://example.invalid/sing-box.zip"
	if err := manifest.Validate(); err == nil {
		t.Fatal("non-official sing-box source URL was accepted")
	}
}

func TestOfficialPinsDescribeReviewedAssets(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		pin := officialPins[arch]
		if pin.arch != arch || pin.singBoxVersion != "v1.11.4" ||
			pin.singBoxCommit != "eb07c7a79eeca943370eafea601e87da76c0e57e" ||
			!validLowerHex(pin.singBoxArchive, 64) || pin.wintunArchive != "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51" {
			t.Fatalf("invalid reviewed %s pin: %+v", arch, pin)
		}
	}
}

func buildFixtureArtifact(t *testing.T) (Artifact, ed25519.PrivateKey) {
	t.Helper()
	singBox := buildWindowsFixture(t)
	identity := fixtureIdentity()
	wintun := append([]byte(nil), singBox...)
	markPEDLL(t, wintun)
	singArchive, err := buildZip(map[string][]byte{
		"sing-box-1.11.4-windows-amd64/LICENSE":      []byte("fixture sing-box license\n"),
		"sing-box-1.11.4-windows-amd64/sing-box.exe": singBox,
	})
	if err != nil {
		t.Fatal(err)
	}
	wintunArchive, err := buildZip(map[string][]byte{
		"wintun/LICENSE.txt":          []byte("fixture Wintun license\n"),
		"wintun/bin/amd64/wintun.dll": wintun,
	})
	if err != nil {
		t.Fatal(err)
	}
	pin := releasePin{
		arch: "amd64", singBoxVersion: identity.version, singBoxCommit: identity.commit,
		singBoxReleaseID: 1, singBoxAssetID: 2,
		singBoxURL:     "https://github.com/SagerNet/sing-box/releases/download/v1.11.4/sing-box-1.11.4-windows-amd64.zip",
		singBoxArchive: sha256Hex(singArchive), wintunVersion: "0.14.1", wintunArchive: sha256Hex(wintunArchive),
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x12}, ed25519.SeedSize))
	artifact, err := buildPinnedWithInspect(pin, singArchive, wintunArchive, key, fixtureSingInspector(t, identity), inspectWintun)
	if err != nil {
		t.Fatal(err)
	}
	return artifact, key
}

func buildWindowsFixture(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	outer := filepath.Join(dir, "outer")
	module := filepath.Join(dir, "sing-box")
	writeFixture(t, filepath.Join(outer, "go.mod"), "module fixture\n\ngo 1.27.0\n\nrequire github.com/sagernet/sing-box v1.11.4\nreplace github.com/sagernet/sing-box => ../sing-box\n")
	writeFixture(t, filepath.Join(module, "go.mod"), "module github.com/sagernet/sing-box\n\ngo 1.27.0\n")
	writeFixture(t, filepath.Join(module, "cmd", "sing-box", "main.go"), "package main\nfunc main() {}\n")
	runFixture(t, dir, "git", "init", "-q")
	runFixture(t, dir, "git", "config", "user.email", "fixture@example.invalid")
	runFixture(t, dir, "git", "config", "user.name", "fixture")
	runFixture(t, dir, "git", "add", "outer", "sing-box")
	runFixture(t, dir, "git", "commit", "-qm", "fixture")
	executable := filepath.Join(dir, "sing-box.exe")
	command := exec.Command("go", "build", "-buildvcs=true", "-o", executable, "github.com/sagernet/sing-box/cmd/sing-box")
	command.Dir = outer
	command.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0", "GOOS=windows", "GOARCH=amd64")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Windows fixture: %v\n%s", err, output)
	}
	body, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := inspectPE(body, "amd64", false); err != nil {
		t.Fatal(err)
	}
	return body
}

func fixtureIdentity() singBoxIdentity {
	return singBoxIdentity{version: "v1.11.4", commit: strings.Repeat("a", 40)}
}

func fixtureSingInspector(t *testing.T, identity singBoxIdentity) func([]byte, string) (singBoxIdentity, error) {
	t.Helper()
	return func(body []byte, arch string) (singBoxIdentity, error) {
		if err := inspectPE(body, arch, false); err != nil {
			return singBoxIdentity{}, err
		}
		return identity, nil
	}
}

func markPEDLL(t *testing.T, body []byte) {
	t.Helper()
	if len(body) < 0x40 {
		t.Fatal("fixture PE is too short")
	}
	header := int(binary.LittleEndian.Uint32(body[0x3c:]))
	characteristics := header + 4 + 18
	if characteristics+2 > len(body) {
		t.Fatal("fixture PE header is invalid")
	}
	value := binary.LittleEndian.Uint16(body[characteristics:])
	binary.LittleEndian.PutUint16(body[characteristics:], value|0x2000)
}

func writeFixture(t *testing.T, name, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runFixture(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	command := exec.Command(name, args...)
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, output)
	}
}
