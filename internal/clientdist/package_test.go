package clientdist

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBuildIsReproducibleAndVerifiable(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("fixture builder currently exercises the production linux/amd64 package")
	}
	loom, singBox := buildClientFixtures(t)
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	in := BuildInput{Loom: loom, SingBox: singBox, PrivateKey: privateKey, AllowDirty: true}
	one, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	two, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if one.Name != "loom-client-linux-amd64.tar.gz" || !bytes.Equal(one.Archive, two.Archive) ||
		!bytes.Equal(one.Checksum, two.Checksum) || !bytes.Equal(one.Signature, two.Signature) {
		t.Fatal("same inputs did not produce identical client artifacts")
	}
	manifest, err := Verify(one.Archive, one.Checksum, one.Signature, privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Lifecycle != "signed-node-bundle" || manifest.SingBox.Version != "v1.11.4" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	dir := t.TempDir()
	archivePath := filepath.Join(dir, one.Name)
	writeTestBytes(t, archivePath, one.Archive)
	writeTestBytes(t, archivePath+".sha256", one.Checksum)
	writeTestBytes(t, archivePath+".sig", one.Signature)
	pubPath := filepath.Join(dir, "trusted.pub")
	writeTestBytes(t, pubPath, append([]byte(base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))), '\n'))
	published, err := VerifyFiles(archivePath, pubPath)
	if err != nil || published.SHA256 == "" || published.Size != int64(len(one.Archive)) || !bytes.Equal(published.Archive, one.Archive) {
		t.Fatalf("VerifyFiles err=%v sha=%q size=%d bytes_match=%v", err, published.SHA256, published.Size, bytes.Equal(published.Archive, one.Archive))
	}
}

func TestReadRegularBoundedRejectsLinks(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	writeTestBytes(t, original, []byte("signed bytes"))

	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(original, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularBounded(symlink, 1024); err == nil {
		t.Fatal("符号链接被当成已发布制品读取")
	}

	hardlink := filepath.Join(dir, "hardlink")
	if err := os.Link(original, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularBounded(hardlink, 1024); err == nil {
		t.Fatal("硬链接被当成已发布制品读取")
	}
}

func TestVerifyRejectsTamperAndWrongTrustRoot(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("fixture builder currently exercises the production linux/amd64 package")
	}
	loom, singBox := buildClientFixtures(t)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	artifact, err := Build(BuildInput{Loom: loom, SingBox: singBox, PrivateKey: privateKey, AllowDirty: true})
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), artifact.Archive...)
	tampered[len(tampered)/2] ^= 1
	if _, err := Verify(tampered, artifact.Checksum, artifact.Signature, privateKey.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("tampered archive was accepted")
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	if _, err := Verify(artifact.Archive, artifact.Checksum, artifact.Signature, wrong.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("wrong trust root was accepted")
	}
}

func TestBuildRejectsFakeSingBox(t *testing.T) {
	if _, err := inspectSingBox([]byte("#!/bin/sh\nexit 0\n"), "amd64"); err == nil || !strings.Contains(err.Error(), "Linux ELF") {
		t.Fatalf("fake sing-box error=%v", err)
	}
}

func buildClientFixtures(t *testing.T) ([]byte, []byte) {
	t.Helper()
	dir := t.TempDir()
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	loomPath := filepath.Join(dir, "loom")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", loomPath, "./cmd/loom")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build Loom fixture: %v\n%s", err, output)
	}

	root := filepath.Join(dir, "fixture")
	module := filepath.Join(dir, "sing-box")
	if err := os.MkdirAll(filepath.Join(module, "cmd", "sing-box"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.27.0\n\nrequire github.com/sagernet/sing-box v1.11.4\nreplace github.com/sagernet/sing-box => ../sing-box\n")
	writeTestFile(t, filepath.Join(module, "go.mod"), "module github.com/sagernet/sing-box\n\ngo 1.27.0\n")
	writeTestFile(t, filepath.Join(module, "cmd", "sing-box", "main.go"), "package main\nfunc main() {}\n")
	singBoxPath := filepath.Join(dir, "sing-box.bin")
	cmd = exec.Command("go", "build", "-buildvcs=false", "-o", singBoxPath, "github.com/sagernet/sing-box/cmd/sing-box")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build sing-box fixture: %v\n%s", err, output)
	}
	loom, err := os.ReadFile(loomPath)
	if err != nil {
		t.Fatal(err)
	}
	singBox, err := os.ReadFile(singBoxPath)
	if err != nil {
		t.Fatal(err)
	}
	return loom, singBox
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTestBytes(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
