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
	if manifest.Lifecycle != "certified-lkg-runtime" || manifest.SingBox.Version != "v1.11.4" {
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

func TestInstallerAndServiceUseOnlyUnifiedRuntime(t *testing.T) {
	command := exec.Command("sh", "-n")
	command.Stdin = strings.NewReader(installScript)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("installer syntax: %v\n%s", err, output)
	}
	for _, forbidden := range []string{" client serve-v2", " loom agent ", " loom pull ", " loom report ", "--server-migration-source", "stage-server-migration", "finalize-server-migration"} {
		if strings.Contains(installScript, forbidden) || strings.Contains(systemdService, forbidden) {
			t.Fatalf("legacy runtime entry remains: %q", forbidden)
		}
	}
	if strings.Contains(systemdService, "Restart=always") || !strings.Contains(systemdService, "Restart=no") {
		t.Fatal("Linux client service may retry a failed host network activation")
	}
	for _, required := range []string{"client run -capture tun", "client preflight", "--upgrade",
		"protected prior deployment requires a verified forward cutover before activation",
		"WorkingDirectory=/var/lib/loom-device", "ReadWritePaths=/var/lib/loom-device /run/loom-client",
		"services remain disabled; certified configuration and floor retained"} {
		if !strings.Contains(installScript+systemdService, required) {
			t.Fatalf("installer is missing %q", required)
		}
	}
	if strings.Contains(systemdService, "ReadWritePaths=/etc ") || strings.Contains(systemdService, "ReadWritePaths=/etc\n") {
		t.Fatal("runtime service may not make all of /etc writable")
	}
	if strings.Index(installScript, "client preflight") > strings.Index(installScript, "systemctl enable loom-client.service") {
		t.Fatal("installer enables the runtime before the network namespace preflight")
	}
	if strings.Contains(installScript, "systemctl stop loom-client-v2.service") || strings.Contains(installScript, "mv /var/lib/loom/client-v2") {
		t.Fatal("installer must not replace a verified forward cutover with automatic legacy cleanup")
	}
}

// Execute the generated installer's failure branch with every host path replaced
// and systemctl intercepted. A failed activation may restore package files, but
// must never restart an older executable with revoked authorization.
func TestInstallerFailurePreservesAuthorityAndLeavesExecutionDisabled(t *testing.T) {
	start := strings.Index(installScript, "if [ \"$ready\" -ne 1 ]; then")
	if start < 0 {
		t.Fatal("installer failure branch is missing")
	}
	end := strings.Index(installScript[start:], "\n[ -z \"$unit_backup\" ]")
	if end < 0 {
		t.Fatal("installer failure branch is missing")
	}
	root := t.TempDir()
	packageDir := filepath.Join(root, "packages")
	if err := os.MkdirAll(packageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(packageDir, "current")
	if err := os.Symlink("demo-new-release", current); err != nil {
		t.Fatal(err)
	}
	unit, backup := filepath.Join(root, "service"), filepath.Join(root, "service.backup")
	writeTestBytes(t, unit, []byte("demo-new-unit"))
	writeTestBytes(t, backup, []byte("demo-previous-unit"))
	state := filepath.Join(root, "device-state")
	authority := []byte("demo-identity; accepted-revocation; floor=8")
	writeTestBytes(t, state, authority)
	log := filepath.Join(root, "systemctl.log")
	script := "set -eu\n" + `
systemctl() { printf '%s\n' "$*" >> "$DEMO_SYSTEMCTL_LOG"; }
ready=0
previous=demo-previous-release
unit=$DEMO_UNIT
unit_backup=$DEMO_BACKUP
state=$DEMO_STATE
` + strings.ReplaceAll(installScript[start:start+end], "/usr/local/lib/loom-client", packageDir)
	command := exec.Command("sh")
	command.Stdin = strings.NewReader(script)
	command.Env = append(os.Environ(), "DEMO_UNIT="+unit, "DEMO_BACKUP="+backup,
		"DEMO_STATE="+state, "DEMO_SYSTEMCTL_LOG="+log)
	output, err := command.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 ||
		!bytes.Contains(output, []byte("services remain disabled")) {
		t.Fatalf("failure branch exit=%v output=%s", err, output)
	}
	readback, err := os.ReadFile(state)
	if err != nil || !bytes.Equal(readback, authority) {
		t.Fatal("package failure changed accepted device authority")
	}
	readback, err = os.ReadFile(unit)
	if err != nil || string(readback) != "demo-previous-unit" {
		t.Fatal("previous package files were not restored")
	}
	target, err := os.Readlink(current)
	if err != nil || target != "demo-previous-release" {
		t.Fatal("previous package link was not restored")
	}
	readback, err = os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(readback)), "\n") {
		if line != "daemon-reload" && !strings.HasPrefix(line, "disable --now ") {
			t.Fatalf("failed activation attempted an execution change: %s", line)
		}
	}
	if !bytes.Contains(readback, []byte("disable --now loom-client.service")) {
		t.Fatal("failed activation left a runtime eligible for automatic restart")
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
