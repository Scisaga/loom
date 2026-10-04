package clientdist

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"loom/internal/clientcomponent"
	"loom/internal/control"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
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
	in := BuildInput{Generation: 1, Loom: loom, SingBox: singBox, PrivateKey: privateKey, AllowDirty: true}
	one, err := buildWithInspect(in, fixtureSingBox, fixtureSources)
	if err != nil {
		t.Fatal(err)
	}
	two, err := buildWithInspect(in, fixtureSingBox, fixtureSources)
	if err != nil {
		t.Fatal(err)
	}
	if one.Name != "loom-client-linux-amd64.tar.gz" || !bytes.Equal(one.Archive, two.Archive) ||
		!bytes.Equal(one.Checksum, two.Checksum) || !bytes.Equal(one.Signature, two.Signature) {
		t.Fatal("same inputs did not produce identical client artifacts")
	}
	manifest, err := verifyWithInspect(one.Archive, one.Checksum, one.Signature, privateKey.Public().(ed25519.PublicKey), fixtureSingBox, fixtureSources)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Lifecycle != "certified-lkg-runtime" || manifest.SingBox.Version != "demo-reviewed" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	dir := t.TempDir()
	archivePath := filepath.Join(dir, one.Name)
	writeTestBytes(t, archivePath, one.Archive)
	writeTestBytes(t, archivePath+".sha256", one.Checksum)
	writeTestBytes(t, archivePath+".sig", one.Signature)
	pubPath := filepath.Join(dir, "trusted.pub")
	writeTestBytes(t, pubPath, append([]byte(base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))), '\n'))
	if _, err := VerifyFiles(archivePath, pubPath); err == nil {
		t.Fatal("public verifier accepted a fixture instead of reviewed source build")
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
	artifact, err := buildWithInspect(BuildInput{Generation: 1, Loom: loom, SingBox: singBox, PrivateKey: privateKey, AllowDirty: true}, fixtureSingBox, fixtureSources)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), artifact.Archive...)
	tampered[len(tampered)/2] ^= 1
	if _, err := verifyWithInspect(tampered, artifact.Checksum, artifact.Signature, privateKey.Public().(ed25519.PublicKey), fixtureSingBox, fixtureSources); err == nil {
		t.Fatal("tampered archive was accepted")
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	if _, err := verifyWithInspect(artifact.Archive, artifact.Checksum, artifact.Signature, wrong.Public().(ed25519.PublicKey), fixtureSingBox, fixtureSources); err == nil {
		t.Fatal("wrong trust root was accepted")
	}
}

func TestBuildRejectsFakeSingBox(t *testing.T) {
	if _, err := inspectSingBox([]byte("#!/bin/sh\nexit 0\n"), "amd64"); err == nil {
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

func fixtureSingBox(body []byte, arch string) (Component, error) {
	return Component{Path: "sing-box", SHA256: sha256Hex(body), Size: len(body), Version: "demo-reviewed", Commit: strings.Repeat("a", 40), Source: &clientcomponent.Source{URL: "https://example.com/source.zip", ArchiveSHA256: strings.Repeat("b", 64), Evidence: "demo-fixture"}}, nil
}
func fixtureSources(_ map[string][]byte) (map[string][]byte, error) {
	result := map[string][]byte{}
	for _, name := range payloadNames() {
		if strings.HasPrefix(name, "source/") || strings.HasPrefix(name, "licenses/") {
			result[name] = []byte("demo source file: " + name)
		}
	}
	return result, nil
}

var reviewedDataPlaneDir = flag.String("linux-dataplane-dir", "", "explicit reviewed source build directory for real two-architecture package checks")

func TestReviewedLinuxPackages(t *testing.T) {
	if *reviewedDataPlaneDir == "" {
		t.Skip("requires explicit reviewed data-plane build inputs")
	}
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string][]byte{}
	for _, name := range []string{"LICENSE", "source-provenance.json", "domain-cache.patch", "prepare-sing-box.py", "build-dataplane.sh"} {
		sources[name], err = os.ReadFile(filepath.Join(*reviewedDataPlaneDir, name))
		if err != nil {
			t.Fatal(err)
		}
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x3a}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			dir := t.TempDir()
			exe := filepath.Join(dir, "loom")
			cmd := exec.Command("go", "build", "-trimpath", "-o", exe, "./cmd/loom")
			cmd.Dir = repo
			cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("build real Loom: %v %s", err, output)
			}
			loom, err := os.ReadFile(exe)
			if err != nil {
				t.Fatal(err)
			}
			sing, err := os.ReadFile(filepath.Join(*reviewedDataPlaneDir, "sing-box-linux-"+arch))
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := Build(BuildInput{Generation: 4, Loom: loom, SingBox: sing, SourceFiles: sources, PrivateKey: private, AllowDirty: true})
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := Verify(artifact.Archive, artifact.Checksum, artifact.Signature, public)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(manifest, artifact.Manifest) {
				t.Fatal("verified manifest changed")
			}
			encoded, err := control.CanonicalEncode(manifest)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Manifest
			if err := control.DecodeCanonical(encoded, &decoded, control.ContractDecodeLimits{MaxBytes: 64 << 10, MaxDepth: 12, MaxItems: 2048}); err != nil || !reflect.DeepEqual(manifest, decoded) {
				t.Fatal("canonical manifest round trip failed", err)
			}
			archive := filepath.Join(dir, artifact.Name)
			writeTestBytes(t, archive, artifact.Archive)
			writeTestBytes(t, archive+".sha256", artifact.Checksum)
			writeTestBytes(t, archive+".sig", artifact.Signature)
			pub := filepath.Join(dir, "trusted.pub")
			writeTestBytes(t, pub, []byte(base64.StdEncoding.EncodeToString(public)+"\n"))
			if got, err := VerifyFiles(archive, pub); err != nil || !bytes.Equal(got.Archive, artifact.Archive) {
				t.Fatal("real file verification failed", err)
			}
			changed := append([]byte(nil), sing...)
			changed[len(changed)/2] ^= 1
			if _, err := Build(BuildInput{Generation: 4, Loom: loom, SingBox: changed, SourceFiles: sources, PrivateKey: private, AllowDirty: true}); err == nil {
				t.Fatal("changed data plane accepted")
			}
			t.Logf("verified linux/%s canonical package: %s", arch, sha256Hex(artifact.Archive))
		})
	}
}

func TestLinuxManifestRejectsAmbiguousAndLegacyBytes(t *testing.T) {
	loom, sing := buildClientFixtures(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	artifact, err := buildWithInspect(BuildInput{Generation: 7, Loom: loom, SingBox: sing, PrivateKey: private, AllowDirty: true}, fixtureSingBox, fixtureSources)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := control.CanonicalEncode(artifact.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string][]byte{
		"old schema":              bytes.Replace(manifest, []byte(`"schema":3`), []byte(`"schema":2`), 1),
		"missing generation":      bytes.Replace(manifest, []byte(`"generation":"7",`), nil, 1),
		"zero generation":         bytes.Replace(manifest, []byte(`"generation":"7"`), []byte(`"generation":"0"`), 1),
		"noncanonical generation": bytes.Replace(manifest, []byte(`"generation":"7"`), []byte(`"generation":"07"`), 1),
		"numeric generation":      bytes.Replace(manifest, []byte(`"generation":"7"`), []byte(`"generation":7`), 1),
		"duplicate generation":    bytes.Replace(manifest, []byte(`"generation":"7"`), []byte(`"generation":"7","generation":"7"`), 1),
		"unknown field":           append([]byte(`{"extra":false,`), manifest[1:]...),
		"wrong audience":          bytes.Replace(manifest, []byte(`"audience":"public"`), []byte(`"audience":"device"`), 1),
		"wrong signing purpose":   bytes.Replace(manifest, []byte(`loom-release-manifest-v3`), []byte(`loom-release-catalog-v3`), 1),
		"whitespace":              append(manifest, '\n'),
	}
	for name, body := range mutations {
		t.Run(name, func(t *testing.T) {
			bad := replaceManifest(t, artifact, body, private)
			if _, err := verifyWithInspect(bad.Archive, bad.Checksum, bad.Signature, public, fixtureSingBox, fixtureSources); err == nil {
				t.Fatal("invalid signed manifest accepted")
			}
		})
	}
	if _, err := Verify(artifact.Archive, artifact.Checksum, []byte(`{"schema":2,"signature":"demo"}`), public); err == nil {
		t.Fatal("legacy signature envelope accepted")
	}
}

func replaceManifest(t *testing.T, artifact Artifact, body []byte, private ed25519.PrivateKey) Artifact {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(artifact.Archive))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	files := map[string]archiveFile{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		_, name, _ := strings.Cut(header.Name, "/")
		files[name] = archiveFile{path: name, mode: header.Mode, body: content}
	}
	signature := ed25519.Sign(private, signatureMessage(body))
	files["manifest.json"] = archiveFile{path: "manifest.json", mode: 0o644, body: body}
	files["manifest.sig"] = archiveFile{path: "manifest.sig", mode: 0o644, body: signature}
	delete(files, "checksums.txt")
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var sums strings.Builder
	payload := make([]archiveFile, 0, len(files)+1)
	for _, name := range names {
		f := files[name]
		fmt.Fprintf(&sums, "%s  %s\n", sha256Hex(f.body), name)
		payload = append(payload, f)
	}
	payload = append(payload, archiveFile{path: "checksums.txt", mode: 0o644, body: []byte(sums.String())})
	sort.Slice(payload, func(i, j int) bool { return payload[i].path < payload[j].path })
	archive, err := buildArchive("loom-client-linux-amd64", payload)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Archive = archive
	artifact.Signature = signature
	artifact.Checksum = []byte(fmt.Sprintf("%s  %s\n", sha256Hex(archive), artifact.Name))
	return artifact
}

func TestInstallerChecksExistingPayloadBeforeReuse(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("installer file ownership check requires Linux root")
	}
	start := strings.Index(installScript, "verify_release() {")
	if start < 0 {
		t.Fatal("missing release verification")
	}
	end := strings.Index(installScript[start:], "\n}\n")
	if end < 0 {
		t.Fatal("missing release verification")
	}
	function := installScript[start : start+end+3]
	cases := []struct {
		name   string
		mutate func(string) error
		valid  bool
	}{
		{name: "exact payload", valid: true},
		{name: "changed executable", mutate: func(root string) error {
			return os.WriteFile(filepath.Join(root, "sing-box"), []byte("demo damaged payload"), 0o755)
		}},
		{name: "writable executable", mutate: func(root string) error { return os.Chmod(filepath.Join(root, "loom"), 0o777) }},
		{name: "linked executable", mutate: func(root string) error {
			path := filepath.Join(root, "loom")
			if err := os.Rename(path, path+".original"); err != nil {
				return err
			}
			return os.Symlink(path+".original", path)
		}},
		{name: "hardlinked executable", mutate: func(root string) error {
			return os.Link(filepath.Join(root, "sing-box"), filepath.Join(root, "extra-link"))
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			base := t.TempDir()
			release := t.TempDir()
			for _, name := range []string{"loom", "sing-box", "manifest.json"} {
				mode := os.FileMode(0o755)
				if name == "manifest.json" {
					mode = 0o644
				}
				for _, root := range []string{base, release} {
					if err := os.WriteFile(filepath.Join(root, name), []byte("demo verified bytes for "+name), mode); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(filepath.Join(root, name), mode); err != nil {
						t.Fatal(err)
					}
				}
			}
			if test.mutate != nil {
				if err := test.mutate(release); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("sh", "-c", "set -eu\nbase=$1\nrelease=$2\n"+function+"\nverify_release", "demo-installer", base, release)
			output, err := command.CombinedOutput()
			if (err == nil) != test.valid {
				t.Fatalf("verify existing release: %v %s", err, output)
			}
		})
	}
}
