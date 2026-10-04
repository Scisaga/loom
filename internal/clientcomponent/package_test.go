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

	"loom/internal/control"
)

func TestBuildSourcePackageAndCanonicalRejection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native executable integration runs separately")
	}
	artifact, key := buildFixtureArtifact(t)
	verify := func(body []byte) (*Verified, error) {
		return verifyWithInspect(body, key.Public().(ed25519.PublicKey), fixtureSingInspector(t, fixtureIdentity()), inspectWintun)
	}
	one, err := verify(artifact.Package)
	if err != nil {
		t.Fatal(err)
	}
	if one.Manifest.Generation != 1 || one.Manifest.SingBox.Version != DataPlaneVersion || one.Manifest.Schema != 3 {
		t.Fatal("wrong manifest coordinates")
	}
	body, err := marshalManifest(one.Manifest)
	if err != nil || !bytes.Equal(body, one.ManifestBody) {
		t.Fatal("manifest did not round trip")
	}
	files, err := readZip(artifact.Package)
	if err != nil {
		t.Fatal(err)
	}
	again, err := buildZip(files)
	if err != nil || !bytes.Equal(again, artifact.Package) {
		t.Fatal("package is not reproducible")
	}
	cases := map[string][]byte{
		"old schema":         bytes.Replace(body, []byte(`"schema":3`), []byte(`"schema":1`), 1),
		"duplicate":          bytes.Replace(body, []byte(`"schema":3`), []byte(`"schema":3,"schema":3`), 1),
		"unknown":            append([]byte(`{"unknown":true,`), body[1:]...),
		"noncanonical":       append(append([]byte{}, body...), '\n'),
		"missing generation": bytes.Replace(body, []byte(`"generation":"1",`), nil, 1),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			changed := cloneFiles(files)
			changed["manifest.json"] = value
			changed["manifest.sig"] = ed25519.Sign(key, signatureMessage(value))
			bad, e := buildZip(changed)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = verify(bad); e == nil {
				t.Fatal("invalid signed bytes accepted")
			}
		})
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))
	if _, err := verifyWithInspect(artifact.Package, wrong.Public().(ed25519.PublicKey), fixtureSingInspector(t, fixtureIdentity()), inspectWintun); err == nil {
		t.Fatal("wrong key accepted")
	}
	files[WintunPath][len(files[WintunPath])/2] ^= 1
	bad, err := buildZip(files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(bad); err == nil || !strings.Contains(err.Error(), "does not match signed manifest") {
		t.Fatalf("tamper accepted: %v", err)
	}
}

func buildFixtureArtifact(t *testing.T) (Artifact, ed25519.PrivateKey) {
	t.Helper()
	sing := buildWindowsFixture(t)
	tun := append([]byte(nil), sing...)
	markPEDLL(t, tun)
	archive, err := buildZip(map[string][]byte{"wintun/LICENSE.txt": []byte("demo license"), "wintun/bin/amd64/wintun.dll": tun})
	if err != nil {
		t.Fatal(err)
	}
	patch, err := os.ReadFile("../../third_party/sing-box/domain-cache.patch")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"sing-box-windows-amd64.exe": sing, "LICENSE": []byte("demo license"), "source-provenance.json": []byte("demo provenance"), "domain-cache.patch": patch, "prepare-sing-box.py": []byte("demo prepare"), "build-dataplane.sh": []byte("demo build")}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x12}, ed25519.SeedSize))
	if _, err := Build("amd64", 1, files, archive, key); err == nil {
		t.Fatal("unreviewed executable accepted by production builder")
	}
	result, err := buildWithInspect("amd64", control.U64(1), files, archive, key, fixtureSingInspector(t, fixtureIdentity()), inspectWintun)
	if err != nil {
		t.Fatal(err)
	}
	return result, key
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
	return singBoxIdentity{version: DataPlaneVersion, commit: upstreamCommit}
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
