package windowsrelease

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"loom/internal/control"
)

var testArtifacts = flag.String("windows-artifacts", "", "optional original Windows build output directory")
var testPublicKey = flag.String("windows-public-key", "", "independent public key for original Windows component bundles")

func TestInspectionOutputBoundAppliesToStreamCopy(t *testing.T) {
	output := &boundedOutput{limit: 8}
	if _, err := io.Copy(output, bytes.NewBufferString("demo oversize output")); err == nil || output.buffer.Len() > 8 {
		t.Fatal("subprocess stream bypassed its output boundary")
	}
}

func demoManifest(edition, arch string) Manifest {
	commit := strings.Repeat("a", 40)
	media, version := "application/zip", ""
	if edition == "installed" {
		media, version = "application/x-msi", "1.2.3"
	}
	components := []control.ComponentReadback{{ComponentID: "agent", Platform: "windows-" + arch, Version: commit, ArtifactDigest: control.ReleaseDigest([]byte("demo agent"))}, {ComponentID: "sing-box", Platform: "windows-" + arch, Version: "demo-native", ArtifactDigest: control.ReleaseDigest([]byte("demo native"))}}
	if edition != "portable-mixed" {
		components = append(components, control.ComponentReadback{ComponentID: "wintun", Platform: "windows-" + arch, Version: "demo-driver", ArtifactDigest: control.ReleaseDigest([]byte("demo driver"))})
	}
	return Manifest{Schema: 3, Kind: Kind, Edition: edition, Arch: arch, Generation: 1, SourceCommit: commit, InstallerVersion: version, Artifact: control.ReleaseArtifact{Name: Name(edition, arch), Digest: control.ReleaseDigest([]byte("demo artifact")), Size: 100, MediaType: media, Audience: "public"}, Components: components}
}

func TestApplicationRoundTripAndDeliveryBoundaries(t *testing.T) {
	for _, edition := range []string{"installed", "portable-tun", "portable-mixed"} {
		for _, arch := range []string{"amd64", "arm64"} {
			m := demoManifest(edition, arch)
			body, err := control.CanonicalEncode(m)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Manifest
			if err = control.DecodeCanonical(body, &decoded, control.ContractDecodeLimits{MaxBytes: 64 << 10, MaxDepth: 12, MaxItems: 1024}); err != nil {
				t.Fatal(err)
			}
			again, err := control.CanonicalEncode(decoded)
			if err != nil || !bytes.Equal(body, again) {
				t.Fatal("application manifest did not round trip")
			}
			entry := control.ReleaseEntry{ComponentID: "windows-client-" + edition, Platform: "windows-" + arch, ManifestDigest: control.ReleaseDigest(body), Artifact: m.Artifact}
			if entry.Validate() != nil || !IsArtifact(m.Artifact.Name) {
				t.Fatal("delivery form was not a unique catalog entry")
			}
			if m.Components[0].ArtifactDigest == m.Artifact.Digest {
				t.Fatal("whole artifact replaced executable identity")
			}
			for _, bad := range [][]byte{append([]byte(" "), body...), bytes.Replace(body, []byte(`"schema":3`), []byte(`"schema":1`), 1), bytes.Replace(body, []byte(`"schema":3`), []byte(`"schema":3,"schema":3`), 1), append([]byte(`{"unknown":true,`), body[1:]...)} {
				if control.DecodeCanonical(bad, &decoded, control.ContractDecodeLimits{MaxBytes: 64 << 10, MaxDepth: 12, MaxItems: 1024}) == nil {
					t.Fatal("noncanonical application accepted")
				}
			}
		}
	}
	m := demoManifest("installed", "amd64")
	for _, change := range []func(*Manifest){
		func(m *Manifest) { m.Edition = "demo-unknown" }, func(m *Manifest) { m.Arch = "any" }, func(m *Manifest) { m.Generation = 0 }, func(m *Manifest) { m.SourceCommit = strings.Repeat("A", 40) },
		func(m *Manifest) { m.InstallerVersion = "01.2.3" }, func(m *Manifest) { m.InstallerVersion = "256.0.0" }, func(m *Manifest) { m.InstallerVersion = "1.0.65536" }, func(m *Manifest) { m.InstallerVersion = "" },
		func(m *Manifest) { m.Artifact.Name = "demo-other.msi" }, func(m *Manifest) { m.Artifact.MediaType = "application/zip" }, func(m *Manifest) { m.Components[0].Version = "demo-invented" }, func(m *Manifest) { m.Components[1].Platform = "windows-arm64" }, func(m *Manifest) { m.Components[1] = m.Components[0] },
	} {
		bad := m
		bad.Components = slices.Clone(m.Components)
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("ambiguous application accepted")
		}
	}
	m = demoManifest("portable-mixed", "amd64")
	m.InstallerVersion = "1.2.3"
	if m.Validate() == nil {
		t.Fatal("portable package invented MSI version")
	}
	if IsArtifact("loom-client-windows-installed-amd64.zip") {
		t.Fatal("MSI build input became a formal installed delivery")
	}
}

func TestBundleRejectsUnownedAndAmbiguousFiles(t *testing.T) {
	for _, extra := range []string{"../demo.exe", "DEMO.exe", "licenses/demo-extra", payloadNames("portable-mixed", "amd64")[0]} {
		var body bytes.Buffer
		writer := zip.NewWriter(&body)
		names := payloadNames("portable-mixed", "amd64")
		names[len(names)-1] = extra
		for _, name := range names {
			file, _ := writer.Create(name)
			file.Write([]byte("demo"))
		}
		writer.Close()
		if _, err := readBundle(body.Bytes(), "portable-mixed", "amd64"); err == nil {
			t.Fatal("unowned or ambiguous ZIP accepted")
		}
	}
}

func TestMSIExtractionRequiresEveryOriginalByte(t *testing.T) {
	files := map[string][]byte{}
	for _, name := range payloadNames("installed", "amd64") {
		files[name] = []byte("demo " + name)
	}
	makeTar := func(extra string, changed, omit bool) []byte {
		var body bytes.Buffer
		writer := tar.NewWriter(&body)
		for index, name := range payloadNames("installed", "amd64") {
			if omit && index == 0 {
				continue
			}
			value := files[name]
			if changed && index == 0 {
				value = append(bytes.Clone(value), 'x')
			}
			if index == 0 {
				name = "loom-client.exe"
			}
			writer.WriteHeader(&tar.Header{Name: "./PFiles64/Loom/" + name, Mode: 0644, Size: int64(len(value))})
			writer.Write(value)
		}
		if extra != "" {
			writer.WriteHeader(&tar.Header{Name: extra, Mode: 0644, Size: 4})
			writer.Write([]byte("demo"))
		}
		writer.Close()
		return body.Bytes()
	}
	if err := compareExtracted(makeTar("", false, false), files, "amd64"); err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{makeTar("../demo", false, false), makeTar("PFiles64/Loom/demo-extra", false, false), makeTar("PFiles64/Loom/loom-client.exe", false, false), makeTar("", true, false), makeTar("", false, true)} {
		if compareExtracted(body, files, "amd64") == nil {
			t.Fatal("MSI payload mismatch accepted")
		}
	}
}

func TestOriginalApplicationArtifacts(t *testing.T) {
	if *testArtifacts == "" || *testPublicKey == "" {
		t.Skip("requires original Windows artifacts and independent public key")
	}
	public, err := control.ReadReleasePublicKey(*testPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	demoKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	for _, arch := range []string{"amd64", "arm64"} {
		for _, edition := range []string{"installed", "portable-tun", "portable-mixed"} {
			t.Run(edition+"-"+arch, func(t *testing.T) {
				bundle, err := os.ReadFile(filepath.Join(*testArtifacts, "loom-client-windows-"+edition+"-"+arch+".zip"))
				if err != nil {
					t.Fatal(err)
				}
				commit, components, err := inspectBundle(bundle, edition, arch, public)
				if err != nil {
					t.Fatal(err)
				}
				if len(commit) != 40 || components[0].ArtifactDigest == control.ReleaseDigest(bundle) {
					t.Fatal("bundle and executable identities were conflated")
				}
				other := "arm64"
				if arch == other {
					other = "amd64"
				}
				if _, _, err := inspectBundle(bundle, edition, other, public); err == nil {
					t.Fatal("wrong architecture accepted")
				}
				if edition != "installed" {
					return
				}
				artifact, err := os.ReadFile(filepath.Join(*testArtifacts, Name(edition, arch)))
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				version, err := AuditMSI(ctx, artifact, bundle, arch)
				if err != nil {
					t.Fatal(err)
				}
				m := demoManifest(edition, arch)
				m.SourceCommit = commit
				m.InstallerVersion = version
				m.Components = components
				m.Artifact.Size = control.U64(len(artifact))
				m.Artifact.Digest = control.ReleaseDigest(artifact)
				body, err := control.CanonicalEncode(m)
				if err != nil {
					t.Fatal(err)
				}
				signature := ed25519.Sign(demoKey, append([]byte(signatureDomain), body...))
				if _, err := Verify(body, signature, artifact, demoKey.Public().(ed25519.PublicKey)); err != nil {
					t.Fatal(err)
				}
				if _, err := Verify(body, signature, artifact, public); err == nil {
					t.Fatal("wrong signer accepted")
				}
				changed := bytes.Clone(artifact)
				changed[len(changed)/2] ^= 1
				if _, err := Verify(body, signature, changed, demoKey.Public().(ed25519.PublicKey)); err == nil {
					t.Fatal("changed MSI accepted")
				}
			})
		}
	}
}
