// Package windowsrelease binds the three existing Windows delivery forms to
// their exact artifacts and executable coordinates. It owns no install state.
package windowsrelease

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"debug/buildinfo"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"loom/internal/clientcomponent"
	"loom/internal/control"
)

const Kind = "windows-application"
const signatureDomain = "loom-release-manifest-v3\x00"
const maxArtifact = 256 << 20

type Manifest struct {
	Schema           int                         `json:"schema"`
	Kind             string                      `json:"kind"`
	Edition          string                      `json:"edition"`
	Arch             string                      `json:"arch"`
	Generation       control.U64                 `json:"generation"`
	SourceCommit     string                      `json:"source_commit"`
	InstallerVersion string                      `json:"installer_version,omitempty"`
	Artifact         control.ReleaseArtifact     `json:"artifact"`
	Components       []control.ComponentReadback `json:"components"`
}

func validEdition(edition string) bool {
	return edition == "installed" || edition == "portable-tun" || edition == "portable-mixed"
}

func Name(edition, arch string) string {
	extension := ".zip"
	if edition == "installed" {
		extension = ".msi"
	}
	return "loom-client-windows-" + edition + "-" + arch + extension
}

func IsArtifact(name string) bool {
	for _, edition := range []string{"installed", "portable-tun", "portable-mixed"} {
		for _, arch := range []string{"amd64", "arm64"} {
			if name == Name(edition, arch) {
				return true
			}
		}
	}
	return false
}

func installerVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	for index, part := range parts {
		value, err := strconv.Atoi(part)
		limit := 255
		if index == 2 {
			limit = 65535
		}
		if err != nil || value < 0 || value > limit || strconv.Itoa(value) != part {
			return false
		}
	}
	return true
}

func (m Manifest) Validate() error {
	if m.Schema != 3 || m.Kind != Kind || !validEdition(m.Edition) || (m.Arch != "amd64" && m.Arch != "arm64") || m.Generation == 0 || len(m.SourceCommit) != 40 || control.ValidateDigest("sha256:"+m.SourceCommit+strings.Repeat("0", 24)) != nil {
		return errors.New("Windows application coordinates are invalid")
	}
	media := "application/zip"
	if m.Edition == "installed" {
		media = "application/x-msi"
		if !installerVersion(m.InstallerVersion) {
			return errors.New("Windows installer version is invalid")
		}
	} else if m.InstallerVersion != "" {
		return errors.New("portable application has no installer version")
	}
	if m.Artifact.Validate() != nil || m.Artifact.Name != Name(m.Edition, m.Arch) || m.Artifact.MediaType != media || m.Artifact.Size > maxArtifact {
		return errors.New("Windows application artifact is invalid")
	}
	ids := []string{"agent", "sing-box", "wintun"}
	if m.Edition == "portable-mixed" {
		ids = ids[:2]
	}
	if len(m.Components) != len(ids) {
		return errors.New("Windows application component set is invalid")
	}
	for index, component := range m.Components {
		if component.Validate() != nil || component.ComponentID != ids[index] || component.Platform != "windows-"+m.Arch || index == 0 && component.Version != m.SourceCommit {
			return errors.New("Windows executable component binding is invalid")
		}
	}
	return nil
}

func (m Manifest) Version() string {
	if m.Edition == "installed" {
		return m.InstallerVersion
	}
	return m.SourceCommit
}

func payloadNames(edition, arch string) []string {
	return []string{"loom-client-windows-" + edition + "-" + arch + ".exe", "windows-dataplane.zip", "PREVIEW-NOTICE.txt", "LICENSE", "NOTICE",
		"licenses/gozxing-LICENSE", "licenses/golang-x-sys-LICENSE", "licenses/golang-x-sys-PATENTS", "licenses/golang-x-text-LICENSE", "licenses/golang-x-text-PATENTS", "licenses/golang-x-xerrors-LICENSE", "licenses/golang-x-xerrors-PATENTS", "licenses/yaml-v3-LICENSE"}
}

func readBundle(body []byte, edition, arch string) (map[string][]byte, error) {
	if !validEdition(edition) || (arch != "amd64" && arch != "arm64") || len(body) == 0 || len(body) > maxArtifact {
		return nil, errors.New("Windows bundle inputs are invalid")
	}
	archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	names := payloadNames(edition, arch)
	if err != nil || len(archive.File) != len(names) {
		return nil, errors.New("Windows bundle file set is invalid")
	}
	files := map[string][]byte{}
	var total uint64
	for _, entry := range archive.File {
		if !slices.Contains(names, entry.Name) || files[entry.Name] != nil || !entry.Mode().IsRegular() || entry.UncompressedSize64 == 0 || entry.UncompressedSize64 > 128<<20 || total+entry.UncompressedSize64 > maxArtifact {
			return nil, errors.New("Windows bundle contains an ambiguous or unsupported entry")
		}
		total += entry.UncompressedSize64
		reader, err := entry.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(reader, int64(entry.UncompressedSize64)+1))
		closeErr := reader.Close()
		if err != nil || closeErr != nil || uint64(len(data)) != entry.UncompressedSize64 {
			return nil, errors.New("Windows bundle file is incomplete")
		}
		files[entry.Name] = data
	}
	return files, nil
}

func inspectBundle(body []byte, edition, arch string, public ed25519.PublicKey) (string, []control.ComponentReadback, error) {
	files, err := readBundle(body, edition, arch)
	if err != nil {
		return "", nil, err
	}
	agent := files[payloadNames(edition, arch)[0]]
	object, err := pe.NewFile(bytes.NewReader(agent))
	if err != nil {
		return "", nil, errors.New("Windows agent is not PE")
	}
	defer object.Close()
	machine := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
	if arch == "arm64" {
		machine = pe.IMAGE_FILE_MACHINE_ARM64
	}
	if object.Machine != machine || object.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		return "", nil, errors.New("Windows agent architecture or executable kind differs")
	}
	info, err := buildinfo.Read(bytes.NewReader(agent))
	if err != nil || info.Main.Path != "loom" || info.Path != "loom/clients/windows" {
		return "", nil, errors.New("Windows agent build identity is unavailable")
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	commit := settings["vcs.revision"]
	if settings["GOOS"] != "windows" || settings["GOARCH"] != arch || settings["CGO_ENABLED"] != "0" || settings["-buildmode"] != "exe" || settings["-trimpath"] != "true" || settings["vcs"] != "git" || settings["vcs.modified"] != "false" || len(commit) != 40 || control.ValidateDigest("sha256:"+commit+strings.Repeat("0", 24)) != nil {
		return "", nil, errors.New("Windows agent clean source or platform binding is invalid")
	}
	verified, err := clientcomponent.Verify(files["windows-dataplane.zip"], public)
	if err != nil {
		return "", nil, err
	}
	if verified.Manifest.Arch != arch {
		return "", nil, errors.New("Windows bundled data-plane architecture differs")
	}
	components := []control.ComponentReadback{
		{ComponentID: "agent", Platform: "windows-" + arch, Version: commit, ArtifactDigest: control.ReleaseDigest(agent)},
		{ComponentID: "sing-box", Platform: "windows-" + arch, Version: verified.Manifest.SingBox.Version, ArtifactDigest: "sha256:" + verified.Manifest.SingBox.SHA256},
	}
	if edition != "portable-mixed" {
		components = append(components, control.ComponentReadback{ComponentID: "wintun", Platform: "windows-" + arch, Version: verified.Manifest.Wintun.Version, ArtifactDigest: "sha256:" + verified.Manifest.Wintun.SHA256})
	}
	return commit, components, nil
}

// Build is pure. For MSI the caller first audits these exact artifact/bundle
// bytes and ProductVersion with AuditMSI; the bundle is never a delivery file.
func Build(artifact, bundle []byte, edition, arch, version string, generation control.U64, key ed25519.PrivateKey) (Manifest, []byte, []byte, error) {
	var zero Manifest
	if len(key) != ed25519.PrivateKeySize || len(artifact) == 0 || len(artifact) > maxArtifact {
		return zero, nil, nil, errors.New("Windows signing inputs are invalid")
	}
	if edition != "installed" && !bytes.Equal(artifact, bundle) {
		return zero, nil, nil, errors.New("portable delivery differs from inspected bundle")
	}
	public := key.Public().(ed25519.PublicKey)
	commit, components, err := inspectBundle(bundle, edition, arch, public)
	if err != nil {
		return zero, nil, nil, err
	}
	if components[1].Version != clientcomponent.DataPlaneVersion {
		return zero, nil, nil, errors.New("Windows publisher only writes the current reviewed data plane")
	}
	media := "application/zip"
	if edition == "installed" {
		media = "application/x-msi"
	}
	m := Manifest{Schema: 3, Kind: Kind, Edition: edition, Arch: arch, Generation: generation, SourceCommit: commit, InstallerVersion: version, Artifact: control.ReleaseArtifact{Name: Name(edition, arch), Digest: control.ReleaseDigest(artifact), Size: control.U64(len(artifact)), MediaType: media, Audience: "public"}, Components: components}
	body, err := control.CanonicalEncode(m)
	if err != nil {
		return zero, nil, nil, err
	}
	signature := ed25519.Sign(key, append([]byte(signatureDomain), body...))
	if _, err = Verify(body, signature, artifact, public); err != nil {
		return zero, nil, nil, err
	}
	return m, body, signature, nil
}

// VerifyManifest authenticates canonical coordinates without reading artifact bytes.
func VerifyManifest(body, signature []byte, key ed25519.PublicKey) (Manifest, error) {
	var m Manifest
	if err := control.DecodeCanonical(body, &m, control.ContractDecodeLimits{MaxBytes: 64 << 10, MaxDepth: 12, MaxItems: 1024}); err != nil {
		return Manifest{}, err
	}
	if len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, append([]byte(signatureDomain), body...), signature) {
		return Manifest{}, errors.New("Windows application signature is invalid")
	}
	return m, nil
}

func Verify(body, signature, artifact []byte, key ed25519.PublicKey) (Manifest, error) {
	m, err := VerifyManifest(body, signature, key)
	if err != nil {
		return Manifest{}, err
	}
	if len(artifact) == 0 || len(artifact) > maxArtifact || m.Artifact.Size != control.U64(len(artifact)) || m.Artifact.Digest != control.ReleaseDigest(artifact) {
		return Manifest{}, errors.New("Windows delivery differs from its signed artifact")
	}
	if m.Edition != "installed" {
		commit, components, err := inspectBundle(artifact, m.Edition, m.Arch, key)
		if err != nil {
			return Manifest{}, err
		}
		if commit != m.SourceCommit || !slices.Equal(components, m.Components) {
			return Manifest{}, errors.New("Windows bundle differs from its signed executable coordinates")
		}
	} else if !bytes.HasPrefix(artifact, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}) {
		return Manifest{}, fmt.Errorf("Windows installer is not a compound database")
	}
	return m, nil
}
