// Package clientcomponent builds and verifies the Windows data-plane package.
//
// The platform signer consumes the reviewed source build and pinned Wintun archive. The client
// trusts neither an archive URL nor a mutable package manager: it accepts only
// an exact file set covered by the locally pinned Loom Ed25519 public key.
package clientcomponent

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/pe"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"loom/internal/control"
)

const (
	Schema                 = 3
	Kind                   = "windows-dataplane"
	signatureDomain        = "loom-release-manifest-v3"
	maxPackageBytes        = 128 << 20
	maxUpstreamArchiveSize = 128 << 20
	maxEntryBytes          = 64 << 20
	maxManifestBytes       = 64 << 10
	maxFiles               = 16
)

const (
	SingBoxPath       = "bin/sing-box.exe"
	WintunPath        = "bin/wintun.dll"
	SingBoxLicense    = "licenses/sing-box-LICENSE"
	WintunLicense     = "licenses/wintun-LICENSE.txt"
	evidenceSingBox   = "go-module+reviewed-patch"
	evidenceWintun    = "publisher-sha256+authenticode"
	wintunPublisher   = "WireGuard LLC"
	officialWintunURL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
)

// Source is signed provenance, not another trust root.
type Source struct {
	URL                   string `json:"url"`
	ArchiveSHA256         string `json:"archive_sha256"`
	Evidence              string `json:"evidence"`
	UpstreamVersion       string `json:"upstream_version,omitempty"`
	ModuleSum             string `json:"module_sum,omitempty"`
	PatchSHA256           string `json:"patch_sha256,omitempty"`
	AuthenticodeRequired  bool   `json:"authenticode_required,omitempty"`
	AuthenticodePublisher string `json:"authenticode_publisher,omitempty"`
}

type Component struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Size    int    `json:"size"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Source  Source `json:"source"`
}

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

type Manifest struct {
	Generation      control.U64 `json:"generation"`
	Version         string      `json:"version"`
	Audience        string      `json:"audience"`
	Schema          int         `json:"schema"`
	Kind            string      `json:"kind"`
	OS              string      `json:"os"`
	Arch            string      `json:"arch"`
	SignatureDomain string      `json:"signature_domain"`
	SingBox         Component   `json:"sing_box"`
	Wintun          Component   `json:"wintun"`
	Files           []File      `json:"files"`
}

type Artifact struct {
	Name     string
	Package  []byte
	SHA256   string
	Manifest Manifest
}

type Verified struct {
	ID           string
	Manifest     Manifest
	ManifestBody []byte
	Signature    []byte
	Files        map[string][]byte
}

const DataPlaneVersion = "1.11.4-loom.1"
const upstreamCommit = "eb07c7a79eeca943370eafea601e87da76c0e57e"
const upstreamVersion = "v1.11.4"
const upstreamURL = "https://proxy.golang.org/github.com/sagernet/sing-box/@v/v1.11.4.zip"
const upstreamArchive = "43928129d0aa0ecf6bc3bede60d805e918f3f1510e8a38612b7ccd78f3bc8bf2"
const upstreamModuleSum = "h1:Z3xLwVJlTJfJ1p8R9M05aNJLFKRAwGebA5M/DFmr8p8="
const patchDigest = "5c8a8b8403834dedfe35345aa914fda2c909cca5c89ffb06868d19f7c5c65b08"
const wintunVersion = "0.14.1"
const wintunArchiveDigest = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

var reviewedBuilds = map[string]string{
	"amd64": "59aa4de23625dfc309292a27363507687dfa5ed12e9095b190b4f3d9e6916218",
	"arm64": "9c66eb2d9a828769f84e54be975cb51c41324c7f03aef0b0e91d2d97d27ba3a6",
}

var reviewedSources = map[string]string{
	"LICENSE":                "650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c",
	"source-provenance.json": "3272bb452fd24129d8d78ab8744b6d377990b236a79c576e9615728f1ade0dfe",
	"domain-cache.patch":     patchDigest,
	"prepare-sing-box.py":    "2cfcd7b16889f0ab7553b51253be4680f331d0c08ba6a7081653c8cb0a73daed",
	"build-dataplane.sh":     "d2704928f0b9ceb3f5b01a458b0ad534e754d75039f234445705a3bfd323f337",
}

const sourceBuildInstructions = `This package contains a modified sing-box 1.11.4, built with Go 1.27.0.
The upstream source ZIP, checksum and module sum are in the signed manifest.
The source-provenance.json file identifies the exact upstream commit and patch.

To reproduce with Bash, Python 3, Git and Go available, in a new directory:
  mkdir -p scripts third_party/sing-box
  cp /path/to/package/source/prepare-sing-box.py scripts/
  cp /path/to/package/source/build-dataplane.sh scripts/
  cp /path/to/package/source/domain-cache.patch third_party/sing-box/
  bash scripts/build-dataplane.sh

The script checks and downloads the pinned Go module source, applies the patch,
and writes the four deterministic executables to out/dataplane. It does not
require Loom's repository or any signing key. The upstream license is included
in licenses/sing-box-LICENSE. Wintun is the unchanged signed publisher DLL;
its source and license are described by its publisher and the signed manifest.
`

// Build consumes only explicit bytes. No clock, network or file reads occur.
// The generation is selected by the release caller, never inferred from time.
func Build(arch string, generation control.U64, buildFiles map[string][]byte, wintunArchive []byte, privateKey ed25519.PrivateKey) (Artifact, error) {
	for name, digest := range reviewedSources {
		if sha256Hex(buildFiles[name]) != digest {
			return Artifact{}, fmt.Errorf("data-plane source file %s differs from reviewed inputs", name)
		}
	}
	if sha256Hex(buildFiles["sing-box-windows-"+arch+".exe"]) != reviewedBuilds[arch] || reviewedBuilds[arch] == "" {
		return Artifact{}, errors.New("data-plane binary differs from the reviewed source build")
	}
	if sha256Hex(wintunArchive) != wintunArchiveDigest {
		return Artifact{}, errors.New("Wintun upstream archive does not match the publisher SHA-256 pin")
	}
	return buildWithInspect(arch, generation, buildFiles, wintunArchive, privateKey, inspectSingBox, inspectWintun)
}

func buildWithInspect(arch string, generation control.U64, buildFiles map[string][]byte, wintunArchive []byte, privateKey ed25519.PrivateKey,
	inspectSing func([]byte, string) (singBoxIdentity, error), inspectTun func([]byte, string) error) (Artifact, error) {
	if len(privateKey) != ed25519.PrivateKeySize || len(wintunArchive) == 0 || len(wintunArchive) > maxUpstreamArchiveSize {
		return Artifact{}, errors.New("invalid platform key or Wintun archive bounds")
	}
	wintunFiles, err := readZip(wintunArchive)
	if err != nil {
		return Artifact{}, err
	}
	payload := map[string][]byte{
		SingBoxPath:    buildFiles["sing-box-windows-"+arch+".exe"],
		WintunPath:     wintunFiles["wintun/bin/"+arch+"/wintun.dll"],
		SingBoxLicense: buildFiles["LICENSE"], WintunLicense: wintunFiles["wintun/LICENSE.txt"],
		"source/source-provenance.json": buildFiles["source-provenance.json"],
		"source/domain-cache.patch":     buildFiles["domain-cache.patch"],
		"source/prepare-sing-box.py":    buildFiles["prepare-sing-box.py"],
		"source/build-dataplane.sh":     buildFiles["build-dataplane.sh"],
		"source/BUILD.txt":              []byte(sourceBuildInstructions),
	}
	for name, body := range payload {
		if len(body) == 0 || len(body) > maxEntryBytes {
			return Artifact{}, fmt.Errorf("missing or oversized component file %s", name)
		}
	}
	if sha256Hex(payload["source/domain-cache.patch"]) != patchDigest {
		return Artifact{}, errors.New("unreviewed data-plane patch")
	}
	identity, err := inspectSing(payload[SingBoxPath], arch)
	if err != nil {
		return Artifact{}, err
	}
	if identity.version != DataPlaneVersion || identity.commit != upstreamCommit {
		return Artifact{}, errors.New("data-plane build identity differs from reviewed source")
	}
	if err = inspectTun(payload[WintunPath], arch); err != nil {
		return Artifact{}, err
	}
	manifest := Manifest{Schema: Schema, Kind: Kind, OS: "windows", Arch: arch, Generation: generation, Version: DataPlaneVersion, Audience: "public", SignatureDomain: signatureDomain,
		SingBox: Component{Path: SingBoxPath, SHA256: sha256Hex(payload[SingBoxPath]), Size: len(payload[SingBoxPath]), Version: DataPlaneVersion, Commit: upstreamCommit,
			Source: Source{URL: upstreamURL, ArchiveSHA256: upstreamArchive, Evidence: evidenceSingBox, UpstreamVersion: upstreamVersion, ModuleSum: upstreamModuleSum, PatchSHA256: patchDigest}},
		Wintun: Component{Path: WintunPath, SHA256: sha256Hex(payload[WintunPath]), Size: len(payload[WintunPath]), Version: wintunVersion,
			Source: Source{URL: officialWintunURL, ArchiveSHA256: wintunArchiveDigest, Evidence: evidenceWintun, AuthenticodeRequired: true, AuthenticodePublisher: wintunPublisher}},
	}
	for name, body := range payload {
		manifest.Files = append(manifest.Files, File{Path: name, SHA256: sha256Hex(body), Size: len(body)})
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	manifestBody, err := marshalManifest(manifest)
	if err != nil {
		return Artifact{}, err
	}
	payload["manifest.json"] = manifestBody
	payload["manifest.sig"] = ed25519.Sign(privateKey, signatureMessage(manifestBody))
	body, err := buildZip(payload)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Name: fmt.Sprintf("loom-windows-dataplane-%s-%s.zip", DataPlaneVersion, arch), Package: body, SHA256: sha256Hex(body), Manifest: manifest}, nil
}

func payloadNames() []string {
	names := []string{SingBoxPath, WintunPath, SingBoxLicense, WintunLicense, "source/source-provenance.json", "source/domain-cache.patch", "source/prepare-sing-box.py", "source/build-dataplane.sh", "source/BUILD.txt"}
	sort.Strings(names)
	return names
}

func Verify(packageBody []byte, publicKey ed25519.PublicKey) (*Verified, error) {
	return verifyWithInspect(packageBody, publicKey, inspectSingBox, inspectWintun)
}

func verifyWithInspect(packageBody []byte, publicKey ed25519.PublicKey,
	inspectSing func([]byte, string) (singBoxIdentity, error), inspectTun func([]byte, string) error) (*Verified, error) {
	if len(packageBody) == 0 || len(packageBody) > maxPackageBytes {
		return nil, errors.New("Windows component package has invalid size")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("pinned platform public key has invalid length")
	}
	files, err := readZip(packageBody)
	if err != nil {
		return nil, err
	}
	names := sortedNames(files)
	wantNames := append(payloadNames(), "manifest.json", "manifest.sig")
	sort.Strings(wantNames)
	if !slices.Equal(names, wantNames) {
		return nil, fmt.Errorf("Windows component package file set is %v, want %v", names, wantNames)
	}
	manifestBody := files["manifest.json"]
	if len(manifestBody) == 0 || len(manifestBody) > maxManifestBytes {
		return nil, errors.New("component manifest has invalid size")
	}
	var manifest Manifest
	if err := control.DecodeCanonical(manifestBody, &manifest, control.ContractDecodeLimits{MaxBytes: maxManifestBytes, MaxDepth: 16, MaxItems: 4096}); err != nil {
		return nil, fmt.Errorf("decode component manifest: %w", err)
	}
	signature := files["manifest.sig"]
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, signatureMessage(manifestBody), signature) {
		return nil, errors.New("component manifest signature is missing, malformed, or invalid")
	}
	for _, file := range manifest.Files {
		body, ok := files[file.Path]
		if !ok || len(body) != file.Size || sha256Hex(body) != file.SHA256 {
			return nil, fmt.Errorf("component payload %q does not match signed manifest", file.Path)
		}
	}
	singIdentity, err := inspectSing(files[SingBoxPath], manifest.Arch)
	if err != nil {
		return nil, err
	}
	if sha256Hex(files["source/domain-cache.patch"]) != manifest.SingBox.Source.PatchSHA256 {
		return nil, errors.New("source patch differs from signed provenance")
	}
	if singIdentity.version != manifest.SingBox.Version || singIdentity.commit != manifest.SingBox.Commit {
		return nil, errors.New("sing-box executable identity does not match signed manifest")
	}
	if err := inspectTun(files[WintunPath], manifest.Arch); err != nil {
		return nil, err
	}
	return &Verified{ID: sha256Hex(manifestBody), Manifest: manifest,
		ManifestBody: append([]byte(nil), manifestBody...), Signature: append([]byte(nil), signature...),
		Files: cloneFiles(files)}, nil
}

func (m Manifest) Validate() error {
	if m.Schema != Schema || m.Kind != Kind || m.OS != "windows" || m.SignatureDomain != signatureDomain || m.Generation == 0 || m.Audience != "public" || m.Version != DataPlaneVersion {
		return errors.New("component manifest has invalid schema, kind, OS, or signature domain")
	}
	if m.Arch != "amd64" && m.Arch != "arm64" {
		return fmt.Errorf("unsupported component architecture %q", m.Arch)
	}
	if err := validateComponent(m.SingBox, SingBoxPath, true); err != nil {
		return fmt.Errorf("invalid sing-box component: %w", err)
	}
	if err := validateComponent(m.Wintun, WintunPath, false); err != nil {
		return fmt.Errorf("invalid Wintun component: %w", err)
	}
	if err := validateSingSource(m.SingBox.Source, m.SingBox.Version, m.Arch); err != nil {
		return err
	}
	if err := validateWintunSource(m.Wintun.Source, m.Wintun.Version); err != nil {
		return err
	}
	if len(m.Files) != len(payloadNames()) {
		return errors.New("component manifest must cover the exact payload file set")
	}
	want := payloadNames()
	sort.Strings(want)
	seen := make([]string, 0, len(m.Files))
	for i, file := range m.Files {
		if file.Path == "" || path.Clean(file.Path) != file.Path || strings.HasPrefix(file.Path, "/") ||
			file.Size <= 0 || file.Size > maxEntryBytes || !validLowerHex(file.SHA256, 64) {
			return fmt.Errorf("invalid component file at index %d", i)
		}
		if i > 0 && m.Files[i-1].Path >= file.Path {
			return errors.New("component files are not strictly sorted")
		}
		seen = append(seen, file.Path)
	}
	if !slices.Equal(seen, want) {
		return errors.New("component manifest payload set is not the managed Windows file set")
	}
	byPath := make(map[string]File, len(m.Files))
	for _, file := range m.Files {
		byPath[file.Path] = file
	}
	if f := byPath[m.SingBox.Path]; f.SHA256 != m.SingBox.SHA256 || f.Size != m.SingBox.Size {
		return errors.New("sing-box component does not match its payload record")
	}
	if f := byPath[m.Wintun.Path]; f.SHA256 != m.Wintun.SHA256 || f.Size != m.Wintun.Size {
		return errors.New("Wintun component does not match its payload record")
	}
	return nil
}

func validateComponent(component Component, wantPath string, requireCommit bool) error {
	if component.Path != wantPath || component.Size <= 0 || component.Size > maxEntryBytes ||
		!validLowerHex(component.SHA256, 64) || component.Version == "" || len(component.Version) > 64 {
		return errors.New("invalid path, digest, size, or version")
	}
	if requireCommit && !validLowerHex(component.Commit, 40) {
		return errors.New("missing or invalid source commit")
	}
	if !requireCommit && component.Commit != "" {
		return errors.New("unexpected commit")
	}
	return nil
}

func validateSingSource(source Source, version, arch string) error {
	want := Source{URL: upstreamURL, ArchiveSHA256: upstreamArchive, Evidence: evidenceSingBox, UpstreamVersion: upstreamVersion, ModuleSum: upstreamModuleSum, PatchSHA256: patchDigest}
	if source != want || version != DataPlaneVersion || reviewedBuilds[arch] == "" {
		return errors.New("sing-box source evidence differs from the reviewed source build")
	}
	return nil
}

func validateWintunSource(source Source, version string) error {
	want := Source{URL: officialWintunURL, ArchiveSHA256: wintunArchiveDigest, Evidence: evidenceWintun, AuthenticodeRequired: true, AuthenticodePublisher: wintunPublisher}
	if source != want || version != wintunVersion {
		return errors.New("Wintun source evidence differs from the pinned publisher archive")
	}
	return nil
}

type singBoxIdentity struct {
	version string
	commit  string
}

func inspectSingBox(body []byte, wantArch string) (singBoxIdentity, error) {
	if reviewedBuilds[wantArch] == "" || sha256Hex(body) != reviewedBuilds[wantArch] {
		return singBoxIdentity{}, errors.New("sing-box binary differs from the reviewed source build")
	}
	if err := inspectPE(body, wantArch, false); err != nil {
		return singBoxIdentity{}, fmt.Errorf("invalid sing-box PE: %w", err)
	}
	info, err := buildinfo.Read(bytes.NewReader(body))
	if err != nil {
		return singBoxIdentity{}, fmt.Errorf("read sing-box Go build identity: %w", err)
	}
	if info.Path != "github.com/sagernet/sing-box/cmd/sing-box" || info.Main.Path != "github.com/sagernet/sing-box" ||
		info.Main.Version != "(devel)" {
		return singBoxIdentity{}, errors.New("executable is not the reviewed sing-box source build")
	}
	var goos, goarch, tags, cgo, trimpath string
	for _, setting := range info.Settings {
		switch setting.Key {
		case "GOOS":
			goos = setting.Value
		case "GOARCH":
			goarch = setting.Value
		case "-tags":
			tags = setting.Value
		case "CGO_ENABLED":
			cgo = setting.Value
		case "-trimpath":
			trimpath = setting.Value
		case "vcs.revision":
			return singBoxIdentity{}, errors.New("patched source build must not claim upstream VCS identity")
		}
	}
	if goos != "windows" || goarch != wantArch || tags != "with_gvisor,with_quic,with_wireguard,with_ech,with_utls,with_clash_api,http2legacy" || cgo != "0" || trimpath != "true" || info.GoVersion != "go1.27.0" {
		return singBoxIdentity{}, errors.New("sing-box build settings do not contain the pinned Windows coordinates")
	}
	return singBoxIdentity{version: DataPlaneVersion, commit: upstreamCommit}, nil
}

func inspectWintun(body []byte, wantArch string) error {
	if err := inspectPE(body, wantArch, true); err != nil {
		return fmt.Errorf("invalid Wintun PE: %w", err)
	}
	return nil
}

func inspectPE(body []byte, wantArch string, wantDLL bool) error {
	if len(body) == 0 || len(body) > maxEntryBytes {
		return errors.New("PE has invalid size")
	}
	file, err := pe.NewFile(bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer file.Close()
	arch := ""
	switch file.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		arch = "arm64"
	}
	if arch != wantArch {
		return fmt.Errorf("PE architecture is %q, want %q", arch, wantArch)
	}
	isDLL := file.Characteristics&pe.IMAGE_FILE_DLL != 0
	if isDLL != wantDLL {
		return fmt.Errorf("PE DLL flag is %t, want %t", isDLL, wantDLL)
	}
	return nil
}

func readZip(body []byte) (map[string][]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, err
	}
	if len(reader.File) == 0 || len(reader.File) > maxFiles {
		return nil, errors.New("ZIP has invalid entry count")
	}
	files := make(map[string][]byte, len(reader.File))
	var total uint64
	for _, entry := range reader.File {
		name := entry.Name
		if name == "" || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.Contains(name, "\\") ||
			!entry.Mode().IsRegular() {
			return nil, fmt.Errorf("ZIP contains unsafe entry %q", name)
		}
		if _, exists := files[name]; exists {
			return nil, fmt.Errorf("ZIP contains duplicate entry %q", name)
		}
		if entry.UncompressedSize64 == 0 || entry.UncompressedSize64 > maxEntryBytes || total+entry.UncompressedSize64 > maxPackageBytes {
			return nil, fmt.Errorf("ZIP entry %q has invalid size", name)
		}
		total += entry.UncompressedSize64
		stream, err := entry.Open()
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(stream, int64(entry.UncompressedSize64)+1))
		closeErr := stream.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if uint64(len(data)) != entry.UncompressedSize64 {
			return nil, fmt.Errorf("ZIP entry %q size changed while reading", name)
		}
		files[name] = data
	}
	return files, nil
}

func buildZip(files map[string][]byte) ([]byte, error) {
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	names := sortedNames(files)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0o644)
		header.Modified = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err := entry.Write(files[name]); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func marshalManifest(manifest Manifest) ([]byte, error) { return control.CanonicalEncode(manifest) }

func signatureMessage(manifestBody []byte) []byte {
	message := make([]byte, 0, len(signatureDomain)+1+len(manifestBody))
	message = append(message, signatureDomain...)
	message = append(message, 0)
	return append(message, manifestBody...)
}

func sortedNames(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func cloneFiles(files map[string][]byte) map[string][]byte {
	clone := make(map[string][]byte, len(files))
	for name, body := range files {
		clone[name] = append([]byte(nil), body...)
	}
	return clone
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range []byte(value) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
