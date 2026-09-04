// Package clientcomponent builds and verifies the Windows data-plane package.
//
// The platform signer consumes complete, pinned upstream archives. The client
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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	Schema                 = 1
	Kind                   = "windows-dataplane"
	signatureDomain        = "loom:windows-dataplane-package:v1"
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
	evidenceSingBox   = "github-release-asset+go-buildinfo"
	evidenceWintun    = "publisher-sha256+authenticode"
	wintunPublisher   = "WireGuard LLC"
	officialWintunURL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
)

// Source records the upstream evidence reviewed before the platform signed the
// package. It is audit metadata, not a client-side trust root.
type Source struct {
	URL                   string `json:"url"`
	ArchiveSHA256         string `json:"archive_sha256"`
	Evidence              string `json:"evidence"`
	ReleaseID             int64  `json:"release_id,omitempty"`
	AssetID               int64  `json:"asset_id,omitempty"`
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
	Schema          int       `json:"schema"`
	Kind            string    `json:"kind"`
	OS              string    `json:"os"`
	Arch            string    `json:"arch"`
	SignatureDomain string    `json:"signature_domain"`
	SingBox         Component `json:"sing_box"`
	Wintun          Component `json:"wintun"`
	Files           []File    `json:"files"`
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

type releasePin struct {
	arch             string
	singBoxVersion   string
	singBoxCommit    string
	singBoxReleaseID int64
	singBoxAssetID   int64
	singBoxURL       string
	singBoxArchive   string
	wintunVersion    string
	wintunArchive    string
}

var officialPins = map[string]releasePin{
	"amd64": {
		arch: "amd64", singBoxVersion: "v1.11.4",
		singBoxCommit:    "eb07c7a79eeca943370eafea601e87da76c0e57e",
		singBoxReleaseID: 201970450, singBoxAssetID: 232020341,
		singBoxURL:     "https://github.com/SagerNet/sing-box/releases/download/v1.11.4/sing-box-1.11.4-windows-amd64.zip",
		singBoxArchive: "8a681dbd6fa84f03d41e9e8637a8ff4df3d1d209556585ebf004b48325f9d70e",
		wintunVersion:  "0.14.1", wintunArchive: "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51",
	},
	"arm64": {
		arch: "arm64", singBoxVersion: "v1.11.4",
		singBoxCommit:    "eb07c7a79eeca943370eafea601e87da76c0e57e",
		singBoxReleaseID: 201970450, singBoxAssetID: 232020344,
		singBoxURL:     "https://github.com/SagerNet/sing-box/releases/download/v1.11.4/sing-box-1.11.4-windows-arm64.zip",
		singBoxArchive: "a0e3516a805774d1d671b3666e6b361f3f672e0a3926cfa99683be8b5076baeb",
		wintunVersion:  "0.14.1", wintunArchive: "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51",
	},
}

// BuildOfficial consumes the complete upstream archives whose identities were
// reviewed and pinned in source. Updating either upstream is an explicit code
// review, not a mutable runtime setting.
func BuildOfficial(arch string, singBoxArchive, wintunArchive []byte, privateKey ed25519.PrivateKey) (Artifact, error) {
	pin, ok := officialPins[arch]
	if !ok {
		return Artifact{}, fmt.Errorf("unsupported Windows component architecture %q", arch)
	}
	return buildPinned(pin, singBoxArchive, wintunArchive, privateKey)
}

func buildPinned(pin releasePin, singBoxArchive, wintunArchive []byte, privateKey ed25519.PrivateKey) (Artifact, error) {
	return buildPinnedWithInspect(pin, singBoxArchive, wintunArchive, privateKey, inspectSingBox, inspectWintun)
}

func buildPinnedWithInspect(pin releasePin, singBoxArchive, wintunArchive []byte, privateKey ed25519.PrivateKey,
	inspectSing func([]byte, string) (singBoxIdentity, error), inspectTun func([]byte, string) error) (Artifact, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Artifact{}, fmt.Errorf("platform signing private key has invalid length %d", len(privateKey))
	}
	if len(singBoxArchive) == 0 || len(singBoxArchive) > maxUpstreamArchiveSize ||
		len(wintunArchive) == 0 || len(wintunArchive) > maxUpstreamArchiveSize {
		return Artifact{}, errors.New("upstream archive has invalid size")
	}
	if sha256Hex(singBoxArchive) != pin.singBoxArchive {
		return Artifact{}, errors.New("sing-box upstream archive does not match the reviewed pin")
	}
	if sha256Hex(wintunArchive) != pin.wintunArchive {
		return Artifact{}, errors.New("Wintun upstream archive does not match the publisher SHA-256 pin")
	}
	singFiles, err := readZip(singBoxArchive)
	if err != nil {
		return Artifact{}, fmt.Errorf("read sing-box upstream archive: %w", err)
	}
	wintunFiles, err := readZip(wintunArchive)
	if err != nil {
		return Artifact{}, fmt.Errorf("read Wintun upstream archive: %w", err)
	}
	plainVersion := strings.TrimPrefix(pin.singBoxVersion, "v")
	singRoot := "sing-box-" + plainVersion + "-windows-" + pin.arch
	singBox, ok := singFiles[singRoot+"/sing-box.exe"]
	if !ok {
		return Artifact{}, errors.New("sing-box upstream archive is missing the pinned executable")
	}
	singLicense, ok := singFiles[singRoot+"/LICENSE"]
	if !ok {
		return Artifact{}, errors.New("sing-box upstream archive is missing LICENSE")
	}
	wintunArch := pin.arch
	if pin.arch == "arm64" {
		wintunArch = "arm64"
	}
	wintun, ok := wintunFiles["wintun/bin/"+wintunArch+"/wintun.dll"]
	if !ok {
		return Artifact{}, errors.New("Wintun upstream archive is missing the pinned DLL")
	}
	wintunLicense, ok := wintunFiles["wintun/LICENSE.txt"]
	if !ok {
		return Artifact{}, errors.New("Wintun upstream archive is missing LICENSE.txt")
	}

	singIdentity, err := inspectSing(singBox, pin.arch)
	if err != nil {
		return Artifact{}, err
	}
	if singIdentity.version != pin.singBoxVersion || singIdentity.commit != pin.singBoxCommit {
		return Artifact{}, fmt.Errorf("sing-box build identity is %s/%s, want %s/%s",
			singIdentity.version, singIdentity.commit, pin.singBoxVersion, pin.singBoxCommit)
	}
	if err := inspectTun(wintun, pin.arch); err != nil {
		return Artifact{}, err
	}

	payload := map[string][]byte{
		SingBoxPath: singBox, WintunPath: wintun,
		SingBoxLicense: singLicense, WintunLicense: wintunLicense,
	}
	manifest := Manifest{
		Schema: Schema, Kind: Kind, OS: "windows", Arch: pin.arch, SignatureDomain: signatureDomain,
		SingBox: Component{Path: SingBoxPath, SHA256: sha256Hex(singBox), Size: len(singBox),
			Version: pin.singBoxVersion, Commit: pin.singBoxCommit,
			Source: Source{URL: pin.singBoxURL, ArchiveSHA256: pin.singBoxArchive,
				Evidence: evidenceSingBox, ReleaseID: pin.singBoxReleaseID, AssetID: pin.singBoxAssetID}},
		Wintun: Component{Path: WintunPath, SHA256: sha256Hex(wintun), Size: len(wintun),
			Version: pin.wintunVersion,
			Source: Source{URL: officialWintunURL, ArchiveSHA256: pin.wintunArchive,
				Evidence: evidenceWintun, AuthenticodeRequired: true, AuthenticodePublisher: wintunPublisher}},
	}
	for name, body := range payload {
		manifest.Files = append(manifest.Files, File{Path: name, SHA256: sha256Hex(body), Size: len(body)})
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	if err := manifest.Validate(); err != nil {
		return Artifact{}, err
	}
	manifestBody, err := marshalManifest(manifest)
	if err != nil {
		return Artifact{}, err
	}
	signature := ed25519.Sign(privateKey, signatureMessage(manifestBody))
	payload["manifest.json"] = manifestBody
	payload["manifest.sig"] = signature
	body, err := buildZip(payload)
	if err != nil {
		return Artifact{}, err
	}
	name := fmt.Sprintf("loom-windows-dataplane-%s-%s.zip", strings.TrimPrefix(pin.singBoxVersion, "v"), pin.arch)
	return Artifact{Name: name, Package: body, SHA256: sha256Hex(body), Manifest: manifest}, nil
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
	wantNames := []string{SingBoxPath, WintunPath, SingBoxLicense, WintunLicense, "manifest.json", "manifest.sig"}
	sort.Strings(wantNames)
	if !slices.Equal(names, wantNames) {
		return nil, fmt.Errorf("Windows component package file set is %v, want %v", names, wantNames)
	}
	manifestBody := files["manifest.json"]
	if len(manifestBody) == 0 || len(manifestBody) > maxManifestBytes {
		return nil, errors.New("component manifest has invalid size")
	}
	var manifest Manifest
	if err := decodeStrict(manifestBody, &manifest); err != nil {
		return nil, fmt.Errorf("decode component manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	canonical, err := marshalManifest(manifest)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, manifestBody) {
		return nil, errors.New("component manifest is not in canonical form")
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
	if m.Schema != Schema || m.Kind != Kind || m.OS != "windows" || m.SignatureDomain != signatureDomain {
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
	if len(m.Files) != 4 {
		return fmt.Errorf("component manifest must cover exactly four payload files, got %d", len(m.Files))
	}
	want := []string{SingBoxPath, WintunPath, SingBoxLicense, WintunLicense}
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
	if source.Evidence != evidenceSingBox || source.ReleaseID <= 0 || source.AssetID <= 0 ||
		source.AuthenticodeRequired || source.AuthenticodePublisher != "" || !validLowerHex(source.ArchiveSHA256, 64) {
		return errors.New("sing-box source evidence is incomplete or inconsistent")
	}
	wantSuffix := fmt.Sprintf("/SagerNet/sing-box/releases/download/%s/sing-box-%s-windows-%s.zip", version, strings.TrimPrefix(version, "v"), arch)
	if err := validateHTTPSURL(source.URL, "github.com", wantSuffix); err != nil {
		return fmt.Errorf("invalid sing-box source URL: %w", err)
	}
	return nil
}

func validateWintunSource(source Source, version string) error {
	if source.Evidence != evidenceWintun || source.ReleaseID != 0 || source.AssetID != 0 ||
		!source.AuthenticodeRequired || source.AuthenticodePublisher != wintunPublisher ||
		!validLowerHex(source.ArchiveSHA256, 64) {
		return errors.New("Wintun source evidence is incomplete or inconsistent")
	}
	if err := validateHTTPSURL(source.URL, "www.wintun.net", "/builds/wintun-"+version+".zip"); err != nil {
		return fmt.Errorf("invalid Wintun source URL: %w", err)
	}
	return nil
}

func validateHTTPSURL(value, host, wantPath string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host != host || u.Path != wantPath ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("source must be the exact HTTPS release URL")
	}
	return nil
}

type singBoxIdentity struct {
	version string
	commit  string
}

func inspectSingBox(body []byte, wantArch string) (singBoxIdentity, error) {
	if err := inspectPE(body, wantArch, false); err != nil {
		return singBoxIdentity{}, fmt.Errorf("invalid sing-box PE: %w", err)
	}
	info, err := buildinfo.Read(bytes.NewReader(body))
	if err != nil {
		return singBoxIdentity{}, fmt.Errorf("read sing-box Go build identity: %w", err)
	}
	if info.Path != "github.com/sagernet/sing-box/cmd/sing-box" || info.Main.Path != "github.com/sagernet/sing-box" ||
		info.Main.Version == "" || info.Main.Version == "(devel)" {
		return singBoxIdentity{}, errors.New("executable is not a versioned upstream sing-box command")
	}
	var goos, goarch, commit string
	for _, setting := range info.Settings {
		switch setting.Key {
		case "GOOS":
			goos = setting.Value
		case "GOARCH":
			goarch = setting.Value
		case "vcs.revision":
			commit = setting.Value
		}
	}
	if goos != "windows" || goarch != wantArch || !validLowerHex(commit, 40) {
		return singBoxIdentity{}, errors.New("sing-box build settings do not contain the pinned Windows coordinates")
	}
	return singBoxIdentity{version: info.Main.Version, commit: commit}, nil
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
		if name == "" || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") ||
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

func marshalManifest(manifest Manifest) ([]byte, error) {
	body, err := json.MarshalIndent(&manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func decodeStrict(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains trailing value")
		}
		return err
	}
	return nil
}

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
