package androidrelease

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"loom/internal/clientcomponent"
	"loom/internal/control"
)

const Kind = "android-application"
const Name = "loom-android.apk"
const PackageID = "io.github.scisaga.loom"
const MediaType = "application/vnd.android.package-archive"
const signatureDomain = "loom-release-manifest-v3\x00"
const maxAPK = 256 << 20
const provenancePath = "assets/loom/source-provenance.json"

type NativeLibrary struct {
	Arch   string `json:"arch"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

type Manifest struct {
	Schema          int                     `json:"schema"`
	Kind            string                  `json:"kind"`
	Generation      control.U64             `json:"generation"`
	ApplicationID   string                  `json:"application_id"`
	VersionCode     int                     `json:"version_code"`
	VersionName     string                  `json:"version_name"`
	SourceCommit    string                  `json:"source_commit"`
	AARSHA256       string                  `json:"aar_sha256"`
	SingBoxVersion  string                  `json:"sing_box_version"`
	Artifact        control.ReleaseArtifact `json:"artifact"`
	NativeLibraries []NativeLibrary         `json:"native_libraries"`
}

var versionText = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
var dexName = regexp.MustCompile(`^classes(?:[2-9]|[1-9][0-9]+)?\.dex$`)

func hexSize(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && hex.EncodeToString(decoded) == value
}

func libraryPath(arch string) string {
	switch arch {
	case "amd64":
		return "lib/x86_64/libbox.so"
	case "arm64":
		return "lib/arm64-v8a/libbox.so"
	}
	return ""
}

func (m Manifest) Validate() error {
	if m.Schema != 3 || m.Kind != Kind || m.Generation == 0 || m.ApplicationID != PackageID || m.VersionCode < 1 || m.VersionCode > 2147483647 || !versionText.MatchString(m.VersionName) || !hexSize(m.SourceCommit, 20) || !hexSize(m.AARSHA256, 32) || !versionText.MatchString(m.SingBoxVersion) {
		return errors.New("Android application manifest coordinates are invalid")
	}
	if m.Artifact.Validate() != nil || m.Artifact.Name != Name || m.Artifact.MediaType != MediaType || m.Artifact.Size > maxAPK || len(m.NativeLibraries) != 2 {
		return errors.New("Android application artifact is invalid")
	}
	for index, arch := range []string{"amd64", "arm64"} {
		library := m.NativeLibraries[index]
		if library.Arch != arch || library.Path != libraryPath(arch) || !hexSize(library.SHA256, 32) || library.Size <= 0 || library.Size > maxAPK {
			return errors.New("Android native library coordinates are invalid")
		}
	}
	return nil
}

// APKMetadata is a disposable inspection of the actual APK. It has no wire,
// authority or persistence separate from the signed manifest and artifact.
type APKMetadata struct {
	VersionCode                    int
	VersionName, Commit, AARSHA256 string
	SingBoxVersion                 string
	Libraries                      []NativeLibrary
}

func readEntry(entry *zip.File, limit int64) ([]byte, error) {
	if entry.UncompressedSize64 == 0 || entry.UncompressedSize64 > uint64(limit) {
		return nil, errors.New("Android archive entry exceeds its boundary")
	}
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || uint64(len(body)) != entry.UncompressedSize64 {
		return nil, errors.New("Android archive entry is incomplete")
	}
	return body, nil
}

func archiveFiles(body []byte) (map[string]*zip.File, error) {
	if len(body) == 0 || len(body) > maxAPK {
		return nil, errors.New("Android archive size is invalid")
	}
	archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil || len(archive.File) > 65536 {
		return nil, errors.New("Android archive directory is invalid")
	}
	files := map[string]*zip.File{}
	seen := map[string]bool{}
	var total uint64
	for _, entry := range archive.File {
		name := entry.Name
		if entry.FileInfo().IsDir() {
			name = strings.TrimSuffix(name, "/")
		}
		if name == "" || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || name == ".." || strings.HasPrefix(name, "../") || seen[name] || entry.UncompressedSize64 > maxAPK {
			return nil, errors.New("Android archive contains an ambiguous or unsupported entry")
		}
		seen[name] = true
		if entry.FileInfo().IsDir() && entry.UncompressedSize64 == 0 {
			continue
		}
		if !entry.Mode().IsRegular() {
			return nil, errors.New("Android archive contains a non-regular file")
		}
		total += entry.UncompressedSize64
		if total > 1<<30 {
			return nil, errors.New("Android archive expanded size exceeds its boundary")
		}
		files[entry.Name] = entry
	}
	return files, nil
}

func InspectAPK(body []byte) (APKMetadata, error) {
	var result APKMetadata
	files, err := archiveFiles(body)
	if err != nil {
		return result, err
	}
	if files["AndroidManifest.xml"] == nil || files["classes.dex"] == nil {
		return result, errors.New("Android application code or manifest is absent")
	}
	result.SingBoxVersion, err = archiveSourceVersion(files)
	if err != nil {
		return APKMetadata{}, err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var config map[string]any
	for _, name := range names {
		entry := files[name]
		if dexName.MatchString(name) {
			body, err := readEntry(entry, 64<<20)
			if err != nil {
				return result, err
			}
			found, err := readBuildConfig(body)
			if err != nil || found != nil && config != nil {
				return result, errDEX
			}
			if found != nil {
				config = found
			}
		}
		if path.Base(name) == "libbox.so" && name != libraryPath("amd64") && name != libraryPath("arm64") {
			return result, errors.New("Android native library ABI is unsupported")
		}
	}
	if len(config) != 7 || config["APPLICATION_ID"] != PackageID || config["BUILD_TYPE"] != "release" || config["DEBUG"] != false {
		return result, errors.New("APK does not contain the official release BuildConfig")
	}
	result.VersionCode, _ = config["VERSION_CODE"].(int)
	result.VersionName, _ = config["VERSION_NAME"].(string)
	result.Commit, _ = config["LOOM_SOURCE_COMMIT"].(string)
	result.AARSHA256, _ = config["LOOM_AAR_SHA256"].(string)
	if result.VersionCode <= 0 || result.VersionCode > 2147483647 || !versionText.MatchString(result.VersionName) || !hexSize(result.Commit, 20) || !hexSize(result.AARSHA256, 32) {
		return APKMetadata{}, errors.New("APK release provenance is incomplete")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		entry := files[libraryPath(arch)]
		if entry == nil || entry.Method != zip.Store {
			return APKMetadata{}, errors.New("APK native library is not directly loadable")
		}
		body, err := readEntry(entry, maxAPK)
		if err != nil {
			return APKMetadata{}, err
		}
		object, err := elf.NewFile(bytes.NewReader(body))
		if err != nil {
			return APKMetadata{}, errors.New("APK native library is not ELF")
		}
		object.Close()
		machine := elf.EM_X86_64
		if arch == "arm64" {
			machine = elf.EM_AARCH64
		}
		if object.Class != elf.ELFCLASS64 || object.Data != elf.ELFDATA2LSB || object.Type != elf.ET_DYN || object.Machine != machine {
			return APKMetadata{}, errors.New("APK native library architecture mismatch")
		}
		info, err := buildinfo.Read(bytes.NewReader(body))
		if err != nil || info.Main.Path != "github.com/sagernet/sing-box" || info.Path != "github.com/sagernet/sing-box/build/"+arch+"/libbox" {
			return APKMetadata{}, errors.New("APK native library build identity is unavailable")
		}
		settings := map[string]string{}
		for _, setting := range info.Settings {
			settings[setting.Key] = setting.Value
		}
		if settings["GOOS"] != "android" || settings["GOARCH"] != arch || settings["-buildmode"] != "c-shared" || settings["CGO_ENABLED"] != "1" || settings["-trimpath"] != "true" {
			return APKMetadata{}, errors.New("APK native library build coordinates mismatch")
		}
		result.Libraries = append(result.Libraries, NativeLibrary{Arch: arch, Path: entry.Name, Size: len(body), SHA256: fmt.Sprintf("%x", sha256.Sum256(body))})
	}
	return result, nil
}

func VerifyAPK(m Manifest, apk []byte) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if m.Artifact.Size != control.U64(len(apk)) || m.Artifact.Digest != control.ReleaseDigest(apk) {
		return errors.New("APK differs from its signed artifact")
	}
	actual, err := InspectAPK(apk)
	if err != nil {
		return err
	}
	if actual.VersionCode != m.VersionCode || actual.VersionName != m.VersionName || actual.Commit != m.SourceCommit || actual.AARSHA256 != m.AARSHA256 || actual.SingBoxVersion != m.SingBoxVersion {
		return errors.New("APK BuildConfig differs from its signed manifest")
	}
	for index, library := range actual.Libraries {
		if library != m.NativeLibraries[index] {
			return errors.New("APK loaded library differs from its signed manifest")
		}
	}
	return nil
}

func archiveSourceVersion(files map[string]*zip.File) (string, error) {
	entry := files[provenancePath]
	if entry == nil {
		return "", errors.New("Android archive lacks its reviewed source provenance")
	}
	body, err := readEntry(entry, 64<<10)
	if err != nil {
		return "", err
	}
	return clientcomponent.ReviewedSourceVersion(body)
}

func Verify(manifest, signature, apk []byte, key ed25519.PublicKey) (Manifest, error) {
	var m Manifest
	if err := control.DecodeCanonical(manifest, &m, control.ContractDecodeLimits{MaxBytes: 64 << 10, MaxDepth: 12, MaxItems: 1024}); err != nil {
		return m, err
	}
	if len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, append([]byte(signatureDomain), manifest...), signature) {
		return Manifest{}, errors.New("Android application manifest signature is invalid")
	}
	if err := VerifyAPK(m, apk); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (m Manifest) Components() []control.ComponentReadback {
	components := []control.ComponentReadback{}
	for _, library := range m.NativeLibraries {
		components = append(components, control.ComponentReadback{ComponentID: "agent", Platform: "android-" + library.Arch, Version: m.SourceCommit, ArtifactDigest: m.Artifact.Digest})
	}
	for _, library := range m.NativeLibraries {
		components = append(components, control.ComponentReadback{ComponentID: "sing-box", Platform: "android-" + library.Arch, Version: m.SingBoxVersion, ArtifactDigest: "sha256:" + library.SHA256})
	}
	return components
}
