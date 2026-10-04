// Package clientdist builds and verifies the reproducible Linux client archive.
//
// The archive is bootstrap material, not a node configuration bundle. The
// generic service is shipped here; device-specific runtime bytes only arrive
// inside the private certified LKG.
package clientdist

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"path"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"loom/internal/clientcomponent"
	"loom/internal/control"
)

const (
	Schema          = 3
	signatureDomain = "loom-release-manifest-v3"
	maxArchiveBytes = 256 << 20
)

// Component records the exact executable embedded in an archive.
type Component struct {
	Path    string                  `json:"path"`
	SHA256  string                  `json:"sha256"`
	Size    int                     `json:"size"`
	Version string                  `json:"version,omitempty"`
	Commit  string                  `json:"commit,omitempty"`
	Dirty   bool                    `json:"dirty,omitempty"`
	Source  *clientcomponent.Source `json:"source,omitempty"`
}

// File records a deterministic payload file. manifest.json and checksums.txt
// are deliberately outside this list to avoid a self-hash cycle.
type File struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest is the machine-readable boundary between a bootstrap archive and a
// signed per-node configuration bundle.
type Manifest struct {
	Generation        control.U64 `json:"generation"`
	Version           string      `json:"version"`
	Audience          string      `json:"audience"`
	Schema            int         `json:"schema"`
	Kind              string      `json:"kind"`
	OS                string      `json:"os"`
	Arch              string      `json:"arch"`
	Lifecycle         string      `json:"lifecycle"`
	SignatureDomain   string      `json:"signature_domain"`
	PlatformKeySHA256 string      `json:"platform_key_sha256"`
	Loom              Component   `json:"loom"`
	SingBox           Component   `json:"sing_box"`
	Files             []File      `json:"files"`
}

func (m Manifest) Validate() error {
	if m.Schema != Schema || m.Kind != "linux-client-bootstrap" || m.OS != "linux" || (m.Arch != "amd64" && m.Arch != "arm64") || m.Generation == 0 || m.Audience != "public" || m.Lifecycle != "certified-lkg-runtime" || m.SignatureDomain != signatureDomain || !lowerHex(m.PlatformKeySHA256, 64) {
		return fmt.Errorf("Linux manifest coordinates are invalid")
	}
	version := m.Loom.Commit
	if version == "" || m.Loom.Dirty {
		version = "devel"
	}
	if m.Version != version || m.Loom.Commit != "" && !lowerHex(m.Loom.Commit, 40) || m.Loom.Version != "" || m.Loom.Source != nil || m.SingBox.Dirty || m.SingBox.Source == nil || !lowerHex(m.SingBox.Commit, 40) || m.SingBox.Version == "" {
		return fmt.Errorf("Linux manifest component source coordinates are invalid")
	}
	names := payloadNames()
	if len(m.Files) != len(names) {
		return fmt.Errorf("Linux manifest payload set is incomplete")
	}
	for index, file := range m.Files {
		mode := "0644"
		if file.Path == "loom" || file.Path == "sing-box" || file.Path == "install.sh" {
			mode = "0755"
		}
		if file.Path != names[index] || file.Mode != mode || file.Size <= 0 || file.Size > maxArchiveBytes || !lowerHex(file.SHA256, 64) {
			return fmt.Errorf("Linux manifest payload is invalid or not strictly sorted")
		}
		for _, component := range []Component{m.Loom, m.SingBox} {
			if component.Path == file.Path && (component.Size != file.Size || component.SHA256 != file.SHA256) {
				return fmt.Errorf("Linux manifest component differs from its payload record")
			}
		}
	}
	if m.Loom.Path != "loom" || m.SingBox.Path != "sing-box" {
		return fmt.Errorf("Linux manifest component path is invalid")
	}
	return nil
}

func lowerHex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(value) == size && hex.EncodeToString(decoded) == value
}

// BuildInput contains all bytes that affect the output. The builder never
// reads the clock, environment, network, or source paths.
type BuildInput struct {
	Generation  control.U64
	SourceFiles map[string][]byte
	Loom        []byte
	SingBox     []byte
	PrivateKey  ed25519.PrivateKey
	AllowDirty  bool
}

// Artifact contains the exact archive and detached verification material.
type Artifact struct {
	Name      string
	Archive   []byte
	Checksum  []byte
	Signature []byte
	Manifest  Manifest
}

type archiveFile struct {
	path string
	mode int64
	body []byte
}

// Build validates that both executables are real matching Linux binaries and
// emits a byte-for-byte reproducible gzip stream.
func Build(in BuildInput) (Artifact, error) {
	return buildWithInspect(in, inspectSingBox, clientcomponent.LinuxSourceFiles)
}

func buildWithInspect(in BuildInput, inspectSing func([]byte, string) (Component, error), sourceFiles func(map[string][]byte) (map[string][]byte, error)) (Artifact, error) {
	if len(in.PrivateKey) != ed25519.PrivateKeySize {
		return Artifact{}, fmt.Errorf("[§4.3 签名高于传输信任] 平台签名私钥长度是 %d，期望 %d", len(in.PrivateKey), ed25519.PrivateKeySize)
	}
	loom, osName, arch, err := inspectLoom(in.Loom, in.AllowDirty)
	if err != nil {
		return Artifact{}, err
	}
	if in.Generation == 0 {
		return Artifact{}, fmt.Errorf("Linux package generation must be nonzero")
	}
	singBox, err := inspectSing(in.SingBox, arch)
	if err != nil {
		return Artifact{}, err
	}
	publicKey := in.PrivateKey.Public().(ed25519.PublicKey)
	publicBody := append([]byte(base64.StdEncoding.EncodeToString(publicKey)), '\n')

	root := fmt.Sprintf("loom-client-%s-%s", osName, arch)
	files := []archiveFile{
		{path: "README.md", mode: 0o644, body: []byte(readme)},
		{path: "install.sh", mode: 0o755, body: []byte(installScript)},
		{path: "loom", mode: 0o755, body: append([]byte(nil), in.Loom...)},
		{path: "platform.pub", mode: 0o644, body: publicBody},
		{path: "sing-box", mode: 0o755, body: append([]byte(nil), in.SingBox...)},
		{path: "systemd/README.md", mode: 0o644, body: []byte(systemdReadme)},
		{path: "systemd/loom-client.service", mode: 0o644, body: []byte(systemdService)},
	}
	sources, err := sourceFiles(in.SourceFiles)
	if err != nil {
		return Artifact{}, err
	}
	for _, name := range slices.Sorted(maps.Keys(sources)) {
		body := sources[name]
		files = append(files, archiveFile{path: name, mode: 0o644, body: body})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })

	manifest := Manifest{
		Generation: in.Generation, Version: loom.Commit, Audience: "public",
		Schema: Schema, Kind: "linux-client-bootstrap", OS: osName, Arch: arch,
		Lifecycle: "certified-lkg-runtime", SignatureDomain: signatureDomain,
		PlatformKeySHA256: sha256Hex(publicKey), Loom: loom, SingBox: singBox,
	}
	if loom.Commit == "" || loom.Dirty {
		manifest.Version = "devel"
	}
	for _, f := range files {
		manifest.Files = append(manifest.Files, File{
			Path: f.path, Mode: fmt.Sprintf("%04o", f.mode), Size: len(f.body), SHA256: sha256Hex(f.body),
		})
	}
	manifestBody, err := control.CanonicalEncode(manifest)
	if err != nil {
		return Artifact{}, err
	}
	files = append(files, archiveFile{path: "manifest.json", mode: 0o644, body: manifestBody})
	signature := ed25519.Sign(in.PrivateKey, signatureMessage(manifestBody))
	files = append(files, archiveFile{path: "manifest.sig", mode: 0o644, body: signature})
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })

	var checksum strings.Builder
	for _, f := range files {
		fmt.Fprintf(&checksum, "%s  %s\n", sha256Hex(f.body), f.path)
	}
	files = append(files, archiveFile{path: "checksums.txt", mode: 0o644, body: []byte(checksum.String())})
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })

	body, err := buildArchive(root, files)
	if err != nil {
		return Artifact{}, err
	}
	name := root + ".tar.gz"
	hash := sha256Hex(body)
	return Artifact{
		Name: name, Archive: body,
		Checksum:  []byte(fmt.Sprintf("%s  %s\n", hash, name)),
		Signature: signature, Manifest: manifest,
	}, nil
}

func payloadNames() []string {
	names := []string{"README.md", "install.sh", "loom", "platform.pub", "sing-box", "systemd/README.md", "systemd/loom-client.service", "licenses/sing-box-LICENSE", "source/source-provenance.json", "source/domain-cache.patch", "source/prepare-sing-box.py", "source/build-dataplane.sh", "source/BUILD.txt"}
	sort.Strings(names)
	return names
}

func inspectLoom(body []byte, allowDirty bool) (Component, string, string, error) {
	if len(body) == 0 {
		return Component{}, "", "", fmt.Errorf("[§15.4 二进制与配置兼容] Loom 二进制为空")
	}
	elfFile, err := elf.NewFile(bytes.NewReader(body))
	if err != nil {
		return Component{}, "", "", fmt.Errorf("Loom must be a Linux ELF: %w", err)
	}
	defer elfFile.Close()
	bi, err := buildinfo.Read(bytes.NewReader(body))
	if err != nil {
		return Component{}, "", "", fmt.Errorf("[§15.4 二进制与配置兼容] Loom 不是可识别的 Go 二进制:%w", err)
	}
	if bi.Path != "loom/cmd/loom" {
		return Component{}, "", "", fmt.Errorf("[§15.4 二进制与配置兼容] 候选程序入口是 %q，不是 loom/cmd/loom", bi.Path)
	}
	osName, arch, commit, dirty := buildCoordinates(bi)
	if osName != "linux" || (arch != "amd64" && arch != "arm64") || elfArch(elfFile.Machine) != arch {
		return Component{}, "", "", fmt.Errorf("[§10.2 渲染目标必须显式] Loom 平台是 %s/%s，当前只打包 linux/amd64 或 linux/arm64", osName, arch)
	}
	if (commit == "" || dirty) && !allowDirty {
		return Component{}, "", "", fmt.Errorf("[§12 可重现制品] Loom 候选无法追溯到干净 commit；提交后重新构建，或显式使用 -allow-dirty")
	}
	return Component{Path: "loom", SHA256: sha256Hex(body), Size: len(body), Commit: commit, Dirty: dirty}, osName, arch, nil
}

func inspectSingBox(body []byte, wantArch string) (Component, error) {
	source, err := clientcomponent.InspectLinuxSourceBuild(body, wantArch)
	if err != nil {
		return Component{}, err
	}
	return Component{Path: source.Path, SHA256: source.SHA256, Size: source.Size, Version: source.Version, Commit: source.Commit, Source: &source.Source}, nil
}

func buildCoordinates(bi *buildinfo.BuildInfo) (osName, arch, commit string, dirty bool) {
	for _, setting := range bi.Settings {
		switch setting.Key {
		case "GOOS":
			osName = setting.Value
		case "GOARCH":
			arch = setting.Value
		case "vcs.revision":
			commit = setting.Value
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	return
}

func elfArch(machine elf.Machine) string {
	switch machine {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_AARCH64:
		return "arm64"
	default:
		return ""
	}
}

func buildArchive(root string, files []archiveFile) ([]byte, error) {
	var out bytes.Buffer
	gz, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	gz.Header.ModTime = time.Unix(0, 0).UTC()
	gz.Header.OS = 255
	tw := tar.NewWriter(gz)
	epoch := time.Unix(0, 0).UTC()
	dirs := []string{root + "/", root + "/systemd/"}
	for _, name := range dirs {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755, ModTime: epoch, Format: tar.FormatUSTAR}); err != nil {
			return nil, err
		}
	}
	for _, f := range files {
		name := root + "/" + f.path
		if path.Clean(name) != name || strings.Contains(name, "..") {
			return nil, fmt.Errorf("内部制品路径非法:%q", name)
		}
		h := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: f.mode, Size: int64(len(f.body)), ModTime: epoch, Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func signatureMessage(manifest []byte) []byte {
	return append([]byte(signatureDomain+"\x00"), manifest...)
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Verify checks the detached checksum/signature and every payload hash. pub is
// a separately trusted key; a platform.pub extracted from the same unverified
// archive is not a trust root.
func Verify(archive, checksum, signature []byte, pub ed25519.PublicKey) (Manifest, error) {
	return verifyWithInspect(archive, checksum, signature, pub, inspectSingBox, clientcomponent.LinuxSourceFiles)
}

func verifyWithInspect(archive, checksum, signature []byte, pub ed25519.PublicKey, inspectSing func([]byte, string) (Component, error), sourceFiles func(map[string][]byte) (map[string][]byte, error)) (Manifest, error) {
	var zero Manifest
	if len(archive) == 0 || len(archive) > maxArchiveBytes || len(signature) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		return zero, fmt.Errorf("Linux package or signature bounds are invalid")
	}
	manifest, err := verifyArchive(archive, signature, pub, inspectSing, sourceFiles)
	if err != nil {
		return zero, err
	}
	expected := fmt.Sprintf("%s  loom-client-linux-%s.tar.gz\n", sha256Hex(archive), manifest.Arch)
	if !bytes.Equal(checksum, []byte(expected)) {
		return zero, fmt.Errorf("Linux archive checksum is not canonical or differs")
	}
	return manifest, nil
}

func verifyArchive(body, signature []byte, pub ed25519.PublicKey, inspectSing func([]byte, string) (Component, error), sourceFiles func(map[string][]byte) (map[string][]byte, error)) (Manifest, error) {
	var zero Manifest
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("解压客户端包:%w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	modes := map[string]int64{}
	root := ""
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return zero, fmt.Errorf("读客户端包:%w", err)
		}
		clean := path.Clean(h.Name)
		if clean == "." || clean != strings.TrimSuffix(h.Name, "/") || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
			return zero, fmt.Errorf("[§10.3 原子安装] 客户端包含非法路径 %q", h.Name)
		}
		parts := strings.Split(clean, "/")
		if root == "" {
			root = parts[0]
		}
		if parts[0] != root || !strings.HasPrefix(root, "loom-client-linux-") {
			return zero, fmt.Errorf("[§10.2 渲染目标必须显式] 客户端包根目录 %q 无效", parts[0])
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg || len(parts) < 2 {
			return zero, fmt.Errorf("[§10.3 原子安装] 客户端包不允许链接或特殊文件 %q", h.Name)
		}
		rel := strings.Join(parts[1:], "/")
		if _, exists := files[rel]; exists {
			return zero, fmt.Errorf("客户端包文件 %q 重复", rel)
		}
		if h.Size < 0 || h.Size > maxArchiveBytes || total+h.Size > maxArchiveBytes {
			return zero, fmt.Errorf("客户端包解压大小超出边界")
		}
		content, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(content)) != h.Size {
			return zero, fmt.Errorf("读客户端包文件 %q 失败", rel)
		}
		total += h.Size
		files[rel], modes[rel] = content, h.Mode&0o777
	}
	required := payloadNames()
	required = append(required, "checksums.txt", "manifest.json", "manifest.sig")
	if len(files) != len(required) {
		return zero, fmt.Errorf("客户端包文件数是 %d，期望 %d", len(files), len(required))
	}
	for _, name := range required {
		if _, ok := files[name]; !ok {
			return zero, fmt.Errorf("客户端包缺少 %s", name)
		}
	}
	var manifest Manifest
	if err := control.DecodeCanonical(files["manifest.json"], &manifest, control.ContractDecodeLimits{MaxBytes: 64 << 10, MaxDepth: 12, MaxItems: 2048}); err != nil {
		return zero, fmt.Errorf("invalid canonical Linux manifest: %w", err)
	}
	if manifest.Schema != Schema || manifest.Kind != "linux-client-bootstrap" || manifest.OS != "linux" || manifest.SignatureDomain != signatureDomain || manifest.Lifecycle != "certified-lkg-runtime" || manifest.Generation == 0 || manifest.Audience != "public" || (manifest.Arch != "amd64" && manifest.Arch != "arm64") {
		return zero, fmt.Errorf("Linux manifest semantics are invalid")
	}
	if !bytes.Equal(signature, files["manifest.sig"]) || !ed25519.Verify(pub, signatureMessage(files["manifest.json"]), signature) {
		return zero, fmt.Errorf("Linux manifest signature is invalid")
	}
	if root != "loom-client-linux-"+manifest.Arch {
		return zero, fmt.Errorf("manifest 架构 %q 与目录 %q 不一致", manifest.Arch, root)
	}
	decodedPub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(files["platform.pub"])))
	if err != nil || !bytes.Equal(decodedPub, pub) || manifest.PlatformKeySHA256 != sha256Hex(pub) {
		return zero, fmt.Errorf("[§4.3 签名高于传输信任] 包内平台公钥与带外可信公钥不一致")
	}
	seen := map[string]bool{}
	for index, f := range manifest.Files {
		if index >= len(payloadNames()) || f.Path != payloadNames()[index] {
			return zero, fmt.Errorf("Linux manifest payload order or membership is invalid")
		}
		content, ok := files[f.Path]
		if !ok || seen[f.Path] || f.Size != len(content) || f.SHA256 != sha256Hex(content) || f.Mode != fmt.Sprintf("%04o", modes[f.Path]) {
			return zero, fmt.Errorf("manifest 中的文件 %q 与实际内容不一致", f.Path)
		}
		seen[f.Path] = true
	}
	if len(seen) != len(required)-3 {
		return zero, fmt.Errorf("manifest 文件清单不完整")
	}
	if err := verifyChecksums(files); err != nil {
		return zero, err
	}
	loom, osName, arch, err := inspectLoom(files["loom"], true)
	if err != nil || osName != manifest.OS || arch != manifest.Arch || !reflect.DeepEqual(loom, manifest.Loom) {
		return zero, fmt.Errorf("包内 Loom 身份与 manifest 不一致:%v", err)
	}
	singBox, err := inspectSing(files["sing-box"], manifest.Arch)
	if err != nil || !reflect.DeepEqual(singBox, manifest.SingBox) {
		return zero, fmt.Errorf("包内 sing-box 身份与 manifest 不一致:%v", err)
	}
	version := loom.Commit
	if loom.Commit == "" || loom.Dirty {
		version = "devel"
	}
	if manifest.Version != version {
		return zero, fmt.Errorf("Linux package version differs from Loom source coordinates")
	}
	sourceInputs := map[string][]byte{"LICENSE": files["licenses/sing-box-LICENSE"]}
	for _, name := range []string{"source-provenance.json", "domain-cache.patch", "prepare-sing-box.py", "build-dataplane.sh"} {
		sourceInputs[name] = files["source/"+name]
	}
	sources, err := sourceFiles(sourceInputs)
	if err != nil {
		return zero, err
	}
	for _, name := range slices.Sorted(maps.Keys(sources)) {
		expected := sources[name]
		if !bytes.Equal(files[name], expected) {
			return zero, fmt.Errorf("Linux package source payload differs: %s", name)
		}
	}
	payload := make([]archiveFile, 0, len(files))
	for _, name := range slices.Sorted(maps.Keys(files)) {
		content := files[name]
		wantMode := int64(0o644)
		if name == "loom" || name == "sing-box" || name == "install.sh" {
			wantMode = 0o755
		}
		if modes[name] != wantMode {
			return zero, fmt.Errorf("Linux package file mode differs: %s", name)
		}
		payload = append(payload, archiveFile{path: name, mode: wantMode, body: content})
	}
	sort.Slice(payload, func(i, j int) bool { return payload[i].path < payload[j].path })
	canonical, err := buildArchive(root, payload)
	if err != nil || !bytes.Equal(canonical, body) {
		return zero, fmt.Errorf("Linux archive is not canonical")
	}
	return manifest, nil
}

func verifyChecksums(files map[string][]byte) error {
	names := make([]string, 0, len(files)-1)
	for name := range files {
		if name != "checksums.txt" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var expected strings.Builder
	for _, name := range names {
		fmt.Fprintf(&expected, "%s  %s\n", sha256Hex(files[name]), name)
	}
	if !bytes.Equal(files["checksums.txt"], []byte(expected.String())) {
		return fmt.Errorf("checksums.txt is incomplete or not canonical")
	}
	return nil
}

const readme = `# Loom Linux client

This archive is a signed bootstrap package for Linux Server. It contains real
Loom and sing-box executables, an installer, and a manifest. It does not contain
a node's data-plane secrets or generic copies of node-specific systemd units.

Verify the archive before extraction with a platform public key obtained through
a separate trusted channel:

    loom client verify -archive loom-client-linux-amd64.tar.gz -pubkey /trusted/platform-signing.pub

Install and consume the downloaded invitation file without putting its bearer
token in shell history:

    tar -xzf loom-client-linux-amd64.tar.gz
    cd loom-client-linux-amd64
    sudo ./install.sh --invite-file ../client.loom-invite

The installer creates one Ed25519 device identity, completes private
Enrollment, validates the certified RuntimeProfile with the packaged sing-box,
and starts loom-client.service. The service derives candidates from the full
LKG, applies the shared Direct/Auto/fixed-exit selector, reads the actual
selector back, and submits signed observations through the private device
channel. It never uses the public website for device config or reports.
`

const systemdReadme = `# systemd lifecycle boundary

loom-client.service is the only Linux client runtime unit. It owns the packaged
sing-box process and projects its ephemeral config from the certified LKG on
every start. Preference and bounded observations are the only additional local
persistent values; actual Selection is always selector readback under /run.
`

const systemdService = `[Unit]
Description=Loom certified Linux client runtime
Documentation=file:/opt/loom/docs/clients/client-runtime-model.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/var/lib/loom-device
ExecStartPre=/usr/bin/rm -f /run/loom-client/status.json
ExecStart=/usr/local/lib/loom-client/current/loom client run -capture tun
ExecReload=/bin/kill -HUP $MAINPID
Restart=no
TimeoutStopSec=20s
KillMode=mixed
UMask=0077
RuntimeDirectory=loom-client
RuntimeDirectoryMode=0700
StateDirectory=loom-device
StateDirectoryMode=0700
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
# Runtime configuration is disposable; authenticated identity stays in the
# protected device directory. TUN still requires an isolated network namespace.
ReadWritePaths=/var/lib/loom-device /run/loom-client
DeviceAllow=/dev/net/tun rw
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes

[Install]
WantedBy=multi-user.target
`

const installScript = `#!/bin/sh
set -eu

usage() {
    echo "usage: sudo ./install.sh --invite-file PATH [--state PATH]" >&2
    echo "       sudo ./install.sh --upgrade [--state PATH]" >&2
    echo "       sudo ./install.sh --no-enroll" >&2
    exit 2
}

invite_file=
state=/var/lib/loom-device/state.json
no_enroll=0
upgrade=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --invite-file) [ "$#" -ge 2 ] || usage; invite_file=$2; shift 2 ;;
        --state) [ "$#" -ge 2 ] || usage; state=$2; shift 2 ;;
        --no-enroll) no_enroll=1; shift ;;
        --upgrade) upgrade=1; shift ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "install.sh must run as root" >&2; exit 1; }
modes=$no_enroll
[ "$upgrade" -eq 0 ] || modes=$((modes + 1))
[ -z "$invite_file" ] || modes=$((modes + 1))
[ "$modes" -eq 1 ] || usage

base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
(cd "$base" && sha256sum -c checksums.txt)
for file in loom sing-box platform.pub manifest.json systemd/loom-client.service; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || {
        echo "unsafe or missing package file: $file" >&2
        exit 1
    }
done

if [ -e /etc/loom/trust/platform.pub ] && ! cmp -s "$base/platform.pub" /etc/loom/trust/platform.pub; then
    echo "existing platform trust cannot be replaced by an installer" >&2
    exit 1
fi
if [ "$no_enroll" -eq 0 ]; then
    for protected_path in /var/lib/loom-device/migration-overlay.json /var/lib/loom/client-v2 /etc/loom/agent/v2 /etc/loom/sing-box/v2 /etc/systemd/system/loom-client.service.d/00-host-network-quarantine.conf; do
        if [ -e "$protected_path" ] || [ -L "$protected_path" ]; then
            echo "protected prior deployment requires a verified forward cutover before activation" >&2
            exit 1
        fi
    done
    for old in loom-client-v2.service loom-client-v2-agent.service loom-client-v2-sing-box.service loom-client-v2-report.service; do
        if [ "$(systemctl show "$old" --property=LoadState --value)" != "not-found" ]; then
            echo "prior runtime entry remains; verified cutover must remove it before activation" >&2
            exit 1
        fi
    done
fi

install -d -m 0755 /usr/local/bin /usr/local/lib/loom-client/releases /etc/loom/trust
install -d -m 0700 "$(dirname -- "$state")" /var/lib/loom-device

install_atomic() {
    src=$1
    dst=$2
    mode=$3
    tmp=$(mktemp "${dst}.tmp.XXXXXX")
    trap 'rm -f "$tmp"' EXIT HUP INT TERM
    install -m "$mode" "$src" "$tmp"
    mv -f "$tmp" "$dst"
    trap - EXIT HUP INT TERM
}

install_atomic "$base/platform.pub" /etc/loom/trust/platform.pub 0644

verify_release() {
    for release_file in loom sing-box manifest.json; do
        release_mode=755
        [ "$release_file" != manifest.json ] || release_mode=644
        [ -f "$release/$release_file" ] && [ ! -L "$release/$release_file" ] &&
            [ "$(stat -c '%u:%h:%a' "$release/$release_file")" = "0:1:$release_mode" ] &&
            cmp -s "$base/$release_file" "$release/$release_file" || {
                echo "existing release payload differs from the verified package" >&2
                return 1
            }
    done
}

release_id=$(sha256sum "$base/manifest.json" | cut -d' ' -f1)
release=/usr/local/lib/loom-client/releases/$release_id
[ ! -L "$release" ] || {
    echo "existing release directory must not be a symlink" >&2
    exit 1
}
if [ ! -d "$release" ]; then
    staging=$(mktemp -d /usr/local/lib/loom-client/releases/.staging.XXXXXX)
    trap 'rm -rf "$staging"' EXIT HUP INT TERM
    install -m 0755 "$base/loom" "$staging/loom"
    install -m 0755 "$base/sing-box" "$staging/sing-box"
    install -m 0644 "$base/manifest.json" "$staging/manifest.json"
    mv "$staging" "$release"
    trap - EXIT HUP INT TERM
fi
verify_release

if [ "$no_enroll" -eq 1 ]; then
    echo "Installed the verified release without binding a Device or starting a service."
    exit 0
fi

if [ "$upgrade" -eq 0 ]; then
    "$release/loom" client enroll -invite-file "$invite_file" -state "$state" -wait 5m
fi
"$release/loom" client preflight -state "$state" -sing-box "$release/sing-box" -capture tun

unit=/etc/systemd/system/loom-client.service
unit_backup=
if [ -f "$unit" ]; then
    unit_backup=$(mktemp /etc/systemd/system/.loom-client.service.XXXXXX)
    cp -p "$unit" "$unit_backup"
fi
previous=
if [ -L /usr/local/lib/loom-client/current ]; then
    previous=$(readlink /usr/local/lib/loom-client/current)
fi

link_tmp=/usr/local/lib/loom-client/.current.$$
ready=0
activation_ok=1
if ! ln -s "$release" "$link_tmp" || ! mv -Tf "$link_tmp" /usr/local/lib/loom-client/current; then
    activation_ok=0
    rm -f "$link_tmp"
fi
if ! install_atomic "$base/systemd/loom-client.service" "$unit" 0644; then activation_ok=0; fi
if ! systemctl daemon-reload; then activation_ok=0; fi
if ! systemctl enable loom-client.service >/dev/null; then activation_ok=0; fi
if [ "$activation_ok" -eq 1 ] && ! systemctl restart loom-client.service; then activation_ok=0; fi

if [ "$activation_ok" -eq 1 ]; then
    attempt=0
    while [ "$attempt" -lt 30 ]; do
        if systemctl is-active --quiet loom-client.service && "$release/loom" client status >/dev/null 2>&1; then
            ready=1
            break
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
fi

if [ "$ready" -ne 1 ]; then
    systemctl disable --now loom-client.service >/dev/null 2>&1 || true
    if [ -n "$previous" ]; then
        rollback_tmp=/usr/local/lib/loom-client/.current.rollback.$$
        ln -s "$previous" "$rollback_tmp"
        mv -Tf "$rollback_tmp" /usr/local/lib/loom-client/current
    else
        rm -f /usr/local/lib/loom-client/current
    fi
    if [ -n "$unit_backup" ]; then
        mv -f "$unit_backup" "$unit"
        unit_backup=
    else
        rm -f "$unit"
    fi
    systemctl daemon-reload
    # Restoring files does not prove that an old unit is isolated or that its
    # runtime still satisfies the newly accepted authorization. Keep execution
    # disabled; identity, LKG and floor are never rolled back with the package.
    echo "new runtime failed readback; package files restored, services remain disabled; certified configuration and floor retained" >&2
    exit 1
fi

[ -z "$unit_backup" ] || rm -f "$unit_backup"
cli_tmp=/usr/local/bin/.loom.$$
ln -s /usr/local/lib/loom-client/current/loom "$cli_tmp"
mv -Tf "$cli_tmp" /usr/local/bin/loom

echo "Loom Linux client is enrolled, running, and confirmed by selector readback."
`
