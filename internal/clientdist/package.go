// Package clientdist builds and verifies the reproducible Linux client archive.
//
// The archive is bootstrap material, not a node configuration bundle.  Exact
// systemd units and data-plane secrets still arrive through the signed pull
// transaction described by design.md §14.2.
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
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	Schema          = 1
	signatureDomain = "loom:linux-client-package:v1"
	maxArchiveBytes = 256 << 20
)

// Component records the exact executable embedded in an archive.
type Component struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Size    int    `json:"size"`
	Version string `json:"version,omitempty"`
	Commit  string `json:"commit,omitempty"`
	Dirty   bool   `json:"dirty,omitempty"`
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
	Schema            int       `json:"schema"`
	Kind              string    `json:"kind"`
	OS                string    `json:"os"`
	Arch              string    `json:"arch"`
	Lifecycle         string    `json:"lifecycle"`
	SignatureDomain   string    `json:"signature_domain"`
	PlatformKeySHA256 string    `json:"platform_key_sha256"`
	Loom              Component `json:"loom"`
	SingBox           Component `json:"sing_box"`
	Files             []File    `json:"files"`
}

// BuildInput contains all bytes that affect the output. The builder never
// reads the clock, environment, network, or source paths (design.md §12).
type BuildInput struct {
	Loom       []byte
	SingBox    []byte
	PrivateKey ed25519.PrivateKey
	AllowDirty bool
}

// Artifact contains the exact archive and detached verification material.
type Artifact struct {
	Name      string
	Archive   []byte
	Checksum  []byte
	Signature []byte
	Manifest  Manifest
}

type signatureEnvelope struct {
	Schema    int    `json:"schema"`
	Algorithm string `json:"algorithm"`
	Domain    string `json:"domain"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
}

type archiveFile struct {
	path string
	mode int64
	body []byte
}

// Build validates that both executables are real matching Linux binaries and
// emits a byte-for-byte reproducible gzip stream.
func Build(in BuildInput) (Artifact, error) {
	if len(in.PrivateKey) != ed25519.PrivateKeySize {
		return Artifact{}, fmt.Errorf("[§4.3 签名高于传输信任] 平台签名私钥长度是 %d，期望 %d", len(in.PrivateKey), ed25519.PrivateKeySize)
	}
	loom, osName, arch, err := inspectLoom(in.Loom, in.AllowDirty)
	if err != nil {
		return Artifact{}, err
	}
	singBox, err := inspectSingBox(in.SingBox, arch)
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
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })

	manifest := Manifest{
		Schema: Schema, Kind: "linux-client-bootstrap", OS: osName, Arch: arch,
		Lifecycle: "signed-node-bundle", SignatureDomain: signatureDomain,
		PlatformKeySHA256: sha256Hex(publicKey), Loom: loom, SingBox: singBox,
	}
	for _, f := range files {
		manifest.Files = append(manifest.Files, File{
			Path: f.path, Mode: fmt.Sprintf("%04o", f.mode), Size: len(f.body), SHA256: sha256Hex(f.body),
		})
	}
	manifestBody, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Artifact{}, err
	}
	manifestBody = append(manifestBody, '\n')
	files = append(files, archiveFile{path: "manifest.json", mode: 0o644, body: manifestBody})
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
	signed := signatureMessage(hash)
	sig := ed25519.Sign(in.PrivateKey, signed)
	envelopeBody, err := json.MarshalIndent(signatureEnvelope{
		Schema: Schema, Algorithm: "ed25519", Domain: signatureDomain,
		SHA256: hash, Signature: base64.StdEncoding.EncodeToString(sig),
	}, "", "  ")
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{
		Name: name, Archive: body,
		Checksum:  []byte(fmt.Sprintf("%s  %s\n", hash, name)),
		Signature: append(envelopeBody, '\n'), Manifest: manifest,
	}, nil
}

func inspectLoom(body []byte, allowDirty bool) (Component, string, string, error) {
	if len(body) == 0 {
		return Component{}, "", "", fmt.Errorf("[§15.4 二进制与配置兼容] Loom 二进制为空")
	}
	bi, err := buildinfo.Read(bytes.NewReader(body))
	if err != nil {
		return Component{}, "", "", fmt.Errorf("[§15.4 二进制与配置兼容] Loom 不是可识别的 Go 二进制:%w", err)
	}
	if bi.Path != "loom/cmd/loom" {
		return Component{}, "", "", fmt.Errorf("[§15.4 二进制与配置兼容] 候选程序入口是 %q，不是 loom/cmd/loom", bi.Path)
	}
	osName, arch, commit, dirty := buildCoordinates(bi)
	if osName != "linux" || (arch != "amd64" && arch != "arm64") {
		return Component{}, "", "", fmt.Errorf("[§10.2 渲染目标必须显式] Loom 平台是 %s/%s，当前只打包 linux/amd64 或 linux/arm64", osName, arch)
	}
	if (commit == "" || dirty) && !allowDirty {
		return Component{}, "", "", fmt.Errorf("[§12 可重现制品] Loom 候选无法追溯到干净 commit；提交后重新构建，或显式使用 -allow-dirty")
	}
	return Component{Path: "loom", SHA256: sha256Hex(body), Size: len(body), Commit: commit, Dirty: dirty}, osName, arch, nil
}

func inspectSingBox(body []byte, wantArch string) (Component, error) {
	if len(body) == 0 {
		return Component{}, fmt.Errorf("[§4.1 数据平面只有一个实现] sing-box 二进制为空")
	}
	ef, err := elf.NewFile(bytes.NewReader(body))
	if err != nil {
		return Component{}, fmt.Errorf("[§4.1 数据平面只有一个实现] sing-box 不是 Linux ELF 二进制:%w", err)
	}
	arch := elfArch(ef.Machine)
	if arch == "" || arch != wantArch {
		return Component{}, fmt.Errorf("[§10.2 渲染目标必须显式] sing-box 架构是 %q，Loom 架构是 %q", arch, wantArch)
	}
	bi, err := buildinfo.Read(bytes.NewReader(body))
	if err != nil {
		return Component{}, fmt.Errorf("[§4.1 数据平面只有一个实现] 读不出 sing-box 构建身份:%w", err)
	}
	if bi.Path != "github.com/sagernet/sing-box/cmd/sing-box" || bi.Main.Path != "github.com/sagernet/sing-box" {
		return Component{}, fmt.Errorf("[§4.1 数据平面只有一个实现] 数据平面候选是 %q(%q)，不是真实 sing-box", bi.Path, bi.Main.Path)
	}
	if bi.Main.Version == "" || bi.Main.Version == "(devel)" {
		return Component{}, fmt.Errorf("[§12 可重现制品] sing-box 没有可追溯的固定版本")
	}
	return Component{Path: "sing-box", SHA256: sha256Hex(body), Size: len(body), Version: bi.Main.Version}, nil
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

func signatureMessage(hash string) []byte {
	return []byte(signatureDomain + "\n" + hash + "\n")
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Verify checks the detached checksum/signature and every payload hash. pub is
// a separately trusted key; a platform.pub extracted from the same unverified
// archive is not a trust root.
func Verify(archive, checksum, signature []byte, pub ed25519.PublicKey) (Manifest, error) {
	var zero Manifest
	if len(archive) == 0 || len(archive) > maxArchiveBytes {
		return zero, fmt.Errorf("[§4.3 签名高于传输信任] 客户端包大小 %d 超出边界", len(archive))
	}
	hash := sha256Hex(archive)
	fields := strings.Fields(string(checksum))
	if len(fields) != 2 || fields[0] != hash || !strings.HasSuffix(fields[1], ".tar.gz") {
		return zero, fmt.Errorf("[§4.3 签名高于传输信任] 客户端包 SHA-256 校验不一致")
	}
	if len(pub) != ed25519.PublicKeySize {
		return zero, fmt.Errorf("[§4.3 签名高于传输信任] 可信公钥长度无效")
	}
	var envelope signatureEnvelope
	dec := json.NewDecoder(bytes.NewReader(signature))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&envelope); err != nil {
		return zero, fmt.Errorf("解析客户端包签名:%w", err)
	}
	if dec.Decode(&struct{}{}) != io.EOF || envelope.Schema != Schema || envelope.Algorithm != "ed25519" || envelope.Domain != signatureDomain || envelope.SHA256 != hash {
		return zero, fmt.Errorf("[§4.3 签名高于传输信任] 客户端包签名封装无效")
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(pub, signatureMessage(hash), sig) {
		return zero, fmt.Errorf("[§4.3 签名高于传输信任] 客户端包 Ed25519 签名无效")
	}
	return verifyArchive(archive, pub)
}

func verifyArchive(body []byte, pub ed25519.PublicKey) (Manifest, error) {
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
	required := []string{"README.md", "checksums.txt", "install.sh", "loom", "manifest.json", "platform.pub", "sing-box", "systemd/README.md"}
	if len(files) != len(required) {
		return zero, fmt.Errorf("客户端包文件数是 %d，期望 %d", len(files), len(required))
	}
	for _, name := range required {
		if _, ok := files[name]; !ok {
			return zero, fmt.Errorf("客户端包缺少 %s", name)
		}
	}
	var manifest Manifest
	dec := json.NewDecoder(bytes.NewReader(files["manifest.json"]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		return zero, fmt.Errorf("解析 manifest.json 失败:%v", err)
	}
	if manifest.Schema != Schema || manifest.Kind != "linux-client-bootstrap" || manifest.OS != "linux" || manifest.SignatureDomain != signatureDomain || manifest.Lifecycle != "signed-node-bundle" {
		return zero, fmt.Errorf("[§10.2 渲染目标必须显式] manifest 语义无效")
	}
	if root != "loom-client-linux-"+manifest.Arch {
		return zero, fmt.Errorf("manifest 架构 %q 与目录 %q 不一致", manifest.Arch, root)
	}
	decodedPub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(files["platform.pub"])))
	if err != nil || !bytes.Equal(decodedPub, pub) || manifest.PlatformKeySHA256 != sha256Hex(pub) {
		return zero, fmt.Errorf("[§4.3 签名高于传输信任] 包内平台公钥与带外可信公钥不一致")
	}
	seen := map[string]bool{}
	for _, f := range manifest.Files {
		content, ok := files[f.Path]
		if !ok || seen[f.Path] || f.Size != len(content) || f.SHA256 != sha256Hex(content) || f.Mode != fmt.Sprintf("%04o", modes[f.Path]) {
			return zero, fmt.Errorf("manifest 中的文件 %q 与实际内容不一致", f.Path)
		}
		seen[f.Path] = true
	}
	if len(seen) != len(required)-2 {
		return zero, fmt.Errorf("manifest 文件清单不完整")
	}
	if err := verifyChecksums(files); err != nil {
		return zero, err
	}
	loom, osName, arch, err := inspectLoom(files["loom"], true)
	if err != nil || osName != manifest.OS || arch != manifest.Arch || loom != manifest.Loom {
		return zero, fmt.Errorf("包内 Loom 身份与 manifest 不一致:%v", err)
	}
	singBox, err := inspectSingBox(files["sing-box"], manifest.Arch)
	if err != nil || singBox != manifest.SingBox {
		return zero, fmt.Errorf("包内 sing-box 身份与 manifest 不一致:%v", err)
	}
	return manifest, nil
}

func verifyChecksums(files map[string][]byte) error {
	lines := strings.Split(strings.TrimSpace(string(files["checksums.txt"])), "\n")
	if len(lines) != len(files)-1 {
		return fmt.Errorf("checksums.txt 条目数不完整")
	}
	seen := map[string]bool{}
	for _, line := range lines {
		parts := strings.Split(line, "  ")
		if len(parts) != 2 || parts[1] == "checksums.txt" || seen[parts[1]] {
			return fmt.Errorf("checksums.txt 条目无效")
		}
		body, ok := files[parts[1]]
		if !ok || parts[0] != sha256Hex(body) {
			return fmt.Errorf("checksums.txt 中 %q 的校验值不一致", parts[1])
		}
		seen[parts[1]] = true
	}
	return nil
}

const readme = `# Loom Linux Server client

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

If the invitation pins a forwarding/server purpose, declare the real public
endpoint before running the installer:

    sudo install -d -m 0755 /etc/loom
    sudoedit /etc/loom/device.yaml

    server:
      public_endpoint: edge.example.net
      inbound_port: 61698
      direction: bidirectional

This is the server's reachability declaration, not a client route selection.
Enrollment creates or reuses /etc/wireguard/node.key locally, sends only its
public key, and installs wireguard-tools through a supported package manager
before consuming the invitation when the tools are absent.

The installer registers a locally generated P-256 CSR identity (the private key
never leaves the machine), installs
the bootstrap response, and starts the first signed pull when the control plane
returned a complete provisioning envelope. It never changes global proxy
environment variables.
`

const systemdReadme = `# systemd lifecycle boundary

The exact sing-box, pull, Agent, and reporter units depend on the enrolled node
ID and its signed configuration. They are intentionally not generic files in
this bootstrap archive. A successful first signed pull installs the units from
the node-bound bundle and uses the existing transactional apply/rollback path.

If enrollment returns no complete provisioning envelope, no service is enabled
or started. That state is provisioning, not online.
`

const installScript = `#!/bin/sh
set -eu

usage() {
    echo "usage: sudo ./install.sh --invite-file PATH [--state-dir PATH]" >&2
    echo "       sudo ./install.sh --no-enroll" >&2
    exit 2
}

invite_file=
state_dir=/etc/loom/client
no_enroll=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --invite-file) [ "$#" -ge 2 ] || usage; invite_file=$2; shift 2 ;;
        --state-dir) [ "$#" -ge 2 ] || usage; state_dir=$2; shift 2 ;;
        --no-enroll) no_enroll=1; shift ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "install.sh must run as root" >&2; exit 1; }
[ "$no_enroll" -eq 1 ] || [ -n "$invite_file" ] || usage
[ "$no_enroll" -eq 0 ] || [ -z "$invite_file" ] || usage

base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
(cd "$base" && sha256sum -c checksums.txt)
for file in loom sing-box platform.pub; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || {
        echo "unsafe or missing package file: $file" >&2
        exit 1
    }
done

install -d -m 0755 /usr/local/bin /etc/loom/trust
install -d -m 0700 /etc/loom/secrets "$state_dir" /var/lib/loom

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

install_atomic "$base/loom" /usr/local/bin/loom 0755
install_atomic "$base/sing-box" /usr/local/bin/sing-box 0755
install_atomic "$base/platform.pub" /etc/loom/trust/platform.pub 0644

if [ "$no_enroll" -eq 1 ]; then
    echo "Installed binaries only; no identity was registered and no service was started."
    exit 0
fi

/usr/local/bin/loom client enroll -invite-file "$invite_file" -state-dir "$state_dir"
`
