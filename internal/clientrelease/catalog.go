// Package clientrelease 管理跨平台客户端制品及其平台签名目录。
package clientrelease

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"loom/internal/clientdist"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const domain = "loom-client-releases-v1\n"

var safeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type File struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Artifact struct {
	File
	Filename     string `json:"filename"`
	Title        string `json:"title"`
	Platform     string `json:"platform"`
	Arch         string `json:"arch"`
	Variant      string `json:"variant"`
	Version      string `json:"version"`
	SourceCommit string `json:"source_commit"`
	Signing      string `json:"signing"`
	Checksum     File   `json:"checksum"`
	Signature    File   `json:"signature"`
	SBOM         *File  `json:"sbom,omitempty"`
}
type Catalog struct {
	Schema    int        `json:"schema"`
	Artifacts []Artifact `json:"artifacts"`
}
type Input struct {
	Path         string `json:"path"`
	SBOMPath     string `json:"sbom_path,omitempty"`
	Title        string `json:"title"`
	Platform     string `json:"platform"`
	Arch         string `json:"arch"`
	Variant      string `json:"variant"`
	Version      string `json:"version"`
	SourceCommit string `json:"source_commit"`
	Signing      string `json:"signing"`
}

func PrivateKey(path string) (ed25519.PrivateKey, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	key, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if e != nil || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("平台私钥格式无效")
	}
	return ed25519.PrivateKey(key), nil
}
func PublicKey(path string) (ed25519.PublicKey, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	key, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if e != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("平台公钥格式无效")
	}
	return ed25519.PublicKey(key), nil
}
func digest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
func put(root, name string, body []byte) (File, error) {
	if !safeName.MatchString(name) {
		return File{}, fmt.Errorf("制品文件名无效")
	}
	hash := digest(body)
	relative := filepath.ToSlash(filepath.Join("bin", hash))
	dir := filepath.Join(root, "bin")
	if e := os.MkdirAll(dir, 0755); e != nil {
		return File{}, e
	}
	destination := filepath.Join(root, relative)
	if existing, e := os.ReadFile(destination); e == nil {
		if digest(existing) != hash {
			return File{}, fmt.Errorf("不可变制品内容发生变化")
		}
	} else {
		tmp, e := os.CreateTemp(dir, ".artifact-")
		if e != nil {
			return File{}, e
		}
		defer os.Remove(tmp.Name())
		if _, e = tmp.Write(body); e == nil {
			e = tmp.Chmod(0644)
		}
		if e == nil {
			e = tmp.Sync()
		}
		closeErr := tmp.Close()
		if e == nil {
			e = closeErr
		}
		if e != nil {
			return File{}, e
		}
		if e = os.Rename(tmp.Name(), destination); e != nil {
			return File{}, e
		}
	}
	return File{Name: name, Path: relative, SHA256: hash, Size: int64(len(body))}, nil
}
func Build(root string, inputs []Input, key ed25519.PrivateKey) (Catalog, error) {
	result := Catalog{Schema: 1}
	if len(key) != ed25519.PrivateKeySize {
		return result, fmt.Errorf("平台签名私钥不可用")
	}
	if len(inputs) == 0 {
		return result, fmt.Errorf("至少需要一个真实制品")
	}
	for _, input := range inputs {
		if !commitPattern.MatchString(input.SourceCommit) || input.Version == "" || input.Signing == "" {
			return result, fmt.Errorf("制品缺少源码、版本或签名说明")
		}
		switch input.Platform {
		case "linux-server", "android", "windows-desktop":
		default:
			return result, fmt.Errorf("制品平台无效")
		}
		body, e := os.ReadFile(input.Path)
		if e != nil {
			return result, e
		}
		if len(body) == 0 {
			return result, fmt.Errorf("制品为空")
		}
		name := filepath.Base(input.Path)
		file, e := put(root, name, body)
		if e != nil {
			return result, e
		}
		checksum, e := put(root, name+".sha256", []byte(file.SHA256+"  "+name+"\n"))
		if e != nil {
			return result, e
		}
		signatureBody := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(domain+file.SHA256))) + "\n")
		if input.Platform == "linux-server" {
			signatureBody, e = os.ReadFile(input.Path + ".sig")
			if e != nil {
				return result, e
			}
			checksumBody, e := os.ReadFile(input.Path + ".sha256")
			if e != nil {
				return result, e
			}
			manifest, e := clientdist.Verify(body, checksumBody, signatureBody, key.Public().(ed25519.PublicKey))
			if e != nil {
				return result, e
			}
			if manifest.Arch != input.Arch || manifest.Loom.Commit != input.SourceCommit {
				return result, fmt.Errorf("Linux 制品元数据与输入不一致")
			}
		}
		signature, e := put(root, name+".sig", signatureBody)
		if e != nil {
			return result, e
		}
		a := Artifact{File: file, Filename: name, Title: input.Title, Platform: input.Platform, Arch: input.Arch, Variant: input.Variant, Version: input.Version, SourceCommit: input.SourceCommit, Signing: input.Signing, Checksum: checksum, Signature: signature}
		if input.SBOMPath != "" {
			body, e = os.ReadFile(input.SBOMPath)
			if e != nil {
				return result, e
			}
			sbom, e := put(root, filepath.Base(input.SBOMPath), body)
			if e != nil {
				return result, e
			}
			a.SBOM = &sbom
		}
		result.Artifacts = append(result.Artifacts, a)
	}
	sort.Slice(result.Artifacts, func(i, j int) bool { return result.Artifacts[i].Path < result.Artifacts[j].Path })
	body, e := json.MarshalIndent(result, "", "  ")
	if e != nil {
		return result, e
	}
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), body...))) + "\n")
	// catalog.json 是本机发布指针。公网只发布下面的内容寻址目录。
	catalogDir := filepath.Join(root, "catalogs", digest(body))
	if e = os.MkdirAll(catalogDir, 0755); e != nil {
		return result, e
	}
	for name, value := range map[string][]byte{"catalog.json": body, "catalog.sig": sig} {
		if e = os.WriteFile(filepath.Join(catalogDir, name), value, 0644); e != nil {
			return result, e
		}
	}
	current, _ := json.Marshal(struct {
		Catalog string `json:"catalog"`
	}{filepath.ToSlash(filepath.Join("catalogs", digest(body), "catalog.json"))})
	tmp, e := os.CreateTemp(root, ".current-")
	if e != nil {
		return result, e
	}
	defer os.Remove(tmp.Name())
	if _, e = tmp.Write(current); e == nil {
		e = tmp.Sync()
	}
	tmp.Close()
	if e != nil {
		return result, e
	}
	e = os.Rename(tmp.Name(), filepath.Join(root, "current.json"))
	return result, e
}
func Files(c Catalog) []File {
	out := []File{}
	for _, a := range c.Artifacts {
		out = append(out, a.File, a.Checksum, a.Signature)
		if a.SBOM != nil {
			out = append(out, *a.SBOM)
		}
	}
	return out
}
func validFile(f File) bool {
	return hashPattern.MatchString(f.SHA256) && f.Size > 0 && f.Path == "bin/"+f.SHA256 && safeName.MatchString(f.Name)
}
func Read(root string, key ed25519.PublicKey) (Catalog, string, error) {
	var catalog Catalog
	if len(key) != ed25519.PublicKeySize {
		return catalog, "", fmt.Errorf("平台公钥不可用")
	}
	dir, e := os.OpenRoot(root)
	if e != nil {
		return catalog, "", e
	}
	defer dir.Close()
	pointer, e := dir.ReadFile("current.json")
	if e != nil {
		return catalog, "", e
	}
	var current struct {
		Catalog string `json:"catalog"`
	}
	if e = json.Unmarshal(pointer, &current); e != nil {
		return catalog, "", e
	}
	parts := strings.Split(current.Catalog, "/")
	if len(parts) != 3 || parts[0] != "catalogs" || !hashPattern.MatchString(parts[1]) || parts[2] != "catalog.json" {
		return catalog, "", fmt.Errorf("制品目录指针无效")
	}
	body, e := dir.ReadFile(current.Catalog)
	if e != nil {
		return catalog, "", e
	}
	sigBody, e := dir.ReadFile(strings.TrimSuffix(current.Catalog, ".json") + ".sig")
	if e != nil {
		return catalog, "", e
	}
	sig, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigBody)))
	if e != nil || digest(body) != parts[1] || !ed25519.Verify(key, append([]byte(domain), body...), sig) {
		return catalog, "", fmt.Errorf("制品目录签名无效")
	}
	if e = json.Unmarshal(body, &catalog); e != nil {
		return catalog, "", e
	}
	if catalog.Schema != 1 {
		return catalog, "", fmt.Errorf("制品目录版本不支持")
	}
	seen := map[string]bool{}
	for _, a := range catalog.Artifacts {
		if !commitPattern.MatchString(a.SourceCommit) || a.Filename != a.Name || seen[a.Path] {
			return Catalog{}, "", fmt.Errorf("制品元数据无效")
		}
		seen[a.Path] = true
	}
	for _, f := range Files(catalog) {
		if !validFile(f) {
			return Catalog{}, "", fmt.Errorf("制品路径或校验元数据无效")
		}
	}
	return catalog, current.Catalog, nil
}
func OpenVerified(root string, f File) (*os.File, error) {
	if !validFile(f) {
		return nil, fmt.Errorf("制品路径无效")
	}
	dir, e := os.OpenRoot(root)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	file, e := dir.Open(f.Path)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*os.File, error) { file.Close(); return nil, e }
	info, e := file.Stat()
	if e != nil {
		return fail(e)
	}
	if !info.Mode().IsRegular() || info.Size() != f.Size {
		return fail(fmt.Errorf("制品大小或文件类型无效"))
	}
	sum := sha256.New()
	if _, e = io.Copy(sum, file); e != nil {
		return fail(e)
	}
	if hex.EncodeToString(sum.Sum(nil)) != f.SHA256 {
		return fail(fmt.Errorf("制品校验和不匹配"))
	}
	if _, e = file.Seek(0, 0); e != nil {
		return fail(e)
	}
	return file, nil
}

type Store struct {
	Root     string
	Key      ed25519.PublicKey
	mu       sync.Mutex
	verified map[string]os.FileInfo
}

func (s *Store) Load() (Catalog, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	catalog, _, e := Read(s.Root, s.Key)
	if e != nil {
		return Catalog{}, e
	}
	if s.verified == nil {
		s.verified = map[string]os.FileInfo{}
	}
	for _, f := range Files(catalog) {
		info, e := os.Lstat(filepath.Join(s.Root, f.Path))
		if e != nil {
			return Catalog{}, e
		}
		old := s.verified[f.Path]
		if old != nil && os.SameFile(old, info) && old.Size() == info.Size() && old.ModTime() == info.ModTime() {
			continue
		}
		file, e := OpenVerified(s.Root, f)
		if e != nil {
			return Catalog{}, e
		}
		info, e = file.Stat()
		file.Close()
		if e != nil {
			return Catalog{}, e
		}
		s.verified[f.Path] = info
	}
	return catalog, nil
}
