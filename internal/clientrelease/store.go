// Package clientrelease verifies and serves the immutable client release
// catalog. A mutable pointer is accepted only after its signed, content-
// addressed catalog and every referenced file have been verified.
package clientrelease

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const domain = "loom-client-releases-v1\n"

var (
	safeName      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
	hashPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

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

func PublicKey(path string) (ed25519.PublicKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("platform public key is invalid")
	}
	return ed25519.PublicKey(key), nil
}

func Read(root string, key ed25519.PublicKey) (Catalog, error) {
	var empty Catalog
	if len(key) != ed25519.PublicKeySize {
		return empty, errors.New("platform public key is unavailable")
	}
	dir, err := os.OpenRoot(root)
	if err != nil {
		return empty, err
	}
	defer dir.Close()
	pointer, err := dir.ReadFile("current.json")
	if err != nil {
		return empty, err
	}
	var current struct {
		Catalog string `json:"catalog"`
	}
	if err := decodeStrict(pointer, &current); err != nil {
		return empty, err
	}
	parts := strings.Split(current.Catalog, "/")
	if len(parts) != 3 || parts[0] != "catalogs" || !hashPattern.MatchString(parts[1]) || parts[2] != "catalog.json" {
		return empty, errors.New("release catalog pointer is invalid")
	}
	body, err := dir.ReadFile(current.Catalog)
	if err != nil {
		return empty, err
	}
	signatureBody, err := dir.ReadFile(strings.TrimSuffix(current.Catalog, ".json") + ".sig")
	if err != nil {
		return empty, err
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureBody)))
	if err != nil || digest(body) != parts[1] || !ed25519.Verify(key, append([]byte(domain), body...), signature) {
		return empty, errors.New("release catalog signature is invalid")
	}
	var catalog Catalog
	if err := decodeStrict(body, &catalog); err != nil {
		return empty, err
	}
	if catalog.Schema != 1 || catalog.Artifacts == nil {
		return empty, errors.New("release catalog schema is invalid")
	}
	seen := map[string]bool{}
	for _, artifact := range catalog.Artifacts {
		if !commitPattern.MatchString(artifact.SourceCommit) || artifact.Filename != artifact.Name || seen[artifact.Path] {
			return empty, errors.New("release artifact metadata is invalid")
		}
		switch artifact.Platform {
		case "linux-server", "android", "windows-desktop":
		default:
			return empty, errors.New("release artifact platform is invalid")
		}
		seen[artifact.Path] = true
	}
	for _, file := range Files(catalog) {
		if !validFile(file) {
			return empty, errors.New("release file metadata is invalid")
		}
		opened, err := OpenVerified(root, file)
		if err != nil {
			return empty, err
		}
		_ = opened.Close()
	}
	return catalog, nil
}

func Files(catalog Catalog) []File {
	files := []File{}
	for _, artifact := range catalog.Artifacts {
		files = append(files, artifact.File, artifact.Checksum, artifact.Signature)
		if artifact.SBOM != nil {
			files = append(files, *artifact.SBOM)
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}

func OpenVerified(root string, file File) (*os.File, error) {
	if !validFile(file) {
		return nil, errors.New("release file path is invalid")
	}
	dir, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	opened, err := dir.Open(file.Path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) {
		_ = opened.Close()
		return nil, err
	}
	info, err := opened.Stat()
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() || info.Size() != file.Size {
		return fail(errors.New("release file size or type is invalid"))
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, opened); err != nil {
		return fail(err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
		return fail(errors.New("release file digest does not match catalog"))
	}
	if _, err := opened.Seek(0, 0); err != nil {
		return fail(err)
	}
	return opened, nil
}

func Find(catalog Catalog, path string) (File, bool) {
	for _, file := range Files(catalog) {
		if file.Path == path {
			return file, true
		}
	}
	return File{}, false
}

func validFile(file File) bool {
	return safeName.MatchString(file.Name) && hashPattern.MatchString(file.SHA256) && file.Size > 0 && file.Path == "bin/"+file.SHA256
}

func digest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func decodeStrict(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode release catalog: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("release catalog has trailing content")
	}
	return nil
}

func RootPath(root, relative string) string { return filepath.Join(root, filepath.FromSlash(relative)) }
