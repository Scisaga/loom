package clientrelease

import (
	"archive/tar"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"loom/internal/control"
)

func catalogFiles(set control.ReleaseSet) map[string]int64 {
	files := map[string]int64{digestPath("catalogs", set.ID, "catalog.json"): 1 << 20, digestPath("catalogs", set.ID, "catalog.sig"): ed25519.SignatureSize}
	for _, e := range set.Catalog.Entries {
		files[digestPath("bin", e.Artifact.Digest, "")] = int64(e.Artifact.Size)
		files[digestPath("manifests", e.ManifestDigest, "manifest.json")] = 64 << 10
		files[digestPath("manifests", e.ManifestDigest, "manifest.sig")] = ed25519.SignatureSize
	}
	return files
}

// WriteArchive transports only files referenced by an independently verified
// catalog. It never includes the source pointer, private keys or installation state.
func WriteArchive(source, catalog string, key ed25519.PublicKey, output io.Writer) error {
	store, err := New(source, key)
	if err != nil {
		return err
	}
	set, err := store.ReadCatalog(catalog)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(source)
	if err != nil {
		return err
	}
	defer root.Close()
	files := catalogFiles(set)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	writer := tar.NewWriter(output)
	for _, name := range names {
		body, err := readFile(root, name, files[name])
		if err != nil {
			return err
		}
		if err = writer.WriteHeader(&tar.Header{Name: filepath.ToSlash(name), Mode: 0644, Size: int64(len(body)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			return err
		}
		if _, err = writer.Write(body); err != nil {
			return err
		}
	}
	return writer.Close()
}

// ReceiveArchive returns an owned temporary tree. Nothing reaches a target
// until all members and the exact signed catalog have been independently checked.
func ReceiveArchive(input io.Reader, catalog string, key ed25519.PublicKey) (string, error) {
	if control.ValidateDigest(catalog) != nil {
		return "", errors.New("invalid transfer catalog")
	}
	directory, err := os.MkdirTemp("", "loom-release-upload-")
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(directory)
		}
	}()
	seen := map[string]bool{}
	var total int64
	reader := tar.NewReader(input)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		parts := strings.Split(header.Name, "/")
		valid := len(parts) == 2 && parts[0] == "bin" || len(parts) == 3 && (parts[0] == "catalogs" && (parts[2] == "catalog.json" || parts[2] == "catalog.sig") || parts[0] == "manifests" && (parts[2] == "manifest.json" || parts[2] == "manifest.sig"))
		if !valid || control.ValidateDigest("sha256:"+parts[1]) != nil || header.Typeflag != tar.TypeReg || header.Mode != 0644 || len(header.PAXRecords) > 0 || header.Linkname != "" || seen[header.Name] || len(seen) >= 32 || header.Size < 1 || header.Size > maxPackageBytes {
			return "", errors.New("invalid release transfer member")
		}
		total += header.Size
		if total > 2<<30 {
			return "", errors.New("release transfer exceeds boundary")
		}
		seen[header.Name] = true
		path := filepath.Join(directory, header.Name)
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return "", err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return "", err
		}
		_, err = io.CopyN(file, reader, header.Size)
		closeErr := file.Close()
		if err != nil {
			return "", err
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	var extra [1]byte
	if n, err := input.Read(extra[:]); n != 0 || err != io.EOF {
		return "", errors.New("release transfer has trailing content")
	}
	store, err := New(directory, key)
	if err != nil {
		return "", err
	}
	set, err := store.ReadCatalog(catalog)
	if err != nil {
		return "", err
	}
	files := catalogFiles(set)
	if len(files) != len(seen) {
		return "", errors.New("release transfer has unreferenced files")
	}
	for name := range files {
		if !seen[name] {
			return "", errors.New("release transfer is incomplete")
		}
	}
	ok = true
	return directory, nil
}
