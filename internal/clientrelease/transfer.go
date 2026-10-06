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

// TransferFile is a per-call projection of verified public bytes, not a release
// record or a persistent cache of what a target is believed to contain.
type TransferFile struct {
	Name   string
	Size   int64
	Digest string
}

func TransferFiles(source string, set control.ReleaseSet) ([]TransferFile, error) {
	if err := set.Catalog.Validate(); err != nil {
		return nil, err
	}
	if err := control.ValidateDigest(set.ID); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(source)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	limits := catalogFiles(set)
	names := make([]string, 0, len(limits))
	for name := range limits {
		names = append(names, name)
	}
	sort.Strings(names)
	files := make([]TransferFile, 0, len(names))
	for _, name := range names {
		body, err := readFile(root, name, limits[name])
		if err != nil {
			return nil, err
		}
		digest := control.ReleaseDigest(body)
		if !strings.HasSuffix(name, ".sig") && digest != "sha256:"+strings.Split(filepath.ToSlash(name), "/")[1] {
			return nil, errors.New("release source changed after catalog verification")
		}
		files = append(files, TransferFile{Name: filepath.ToSlash(name), Size: int64(len(body)), Digest: digest})
	}
	return files, nil
}

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
func WriteArchive(source, catalog string, key ed25519.PublicKey, output io.Writer, reuse []TransferFile) error {
	store, err := New(source, key)
	if err != nil {
		return err
	}
	set, err := store.ReadCatalog(catalog)
	if err != nil {
		return err
	}
	files, err := TransferFiles(source, set)
	if err != nil {
		return err
	}
	remaining := make(map[string]TransferFile, len(files))
	for _, file := range files {
		remaining[file.Name] = file
	}
	for _, file := range reuse {
		if actual, found := remaining[file.Name]; !found || actual != file {
			return errors.New("reused file differs from the verified source or is duplicated")
		}
		delete(remaining, file.Name)
	}
	root, err := os.OpenRoot(source)
	if err != nil {
		return err
	}
	defer root.Close()
	writer := tar.NewWriter(output)
	for _, file := range files {
		if _, send := remaining[file.Name]; !send {
			continue
		}
		body, err := readFile(root, file.Name, file.Size)
		if err != nil {
			return err
		}
		if int64(len(body)) != file.Size || control.ReleaseDigest(body) != file.Digest {
			return errors.New("release source changed before transfer")
		}
		if err = writer.WriteHeader(&tar.Header{Name: file.Name, Mode: 0644, Size: file.Size, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
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
		// Twelve finite delivery/platform combinations, each with artifact,
		// manifest and signature, plus the catalog and its signature.
		if !valid || control.ValidateDigest("sha256:"+parts[1]) != nil || header.Typeflag != tar.TypeReg || header.Mode != 0644 || len(header.PAXRecords) > 0 || header.Linkname != "" || seen[header.Name] || len(seen) >= 2+3*12 || header.Size < 1 || header.Size > maxPackageBytes {
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
