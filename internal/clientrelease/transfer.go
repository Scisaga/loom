package clientrelease

import (
	"archive/tar"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
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
	buffer := make([]byte, 32<<10)
	for _, name := range names {
		input, err := openFile(root, name, limits[name])
		if err != nil {
			return nil, err
		}
		size, digest, err := hashTransferFile(input, limits[name], buffer)
		err = errors.Join(err, input.Close())
		if err != nil {
			return nil, err
		}
		if (strings.HasPrefix(filepath.ToSlash(name), "bin/") || strings.HasSuffix(name, ".sig")) && size != limits[name] {
			return nil, errors.New("release source differs from its exact signed size")
		}
		if !strings.HasSuffix(name, ".sig") && digest != "sha256:"+strings.Split(filepath.ToSlash(name), "/")[1] {
			return nil, errors.New("release source changed after catalog verification")
		}
		files = append(files, TransferFile{Name: filepath.ToSlash(name), Size: size, Digest: digest})
	}
	return files, nil
}

// Hash one fixed descriptor without retaining a package-sized body. Its stat
// size and the actual EOF must agree, including when the input changes in place.
func hashTransferFile(input *os.File, limit int64, buffer []byte) (int64, string, error) {
	before, err := input.Stat()
	if err != nil {
		return 0, "", err
	}
	if !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit {
		return 0, "", errors.New("release entry is not a bounded regular file")
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(hash, io.LimitReader(input, limit+1), buffer)
	if err != nil {
		return 0, "", err
	}
	after, err := input.Stat()
	if err != nil {
		return 0, "", err
	}
	if n != before.Size() || after.Size() != before.Size() || after.Mode() != before.Mode() {
		return 0, "", errors.New("release source changed while hashing")
	}
	return n, fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}

// The same open file supplies both the fresh digest and the archive body. The
// second digest prevents a concurrent in-place write from completing a transfer.
func writeTransferFile(root *os.Root, writer *tar.Writer, file TransferFile, buffer []byte) (resultErr error) {
	input, err := openFile(root, file.Name, file.Size)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, input.Close()) }()
	size, digest, err := hashTransferFile(input, file.Size, buffer)
	if err != nil {
		return err
	}
	if size != file.Size || digest != file.Digest {
		return errors.New("release source changed before transfer")
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := writer.WriteHeader(&tar.Header{Name: file.Name, Mode: 0644, Size: file.Size, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		return err
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(io.MultiWriter(writer, hash), io.LimitReader(input, file.Size+1), buffer)
	if err != nil {
		return err
	}
	after, err := input.Stat()
	if err != nil {
		return err
	}
	if n != file.Size || after.Size() != file.Size || !after.Mode().IsRegular() || fmt.Sprintf("sha256:%x", hash.Sum(nil)) != file.Digest {
		return errors.New("release source changed during transfer")
	}
	return nil
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
	return store.WriteArchive(catalog, output, reuse)
}

// WriteArchive reuses this call's authenticated parsing, while ReadCatalog
// and the transfer still check actual bytes. Its validation lock is released
// before streaming, so a slow target does not block independent targets.
func (store *Store) WriteArchive(catalog string, output io.Writer, reuse []TransferFile) error {
	set, err := store.ReadCatalog(catalog)
	if err != nil {
		return err
	}
	files, err := TransferFiles(store.root, set)
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
	root, err := os.OpenRoot(store.root)
	if err != nil {
		return err
	}
	defer root.Close()
	writer := tar.NewWriter(output)
	buffer := make([]byte, 32<<10)
	for _, file := range files {
		if _, send := remaining[file.Name]; !send {
			continue
		}
		if err = writeTransferFile(root, writer, file, buffer); err != nil {
			return err
		}
	}
	return writer.Close()
}

// ReceiveArchiveAt returns a private, owned temporary tree on the selected
// disk. Nothing reaches a target until all members and the exact signed catalog
// have been independently checked. The caller owns cleanup after success.
func ReceiveArchiveAt(input io.Reader, catalog string, key ed25519.PublicKey, workRoot string) (result string, resultErr error) {
	if control.ValidateDigest(catalog) != nil || len(key) != ed25519.PublicKeySize {
		return "", errors.New("invalid transfer catalog or independent key")
	}
	if workRoot == "" || !filepath.IsAbs(workRoot) || filepath.Clean(workRoot) != workRoot {
		return "", errors.New("release transfer work root must be an explicit canonical absolute disk path")
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(workRoot, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		entry, err := os.Lstat(current)
		if err != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 || entry.Mode().Perm()&0022 != 0 {
			return "", errors.New("release transfer work root ancestors are not protected directories")
		}
	}
	if err := downloadWorkFilesystem(workRoot); err != nil {
		return "", err
	}
	parent, err := os.OpenRoot(workRoot)
	if err != nil {
		return "", err
	}
	defer func() { resultErr = errors.Join(resultErr, parent.Close()) }()
	directory, err := os.MkdirTemp(workRoot, ".loom-release-upload-")
	if err != nil {
		return "", err
	}
	name := filepath.Base(directory)
	entry, err := parent.Lstat(name)
	pathEntry, pathErr := os.Lstat(directory)
	if err != nil || pathErr != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 || entry.Mode().Perm() != 0700 || !os.SameFile(entry, pathEntry) {
		return "", errors.New("release transfer capture was replaced while opening")
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return "", err
	}
	stable := func() error {
		actual, err := parent.Lstat(name)
		pathEntry, pathErr := os.Lstat(directory)
		fixed, fixedErr := root.Lstat(".")
		if err != nil || pathErr != nil || fixedErr != nil || !actual.IsDir() || actual.Mode()&os.ModeSymlink != 0 || actual.Mode().Perm() != 0700 || !os.SameFile(entry, actual) || !os.SameFile(entry, pathEntry) || !os.SameFile(entry, fixed) {
			return errors.New("release transfer capture ownership changed")
		}
		return nil
	}
	ok := false
	defer func() {
		if !ok {
			if err := stable(); err != nil {
				resultErr = errors.Join(resultErr, err)
			} else {
				resultErr = errors.Join(resultErr, parent.RemoveAll(name))
			}
		}
		resultErr = errors.Join(resultErr, root.Close())
	}()
	seen := map[string]bool{}
	var total int64
	buffer := make([]byte, 64<<10)
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
		if err = root.MkdirAll(filepath.Dir(header.Name), 0700); err != nil {
			return "", err
		}
		file, err := root.OpenFile(header.Name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return "", err
		}
		before, statErr := file.Stat()
		n, copyErr := io.CopyBuffer(file, io.LimitReader(reader, header.Size), buffer)
		after, afterErr := file.Stat()
		observed, observedErr := root.Lstat(header.Name)
		closeErr := file.Close()
		if statErr != nil || copyErr != nil || afterErr != nil || observedErr != nil || closeErr != nil || n != header.Size || !after.Mode().IsRegular() || after.Mode().Perm() != 0600 || after.Size() != header.Size || !os.SameFile(before, after) || !os.SameFile(before, observed) || observed.Mode() != after.Mode() || observed.Size() != after.Size() {
			return "", errors.Join(errors.New("release transfer member changed during capture"), statErr, copyErr, afterErr, observedErr, closeErr)
		}
	}
	var extra [1]byte
	if n, err := input.Read(extra[:]); n != 0 || err != io.EOF {
		return "", errors.New("release transfer has trailing content")
	}
	if err := stable(); err != nil {
		return "", err
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
	if err := stable(); err != nil {
		return "", err
	}
	ok = true
	return directory, nil
}
