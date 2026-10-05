package clientrelease

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"loom/internal/control"
)

// Import installs an explicitly addressed signed catalog from a staging tree.
// The destination accepts the same immutable bytes and conditional advancement
// as local publication; signing secrets never travel to a distribution node.
func Import(source, destination, catalogID string, key ed25519.PublicKey, expected string) (control.ReleaseSet, error) {
	return importCatalog(source, destination, catalogID, key, expected, true)
}

// Prepare validates and durably copies the exact signed catalog while retaining
// the target pointer. It shares the same writer lock and comparison as Import.
func Prepare(source, destination, catalogID string, key ed25519.PublicKey, expected string) (control.ReleaseSet, error) {
	return importCatalog(source, destination, catalogID, key, expected, false)
}

func importCatalog(source, destination, catalogID string, key ed25519.PublicKey, expected string, selectCurrent bool) (control.ReleaseSet, error) {
	store, err := New(source, key)
	if err != nil {
		return control.ReleaseSet{}, err
	}
	set, err := store.ReadCatalog(catalogID)
	if err != nil {
		return control.ReleaseSet{}, err
	}
	root, err := os.OpenRoot(source)
	if err != nil {
		return control.ReleaseSet{}, err
	}
	defer root.Close()
	body, err := readFile(root, digestPath("catalogs", catalogID, "catalog.json"), 1<<20)
	if err != nil {
		return control.ReleaseSet{}, err
	}
	signature, err := readFile(root, digestPath("catalogs", catalogID, "catalog.sig"), ed25519.SignatureSize)
	if err != nil {
		return control.ReleaseSet{}, err
	}
	if control.ReleaseDigest(body) != catalogID {
		return control.ReleaseSet{}, errors.New("staged catalog changed before import")
	}
	packages := map[string]Input{}
	for _, pkg := range set.Packages {
		artifact, err := readFile(root, digestPath("bin", pkg.Entry.Artifact.Digest, ""), int64(pkg.Entry.Artifact.Size))
		if err != nil {
			return control.ReleaseSet{}, err
		}
		packages[pkg.Entry.Artifact.Digest] = Input{Body: artifact, Manifest: pkg.ManifestBody, Signature: pkg.Signature}
	}
	return publish(destination, body, signature, key, packages, expected, selectCurrent)
}

// Publish writes an already signed catalog and exact packages. The expected
// pointer is an explicit plan input, compared while holding the target lock.
func Publish(directory string, body, signature []byte, key ed25519.PublicKey, packages map[string]Input, expected string) (control.ReleaseSet, error) {
	return publish(directory, body, signature, key, packages, expected, true)
}

func publish(directory string, body, signature []byte, key ed25519.PublicKey, packages map[string]Input, expected string, selectCurrent bool) (control.ReleaseSet, error) {
	var zero control.ReleaseSet
	store, err := New(directory, key)
	if err != nil {
		return zero, err
	}
	catalog, err := control.VerifyReleaseCatalog(body, signature, key)
	if err != nil {
		return zero, err
	}
	if expected != "" && control.ValidateDigest(expected) != nil {
		return zero, errors.New("expected release pointer is invalid")
	}
	id := control.ReleaseDigest(body)
	files := map[string][]byte{}
	wanted := map[string]bool{}
	verifiedInput := control.ReleaseSet{Catalog: catalog}
	for _, entry := range catalog.Entries {
		artifact, ok := packages[entry.Artifact.Digest]
		if !ok || control.ReleaseDigest(artifact.Body) != entry.Artifact.Digest {
			return zero, errors.New("catalog package input is missing or differs")
		}
		parsed, err := InspectInput(entry.Artifact.Name, artifact, key)
		if err != nil {
			return zero, err
		}
		if parsed.Entry != entry {
			return zero, errors.New("catalog entry differs from verified package input")
		}
		wanted[entry.Artifact.Digest] = true
		files[digestPath("bin", entry.Artifact.Digest, "")] = artifact.Body
		files[digestPath("manifests", entry.ManifestDigest, "manifest.json")] = parsed.ManifestBody
		files[digestPath("manifests", entry.ManifestDigest, "manifest.sig")] = parsed.Signature
		store.packages[packageCacheKey(entry)] = parsed
		verifiedInput.Packages = append(verifiedInput.Packages, parsed)
	}
	if err := validateBootstrapBindings(verifiedInput); err != nil {
		return zero, err
	}
	if len(packages) != len(wanted) {
		return zero, errors.New("unreferenced package inputs are not published")
	}
	if err = os.MkdirAll(directory, 0o755); err != nil {
		return zero, err
	}
	// Persist the path to a newly created target as well as its later files.
	for parent := filepath.Dir(directory); ; parent = filepath.Dir(parent) {
		f, err := os.Open(parent)
		if err != nil {
			return zero, err
		}
		err = f.Sync()
		f.Close()
		if err != nil {
			return zero, err
		}
		if parent == "/" {
			break
		}
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return zero, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || int(owner.Uid) != os.Geteuid() {
		return zero, errors.New("release target is not an owned protected directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return zero, err
	}
	defer root.Close()
	lock, err := root.OpenFile(".publish.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return zero, err
	}
	defer lock.Close()
	lockInfo, err := lock.Stat()
	if err != nil {
		return zero, err
	}
	lockOwner, ok := lockInfo.Sys().(*syscall.Stat_t)
	if !ok || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 || int(lockOwner.Uid) != os.Geteuid() || lockOwner.Nlink != 1 {
		return zero, errors.New("release publication lock is not an owned regular file")
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return zero, errors.New("another release publication owns the target lock")
	}
	pointer, err := readFile(root, "current.json", 4096)
	if err == nil {
		var current control.ReleaseCurrent
		if err = control.DecodeCanonical(pointer, &current, control.ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 4, MaxItems: 16}); err != nil {
			return zero, errors.New("existing release pointer needs an explicit verified forward cutover")
		}
		prior, err := store.readCatalog(root, current.CatalogDigest)
		if err != nil {
			return zero, err
		}
		if prior.ID == id {
			return prior, nil
		}
		if prior.ID != expected {
			return zero, errors.New("release pointer changed since the plan was read")
		}
		if catalog.Generation < prior.Catalog.Generation || catalog.Generation == prior.Catalog.Generation && id != prior.ID {
			return zero, errors.New("release publication would roll back or equivocate")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if expected != "" {
			return zero, errors.New("planned release pointer is missing")
		}
		// A missing pointer does not authorize resetting a populated historical
		// store. Only the same interrupted initial catalog may be resumed.
		for _, name := range []string{"current", "release-floor.json"} {
			if _, err := root.Lstat(name); err == nil {
				return zero, errors.New("prior release evidence requires a verified forward cutover")
			} else if !errors.Is(err, os.ErrNotExist) {
				return zero, err
			}
		}
		dir, err := root.Open("catalogs")
		if err == nil {
			entries, readErr := dir.ReadDir(-1)
			dir.Close()
			if readErr != nil {
				return zero, readErr
			}
			for _, entry := range entries {
				if entry.Name() != strings.TrimPrefix(id, "sha256:") {
					return zero, errors.New("release history exists without its current pointer")
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return zero, err
		}
	} else {
		return zero, err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err = putImmutable(root, directory, name, files[name]); err != nil {
			return zero, err
		}
	}
	// Catalog metadata is written after all payloads, so an initial interrupted
	// publication can be retried only with the exact original signed catalog.
	for _, file := range []struct {
		name string
		body []byte
	}{{"catalog.json", body}, {"catalog.sig", signature}} {
		if err = putImmutable(root, directory, digestPath("catalogs", id, file.name), file.body); err != nil {
			return zero, err
		}
	}
	verified, err := store.readCatalog(root, id)
	if err != nil {
		return zero, err
	}
	if !selectCurrent {
		return verified, nil
	}
	next, err := control.CanonicalEncode(control.ReleaseCurrent{Schema: 3, CatalogDigest: id})
	if err != nil {
		return zero, err
	}
	if err = replaceCurrent(root, directory, next); err != nil {
		return zero, err
	}
	readback, err := store.Read()
	if err != nil {
		return zero, err
	}
	if readback.ID != verified.ID {
		return zero, errors.New("published current readback differs")
	}
	return readback, nil
}

func ensureDirectory(root *os.Root, name string) error {
	path := ""
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == "." || part == "" {
			continue
		}
		path = filepath.Join(path, part)
		info, err := root.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			if err = root.Mkdir(path, 0o755); err != nil {
				return err
			}
			if err = root.Chmod(path, 0o755); err != nil {
				return err
			}
			if err = syncRootDirectory(root, filepath.Dir(path)); err != nil {
				return err
			}
			info, err = root.Lstat(path)
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return errors.New("release subdirectory is not protected")
		}
	}
	return nil
}

func syncRootDirectory(root *os.Root, name string) error {
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func stagedFile(directory string, body []byte) (string, error) {
	f, err := os.CreateTemp(directory, ".release-*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if err = f.Chmod(0o644); err == nil {
		_, err = f.Write(body)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	ok = true
	return filepath.Base(path), nil
}

func putImmutable(root *os.Root, directory, name string, body []byte) error {
	if err := ensureDirectory(root, filepath.Dir(name)); err != nil {
		return err
	}
	if existing, err := readFile(root, name, int64(len(body))); err == nil {
		if !bytes.Equal(existing, body) {
			return errors.New("immutable release path contains different bytes")
		}
		if err = syncRootDirectory(root, name); err != nil {
			return err
		}
		return syncRootDirectory(root, filepath.Dir(name))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	stage, err := stagedFile(directory, body)
	if err != nil {
		return err
	}
	defer root.Remove(stage)
	if err = root.Link(stage, name); err != nil {
		return err
	}
	if err = root.Remove(stage); err != nil {
		return err
	}
	return syncRootDirectory(root, filepath.Dir(name))
}

func replaceCurrent(root *os.Root, directory string, body []byte) error {
	stage, err := stagedFile(directory, body)
	if err != nil {
		return err
	}
	defer root.Remove(stage)
	if err = root.Rename(stage, "current.json"); err != nil {
		return err
	}
	if err = syncRootDirectory(root, "."); err != nil {
		return err
	}
	value, err := readFile(root, "current.json", 4096)
	if err != nil {
		return err
	}
	if !bytes.Equal(value, body) {
		return io.ErrUnexpectedEOF
	}
	return nil
}
