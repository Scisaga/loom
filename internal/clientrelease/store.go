// Package clientrelease consumes only the current signed release catalog and
// the original platform package formats. It never decodes historical catalogs.
package clientrelease

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"loom/internal/clientcomponent"
	"loom/internal/clientdist"
	"loom/internal/control"
)

const maxPackageBytes = 256 << 20

// Store caches only authenticated package parsing. Every read rehashes the
// actual file bytes before using that removable content-addressed cache.
type Store struct {
	root     string
	key      ed25519.PublicKey
	mu       sync.Mutex
	packages map[string]control.ReleasePackage
}

func New(root string, key ed25519.PublicKey) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("release root or independent trust input is invalid")
	}
	return &Store{root: root, key: append(ed25519.PublicKey(nil), key...), packages: map[string]control.ReleasePackage{}}, nil
}

func digestPath(prefix, digest, name string) string {
	return filepath.Join(prefix, strings.TrimPrefix(digest, "sha256:"), name)
}

func readFile(root *os.Root, path string, limit int64) ([]byte, error) {
	info, err := root.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, errors.New("release entry is not a bounded regular file")
	}
	f, err := root.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil || !os.SameFile(info, current) {
		return nil, errors.New("release entry changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("release entry exceeds its read boundary")
	}
	return body, nil
}

func (store *Store) Read() (control.ReleaseSet, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var zero control.ReleaseSet
	root, err := os.OpenRoot(store.root)
	if err != nil {
		return zero, err
	}
	defer root.Close()
	pointer, err := readFile(root, "current.json", 4096)
	if err != nil {
		return zero, err
	}
	var current control.ReleaseCurrent
	if err = control.DecodeCanonical(pointer, &current, control.ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 4, MaxItems: 16}); err != nil {
		return zero, err
	}
	return store.readCatalog(root, current.CatalogDigest)
}

// ReadCatalog verifies an explicitly addressed immutable catalog. It does not
// select an installed generation or change current; old download links remain
// useful without introducing an installation fallback.
func (store *Store) ReadCatalog(id string) (control.ReleaseSet, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	root, err := os.OpenRoot(store.root)
	if err != nil {
		return control.ReleaseSet{}, err
	}
	defer root.Close()
	return store.readCatalog(root, id)
}

func (store *Store) readCatalog(root *os.Root, id string) (control.ReleaseSet, error) {
	var zero control.ReleaseSet
	if control.ValidateDigest(id) != nil {
		return zero, errors.New("release catalog digest is invalid")
	}
	body, err := readFile(root, digestPath("catalogs", id, "catalog.json"), 1<<20)
	if err != nil {
		return zero, err
	}
	signature, err := readFile(root, digestPath("catalogs", id, "catalog.sig"), ed25519.SignatureSize)
	if err != nil {
		return zero, err
	}
	catalog, err := control.VerifyReleaseCatalog(body, signature, store.key)
	if err != nil {
		return zero, err
	}
	if control.ReleaseDigest(body) != id {
		return zero, errors.New("release catalog differs from its content address")
	}
	result := control.ReleaseSet{ID: id, Catalog: catalog, Packages: []control.ReleasePackage{}}
	for _, entry := range catalog.Entries {
		if uint64(entry.Artifact.Size) > maxPackageBytes {
			return zero, errors.New("release package exceeds the reader boundary")
		}
		artifact, err := readFile(root, digestPath("bin", entry.Artifact.Digest, ""), int64(entry.Artifact.Size))
		if err != nil {
			return zero, err
		}
		if len(artifact) != int(entry.Artifact.Size) || control.ReleaseDigest(artifact) != entry.Artifact.Digest {
			return zero, errors.New("release package differs from its signed digest or size")
		}
		parsed, ok := store.packages[entry.Artifact.Digest]
		if !ok {
			parsed, err = Inspect(entry.Artifact.Name, artifact, store.key)
			if err != nil {
				return zero, err
			}
			store.packages[entry.Artifact.Digest] = parsed
		}
		if parsed.Entry != entry {
			return zero, errors.New("release catalog coordinates differ from the original package manifest")
		}
		manifest, err := readFile(root, digestPath("manifests", entry.ManifestDigest, "manifest.json"), 64<<10)
		if err != nil {
			return zero, err
		}
		signed, err := readFile(root, digestPath("manifests", entry.ManifestDigest, "manifest.sig"), ed25519.SignatureSize)
		if err != nil {
			return zero, err
		}
		if !bytes.Equal(manifest, parsed.ManifestBody) || !bytes.Equal(signed, parsed.Signature) {
			return zero, errors.New("release manifest or signature differs from its original package bytes")
		}
		result.Packages = append(result.Packages, clonePackage(parsed))
	}
	return result, nil
}

func clonePackage(value control.ReleasePackage) control.ReleasePackage {
	value.ManifestBody = append([]byte(nil), value.ManifestBody...)
	value.Signature = append([]byte(nil), value.Signature...)
	value.Components = append([]control.ComponentReadback(nil), value.Components...)
	return value
}

// Inspect binds a download to its original manifest and to the distinct files
// whose digests the running program can actually report.
func Inspect(name string, body []byte, key ed25519.PublicKey) (control.ReleasePackage, error) {
	var result control.ReleasePackage
	if len(body) == 0 || len(body) > maxPackageBytes {
		return result, errors.New("release package size is invalid")
	}
	artifact := control.ReleaseArtifact{Name: name, Digest: control.ReleaseDigest(body), Size: control.U64(len(body)), Audience: "public"}
	switch {
	case strings.HasPrefix(name, "loom-client-linux-") && strings.HasSuffix(name, ".tar.gz"):
		value, err := clientdist.VerifyPackage(body, key)
		if err != nil {
			return result, err
		}
		m := value.Manifest
		artifact.MediaType = "application/gzip"
		result = control.ReleasePackage{Entry: control.ReleaseEntry{ComponentID: m.Kind, Platform: m.OS + "-" + m.Arch, ManifestDigest: control.ReleaseDigest(value.ManifestBody), Artifact: artifact}, ManifestBody: value.ManifestBody, Signature: value.Signature, Version: m.Version, SourceCommit: m.Loom.Commit, Generation: m.Generation,
			Components: []control.ComponentReadback{{ComponentID: "agent", Platform: m.OS + "-" + m.Arch, Version: m.Version, ArtifactDigest: "sha256:" + m.Loom.SHA256}, {ComponentID: "sing-box", Platform: m.OS + "-" + m.Arch, Version: m.SingBox.Version, ArtifactDigest: "sha256:" + m.SingBox.SHA256}}}
	case strings.HasPrefix(name, "loom-windows-dataplane-") && strings.HasSuffix(name, ".zip"):
		value, err := clientcomponent.Verify(body, key)
		if err != nil {
			return result, err
		}
		m := value.Manifest
		if name != fmt.Sprintf("loom-windows-dataplane-%s-%s.zip", m.Version, m.Arch) {
			return result, errors.New("Windows component filename differs from its signed coordinates")
		}
		artifact.MediaType = "application/zip"
		result = control.ReleasePackage{Entry: control.ReleaseEntry{ComponentID: m.Kind, Platform: m.OS + "-" + m.Arch, ManifestDigest: control.ReleaseDigest(value.ManifestBody), Artifact: artifact}, ManifestBody: value.ManifestBody, Signature: value.Signature, Version: m.Version, SourceCommit: m.SingBox.Commit, Generation: m.Generation,
			Components: []control.ComponentReadback{{ComponentID: "sing-box", Platform: m.OS + "-" + m.Arch, Version: m.SingBox.Version, ArtifactDigest: "sha256:" + m.SingBox.SHA256}, {ComponentID: "wintun", Platform: m.OS + "-" + m.Arch, Version: m.Wintun.Version, ArtifactDigest: "sha256:" + m.Wintun.SHA256}}}
	default:
		return result, errors.New("release package manifest contract is undefined")
	}
	if err := result.Entry.Validate(); err != nil {
		return control.ReleasePackage{}, err
	}
	return result, nil
}

func (store *Store) Open(catalogID string, artifact control.ReleaseArtifact) (io.ReadCloser, error) {
	current, err := store.ReadCatalog(catalogID)
	if err != nil {
		return nil, err
	}
	found := false
	for _, entry := range current.Catalog.Entries {
		if entry.Artifact == artifact {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("artifact is not in the verified current catalog")
	}
	root, err := os.OpenRoot(store.root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	body, err := readFile(root, digestPath("bin", artifact.Digest, ""), int64(artifact.Size))
	if err != nil {
		return nil, err
	}
	if len(body) != int(artifact.Size) || control.ReleaseDigest(body) != artifact.Digest {
		return nil, errors.New("artifact changed before download")
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}
