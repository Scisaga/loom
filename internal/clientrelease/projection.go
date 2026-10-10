package clientrelease

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"loom/internal/androidrelease"
	"loom/internal/clientcomponent"
	"loom/internal/clientdist"
	"loom/internal/control"
	"loom/internal/windowsrelease"
)

// ProjectionSource reads original signed metadata from this store on every call.
// It has no cache or mutable state. Actual downloads still verify package bytes.
func (store *Store) ProjectionSource() control.ReleaseSource { return projectionSource{store} }

type projectionSource struct{ store *Store }

func (source projectionSource) Read() (control.ReleaseSet, error) {
	root, err := os.OpenRoot(source.store.root)
	if err != nil {
		return control.ReleaseSet{}, err
	}
	defer root.Close()
	id, err := currentCatalog(root)
	if err != nil {
		return control.ReleaseSet{}, err
	}
	return source.store.readSignedCatalog(root, id)
}

func (source projectionSource) ReadCatalog(id string) (control.ReleaseSet, error) {
	root, err := os.OpenRoot(source.store.root)
	if err != nil {
		return control.ReleaseSet{}, err
	}
	defer root.Close()
	return source.store.readSignedCatalog(root, id)
}

func (source projectionSource) Open(id string, artifact control.ReleaseArtifact) (io.ReadCloser, error) {
	return source.store.Open(id, artifact)
}

func currentCatalog(root *os.Root) (string, error) {
	body, err := readFile(root, "current.json", 4096)
	if err != nil {
		return "", err
	}
	var current control.ReleaseCurrent
	if err := control.DecodeCanonical(body, &current, control.ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 4, MaxItems: 16}); err != nil {
		return "", err
	}
	return current.CatalogDigest, nil
}

// signedPackage derives runtime coordinates only from authenticated manifests.
// Artifact hashes in the catalog bind downloads; they do not attest local files.
func signedPackage(entry control.ReleaseEntry, body, signature []byte, key ed25519.PublicKey) (control.ReleasePackage, error) {
	var zero control.ReleasePackage
	if err := entry.Validate(); err != nil {
		return zero, err
	}
	if control.ReleaseDigest(body) != entry.ManifestDigest {
		return zero, errors.New("release manifest differs from its content address")
	}
	pkg := control.ReleasePackage{ManifestBody: body, Signature: signature}
	var expected control.ReleaseEntry
	switch entry.ComponentID {
	case "linux-client-bootstrap":
		m, err := clientdist.VerifyManifest(body, signature, key)
		if err != nil {
			return zero, err
		}
		if entry.Artifact.Name != "loom-client-linux-"+m.Arch+".tar.gz" {
			return zero, errors.New("Linux package name differs from its signed architecture")
		}
		expected = control.ReleaseEntry{ComponentID: m.Kind, Platform: m.OS + "-" + m.Arch, ManifestDigest: control.ReleaseDigest(body), Artifact: entry.Artifact}
		pkg.Version, pkg.SourceCommit, pkg.Generation = m.Version, m.Loom.Commit, m.Generation
		pkg.Components = []control.ComponentReadback{{ComponentID: "agent", Platform: expected.Platform, Version: m.Version, ArtifactDigest: "sha256:" + m.Loom.SHA256}, {ComponentID: "sing-box", Platform: expected.Platform, Version: m.SingBox.Version, ArtifactDigest: "sha256:" + m.SingBox.SHA256}}
	case "windows-dataplane":
		m, err := clientcomponent.VerifyManifest(body, signature, key)
		if err != nil {
			return zero, err
		}
		if entry.Artifact.Name != fmt.Sprintf("loom-windows-dataplane-%s-%s.zip", m.Version, m.Arch) {
			return zero, errors.New("Windows component filename differs from its signed coordinates")
		}
		expected = control.ReleaseEntry{ComponentID: m.Kind, Platform: m.OS + "-" + m.Arch, ManifestDigest: control.ReleaseDigest(body), Artifact: entry.Artifact}
		pkg.Version, pkg.SourceCommit, pkg.Generation = m.Version, m.SingBox.Commit, m.Generation
		pkg.Components = []control.ComponentReadback{{ComponentID: "sing-box", Platform: expected.Platform, Version: m.SingBox.Version, ArtifactDigest: "sha256:" + m.SingBox.SHA256}, {ComponentID: "wintun", Platform: expected.Platform, Version: m.Wintun.Version, ArtifactDigest: "sha256:" + m.Wintun.SHA256}}
	case "android-application":
		m, err := androidrelease.VerifyManifest(body, signature, key)
		if err != nil {
			return zero, err
		}
		expected = control.ReleaseEntry{ComponentID: m.Kind, Platform: "android-any", ManifestDigest: control.ReleaseDigest(body), Artifact: m.Artifact}
		pkg.Version, pkg.SourceCommit, pkg.Generation, pkg.Components = m.VersionName, m.SourceCommit, m.Generation, m.Components()
	case "windows-client-installed", "windows-client-portable-tun", "windows-client-portable-mixed":
		m, err := windowsrelease.VerifyManifest(body, signature, key)
		if err != nil {
			return zero, err
		}
		expected = control.ReleaseEntry{ComponentID: "windows-client-" + m.Edition, Platform: "windows-" + m.Arch, ManifestDigest: control.ReleaseDigest(body), Artifact: m.Artifact}
		pkg.Version, pkg.SourceCommit, pkg.Generation, pkg.Components = m.Version(), m.SourceCommit, m.Generation, m.Components
	case "linux-bootstrap-script":
		m, err := control.VerifyReleaseBootstrap(body, signature, key)
		if err != nil {
			return zero, err
		}
		expected = control.ReleaseEntry{ComponentID: m.Kind, Platform: "linux-any", ManifestDigest: control.ReleaseDigest(body), Artifact: m.Artifact}
		pkg.Generation, pkg.Version, pkg.Bootstrap = m.Generation, strconv.FormatUint(uint64(m.Generation), 10), &m
	default:
		return zero, errors.New("release manifest contract is undefined")
	}
	if expected != entry {
		return zero, errors.New("release catalog coordinates differ from the signed manifest")
	}
	pkg.Entry = expected
	return pkg, nil
}
