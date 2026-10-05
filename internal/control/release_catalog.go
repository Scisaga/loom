package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

const ReleaseCatalogDomain = "loom-release-catalog-v3\x00"

// ReleaseCatalog belongs to the independent platform signer. It references
// existing package manifests; it is never a network authorization or a report.
type ReleaseCatalog struct {
	Schema     int            `json:"schema"`
	Generation U64            `json:"generation"`
	Entries    []ReleaseEntry `json:"entries"`
}

type ReleaseEntry struct {
	ComponentID    string          `json:"component_id"`
	Platform       string          `json:"platform"`
	ManifestDigest string          `json:"manifest_digest"`
	Artifact       ReleaseArtifact `json:"artifact"`
}

type ReleaseArtifact struct {
	Name      string `json:"name"`
	Digest    string `json:"digest"`
	Size      U64    `json:"size"`
	MediaType string `json:"media_type"`
	Audience  string `json:"audience"`
}

type ReleaseCurrent struct {
	Schema        int    `json:"schema"`
	CatalogDigest string `json:"catalog_digest"`
}

// These are disposable readbacks from one fully verified release store. They
// are not wire values or a second persistent manifest representation.
type ReleasePackage struct {
	Entry                   ReleaseEntry
	ManifestBody, Signature []byte
	Version, SourceCommit   string
	Generation              U64
	Components              []ComponentReadback
	Bootstrap               *ReleaseBootstrapManifest
}

type ReleaseSet struct {
	ID       string
	Catalog  ReleaseCatalog
	Packages []ReleasePackage
}

type ReleaseSource interface {
	Read() (ReleaseSet, error)
	ReadCatalog(string) (ReleaseSet, error)
	Open(string, ReleaseArtifact) (io.ReadCloser, error)
}

func (current ReleaseCurrent) Validate() error {
	if current.Schema != 3 || ValidateDigest(current.CatalogDigest) != nil {
		return errors.New("release current coordinates are invalid")
	}
	return nil
}

func (artifact ReleaseArtifact) Validate() error {
	if len(artifact.Name) == 0 || len(artifact.Name) > 160 || artifact.Name[0] == '.' || artifact.Size == 0 || artifact.Audience != "public" || ValidateDigest(artifact.Digest) != nil {
		return errors.New("release artifact coordinates are invalid")
	}
	for _, c := range artifact.Name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-", c)) {
			return errors.New("release artifact filename is invalid")
		}
	}
	if artifact.MediaType != "application/gzip" && artifact.MediaType != "application/zip" && artifact.MediaType != "application/x-msi" && artifact.MediaType != "text/x-shellscript" && artifact.MediaType != "application/vnd.android.package-archive" {
		return errors.New("release artifact media type is undefined")
	}
	return nil
}

func (entry ReleaseEntry) Validate() error {
	if ValidateDigest(entry.ManifestDigest) != nil || entry.Artifact.Validate() != nil {
		return errors.New("release entry is invalid")
	}
	switch entry.ComponentID {
	case "linux-client-bootstrap":
		if (entry.Platform != "linux-amd64" && entry.Platform != "linux-arm64") || entry.Artifact.MediaType != "application/gzip" || entry.Artifact.Name != "loom-client-"+entry.Platform+".tar.gz" {
			return errors.New("Linux catalog entry differs from its package form")
		}
	case "windows-dataplane":
		if (entry.Platform != "windows-amd64" && entry.Platform != "windows-arm64") || entry.Artifact.MediaType != "application/zip" {
			return errors.New("Windows data-plane catalog entry differs from its package form")
		}
	case "windows-client-installed", "windows-client-portable-tun", "windows-client-portable-mixed":
		media, extension := "application/zip", ".zip"
		if entry.ComponentID == "windows-client-installed" {
			media, extension = "application/x-msi", ".msi"
		}
		edition := strings.TrimPrefix(entry.ComponentID, "windows-client-")
		arch := strings.TrimPrefix(entry.Platform, "windows-")
		if (entry.Platform != "windows-amd64" && entry.Platform != "windows-arm64") || entry.Artifact.MediaType != media || entry.Artifact.Name != "loom-client-windows-"+edition+"-"+arch+extension {
			return errors.New("Windows application catalog entry differs from its delivery form")
		}
	case "linux-bootstrap-script":
		if entry.Platform != "linux-any" || entry.Artifact.MediaType != "text/x-shellscript" || entry.Artifact.Name != "loom-bootstrap-linux.sh" {
			return errors.New("Linux bootstrap entry differs from its script form")
		}
	case "android-application":
		if entry.Platform != "android-any" || entry.Artifact.MediaType != "application/vnd.android.package-archive" || entry.Artifact.Name != "loom-android.apk" {
			return errors.New("Android catalog entry differs from its application form")
		}
	default:
		return errors.New("release component manifest contract is undefined")
	}
	return nil
}

func (catalog ReleaseCatalog) Validate() error {
	if catalog.Schema != 3 || catalog.Generation == 0 || len(catalog.Entries) == 0 {
		return errors.New("release catalog coordinates are invalid")
	}
	for i, entry := range catalog.Entries {
		if entry.Validate() != nil {
			return errors.New("release catalog entry is invalid")
		}
		if i > 0 {
			prior := catalog.Entries[i-1]
			if prior.ComponentID > entry.ComponentID || prior.ComponentID == entry.ComponentID && prior.Platform >= entry.Platform {
				return errors.New("release catalog entries are not uniquely sorted")
			}
		}
	}
	return nil
}

func ReleaseDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func SignReleaseCatalog(catalog ReleaseCatalog, key ed25519.PrivateKey) ([]byte, []byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("release signing key is invalid")
	}
	body, err := CanonicalEncode(catalog)
	if err != nil {
		return nil, nil, err
	}
	return body, ed25519.Sign(key, append([]byte(ReleaseCatalogDomain), body...)), nil
}

func VerifyReleaseCatalog(body, signature []byte, key ed25519.PublicKey) (ReleaseCatalog, error) {
	var catalog ReleaseCatalog
	if err := DecodeCanonical(body, &catalog, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 16, MaxItems: 1 << 16}); err != nil {
		return ReleaseCatalog{}, err
	}
	if len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, append([]byte(ReleaseCatalogDomain), body...), signature) {
		return ReleaseCatalog{}, errors.New("release catalog signature is invalid")
	}
	return catalog, nil
}
