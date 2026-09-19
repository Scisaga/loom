package clientrelease

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"loom/internal/clientdist"
)

const maximumLinuxPackage = 256 << 20

func readPublicationFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("release publication input is not a bounded regular file")
	}
	return os.ReadFile(path)
}

func syncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func verifyExisting(path string, body []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != int64(len(body)) {
		return errors.New("immutable release object has an unsafe type or size")
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if digest(existing) != digest(body) {
		return errors.New("immutable release object content differs")
	}
	return nil
}

func writeImmutable(path string, body []byte, mode os.FileMode) (retErr error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	if err := verifyExisting(path, body); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".release-object-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err = temporary.Chmod(mode); err == nil {
		_, err = temporary.Write(body)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return verifyExisting(path, body)
		}
		return err
	}
	return syncDir(directory)
}

func releaseFile(root, name string, body []byte) (File, error) {
	if !safeName.MatchString(name) {
		return File{}, errors.New("release filename is invalid")
	}
	hash := digest(body)
	relative := "bin/" + hash
	if err := writeImmutable(filepath.Join(root, filepath.FromSlash(relative)), body, 0o644); err != nil {
		return File{}, err
	}
	return File{Name: name, Path: relative, SHA256: hash, Size: int64(len(body))}, nil
}

func currentCatalog(root string, key ed25519.PublicKey) (Catalog, error) {
	catalog, err := Read(root, key)
	if err == nil {
		return catalog, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return Catalog{Schema: 1, Artifacts: []Artifact{}}, nil
	}
	return Catalog{}, err
}

func activateCatalog(root string, catalog Catalog, key ed25519.PrivateKey) error {
	sort.Slice(catalog.Artifacts, func(i, j int) bool {
		left := catalog.Artifacts[i].Platform + "\x00" + catalog.Artifacts[i].Arch + "\x00" + catalog.Artifacts[i].Variant + "\x00" + catalog.Artifacts[i].Name
		right := catalog.Artifacts[j].Platform + "\x00" + catalog.Artifacts[j].Arch + "\x00" + catalog.Artifacts[j].Variant + "\x00" + catalog.Artifacts[j].Name
		return left < right
	})
	body, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	catalogDigest := digest(body)
	directory := filepath.Join(root, "catalogs", catalogDigest)
	signature := append([]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), body...)))), '\n')
	if err := writeImmutable(filepath.Join(directory, "catalog.json"), body, 0o644); err != nil {
		return err
	}
	if err := writeImmutable(filepath.Join(directory, "catalog.sig"), signature, 0o644); err != nil {
		return err
	}
	pointer, err := json.Marshal(struct {
		Catalog string `json:"catalog"`
	}{Catalog: "catalogs/" + catalogDigest + "/catalog.json"})
	if err != nil {
		return err
	}
	pointer = append(pointer, '\n')
	temporary, err := os.CreateTemp(root, ".current-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o644); err == nil {
		_, err = temporary.Write(pointer)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(root, "current.json")); err != nil {
		return err
	}
	return syncDir(root)
}

func mergeLinuxArtifacts(catalog Catalog, replacements []Artifact) Catalog {
	retained := catalog.Artifacts[:0]
	for _, artifact := range catalog.Artifacts {
		if artifact.Platform != "linux-server" {
			retained = append(retained, artifact)
		}
	}
	catalog.Schema = 1
	catalog.Artifacts = append(retained, replacements...)
	return catalog
}

// PublishLinux verifies both signed bootstrap packages and atomically replaces
// only the Linux entries in the existing signed release catalog. Android and
// Windows artifacts remain byte-for-byte referenced by the new catalog.
func PublishLinux(root string, archives []string, key ed25519.PrivateKey) (Catalog, error) {
	empty := Catalog{}
	if len(key) != ed25519.PrivateKeySize || len(archives) != 2 {
		return empty, errors.New("Linux catalog publication requires one signing key and both architectures")
	}
	if info, err := os.Lstat(root); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return empty, errors.New("release root is not a real directory")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(root, 0o755); err != nil {
			return empty, err
		}
	} else {
		return empty, err
	}
	public := key.Public().(ed25519.PublicKey)
	catalog, err := currentCatalog(root, public)
	if err != nil {
		return empty, fmt.Errorf("read current release catalog: %w", err)
	}
	seen := map[string]bool{}
	newArtifacts := make([]Artifact, 0, 2)
	for _, archivePath := range archives {
		archive, err := readPublicationFile(archivePath, maximumLinuxPackage)
		if err != nil {
			return empty, err
		}
		checksum, err := readPublicationFile(archivePath+".sha256", 4<<10)
		if err != nil {
			return empty, err
		}
		signature, err := readPublicationFile(archivePath+".sig", 4<<10)
		if err != nil {
			return empty, err
		}
		manifest, err := clientdist.Verify(archive, checksum, signature, public)
		if err != nil {
			return empty, fmt.Errorf("verify %s: %w", filepath.Base(archivePath), err)
		}
		if seen[manifest.Arch] || (manifest.Arch != "amd64" && manifest.Arch != "arm64") || len(manifest.Loom.Commit) != 40 {
			return empty, errors.New("Linux release architectures or source commit are invalid")
		}
		seen[manifest.Arch] = true
		name := filepath.Base(archivePath)
		if name != "loom-client-linux-"+manifest.Arch+".tar.gz" {
			return empty, errors.New("Linux release filename does not match its signed architecture")
		}
		file, err := releaseFile(root, name, archive)
		if err != nil {
			return empty, err
		}
		checksumFile, err := releaseFile(root, name+".sha256", checksum)
		if err != nil {
			return empty, err
		}
		signatureFile, err := releaseFile(root, name+".sig", signature)
		if err != nil {
			return empty, err
		}
		newArtifacts = append(newArtifacts, Artifact{File: file, Filename: name, Title: "Loom Linux client",
			Platform: "linux-server", Arch: manifest.Arch, Variant: "unified-runtime", Version: manifest.Loom.Commit[:8],
			SourceCommit: manifest.Loom.Commit, Signing: "Platform-signed Linux package",
			Checksum: checksumFile, Signature: signatureFile})
	}
	if !seen["amd64"] || !seen["arm64"] {
		return empty, errors.New("Linux catalog publication is missing an architecture")
	}
	catalog = mergeLinuxArtifacts(catalog, newArtifacts)
	if err := activateCatalog(root, catalog, key); err != nil {
		return empty, err
	}
	verified, err := Read(root, public)
	if err != nil {
		return empty, fmt.Errorf("read back published release catalog: %w", err)
	}
	return verified, nil
}
