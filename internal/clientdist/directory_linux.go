package clientdist

import (
	"crypto/ed25519"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// VerifiedDirectory retains the bytes verified in one read. Installation must
// copy these bytes rather than reopen the unpacked input after verification.
type VerifiedDirectory struct {
	Manifest Manifest
	ID       string
	Files    map[string][]byte
}

func VerifyDirectory(directory string, public ed25519.PublicKey) (VerifiedDirectory, error) {
	var zero VerifiedDirectory
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return zero, fmt.Errorf("package directory must be a real directory")
	}
	names := append(payloadNames(), "manifest.json", "manifest.sig", "checksums.txt")
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
	}
	files := make(map[string][]byte, len(names))
	var payload []archiveFile
	total := 0
	err = filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == directory {
			return nil
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if relative == "systemd" || relative == "source" || relative == "licenses" {
				return nil
			}
			return fmt.Errorf("package contains an unexpected directory")
		}
		if !wanted[relative] || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("package contains an unexpected file or link")
		}
		body, err := readRegularBounded(path, maxArchiveBytes)
		if err != nil {
			return err
		}
		total += len(body)
		if total > maxArchiveBytes {
			return fmt.Errorf("unpacked package exceeds size boundary")
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		files[relative] = body
		payload = append(payload, archiveFile{path: relative, mode: int64(info.Mode().Perm()), body: body})
		return nil
	})
	if err != nil {
		return zero, err
	}
	manifest, err := verifyManifest(files["manifest.json"], files["manifest.sig"], public)
	if err != nil {
		return zero, err
	}
	sort.Slice(payload, func(i, j int) bool { return payload[i].path < payload[j].path })
	archive, err := buildArchive("loom-client-linux-"+manifest.Arch, payload)
	if err != nil {
		return zero, err
	}
	checksum := []byte(fmt.Sprintf("%s  loom-client-linux-%s.tar.gz\n", sha256Hex(archive), manifest.Arch))
	if _, err := Verify(archive, checksum, files["manifest.sig"], public); err != nil {
		return zero, err
	}
	return VerifiedDirectory{Manifest: manifest, ID: sha256Hex(files["manifest.json"]), Files: files}, nil
}
