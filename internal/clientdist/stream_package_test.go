//go:build linux

package clientdist

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var streamingLinuxArchive = flag.String("linux-package-archive", "", "explicit original signed Linux package for streaming integration")
var streamingLinuxPublic = flag.String("linux-package-public-key", "", "independent public key for the original streaming fixture")

func TestStreamingCanonicalComparisonPreservesExactArchive(t *testing.T) {
	root := t.TempDir()
	input := &packageInput{root: root, files: map[string]*packageFileInput{}}
	var files []archiveFile
	for _, name := range packageInputNames() {
		body := []byte("demo payload: " + name)
		filePath := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filePath, body, packageExpectedMode(name)); err != nil {
			t.Fatal(err)
		}
		value, err := openPackageInput(filePath, name, false)
		if err != nil {
			t.Fatal(err)
		}
		input.files[name] = value
		files = append(files, archiveFile{path: name, mode: int64(value.mode), body: body})
	}
	t.Cleanup(func() {
		if err := input.close(); err != nil {
			t.Error(err)
		}
	})
	archive, err := buildArchive("loom-client-linux-amd64", files)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Clone(archive)
	changed[len(changed)/2] ^= 1
	for _, test := range []struct {
		name  string
		body  []byte
		valid bool
	}{
		{"exact", archive, true}, {"changed", changed, false}, {"missing", archive[:len(archive)-1], false}, {"trailing", append(bytes.Clone(archive), 'x'), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := comparePackageArchive(context.Background(), input, "amd64", bytes.NewReader(test.body))
			if (err == nil) != test.valid {
				t.Fatal("unexpected canonical equality", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := comparePackageArchive(ctx, input, "amd64", bytes.NewReader(archive)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled comparison continued", err)
	}
}

func TestPackageCaptureRejectsDefaultAndTmpfsWorkRoots(t *testing.T) {
	if err := packageWorkRoot(""); err == nil {
		t.Fatal("implicit temporary root accepted")
	}
	if err := packageWorkRoot("relative-root"); err == nil {
		t.Fatal("relative work root accepted")
	}
	if err := packageWorkFilesystem("/run"); err == nil {
		// An installation on an ordinary disk may legitimately use /run only
		// when it is not tmpfs. The platform owns that choice; no mounts change.
		return
	}
	if _, err := newPackageCapture("/run"); err == nil {
		t.Fatal("memory filesystem capture accepted")
	}
}

func TestStreamingInstalledSnapshotCannotConsumeChangedOrReplacedBytes(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "loom")
	original := []byte("demo original binary")
	if err := os.WriteFile(filePath, original, 0755); err != nil {
		t.Fatal(err)
	}
	value, err := openPackageInput(filePath, "loom", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { value.file.Close() })
	value.digest, err = hashPackageInput(context.Background(), value, make([]byte, packageCopyBuffer))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, []byte("demo modified binary"), 0755); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "copied")
	if err := installPackageFile(context.Background(), destination, value); err == nil {
		t.Fatal("changed verified bytes were copied")
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed copy became a destination", err)
	}
	if err := os.Rename(filePath, filePath+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, original, 0755); err != nil {
		t.Fatal(err)
	}
	if err := value.stable(); err == nil {
		t.Fatal("same-byte replaced inode accepted")
	}
}

func TestOriginalSignedLinuxPackageStreamsAndCapturesExactBytes(t *testing.T) {
	if *streamingLinuxArchive == "" || *streamingLinuxPublic == "" {
		t.Skip("requires explicitly selected original package and independent public key")
	}
	workRoot := t.TempDir()
	if err := packageWorkFilesystem(workRoot); err != nil {
		t.Skip("integration needs a disk TMPDIR: ", err)
	}
	publicBody, err := os.ReadFile(*streamingLinuxPublic)
	if err != nil {
		t.Fatal(err)
	}
	public, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(publicBody)))
	if err != nil {
		t.Fatal(err)
	}
	archive, err := os.Open(*streamingLinuxArchive)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	value, err := VerifyArchiveFile(context.Background(), archive, ed25519.PublicKey(public), workRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	if value.ID != sha256Hex(value.ManifestBody) || len(value.Signature) != ed25519.SignatureSize {
		t.Fatal("original metadata changed")
	}
	observed, err := VerifyInstalledDirectory(context.Background(), value.Root, ed25519.PublicKey(public))
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	if !reflect.DeepEqual(observed.Manifest, value.Manifest) || observed.ID != value.ID {
		t.Fatal("installed projection changed original coordinates")
	}
	copyRoot := filepath.Join(workRoot, "copied")
	if err := os.Mkdir(copyRoot, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range packageInputNames() {
		filePath := filepath.Join(copyRoot, name)
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := installPackageFile(context.Background(), filePath, value.input.files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyInstalledPayloadContext(context.Background(), copyRoot, value); err != nil {
		t.Fatal(err)
	}
	// Canonical equality cannot ignore bytes beyond the original gzip stream.
	extra := filepath.Join(workRoot, "trailing.tar.gz")
	file, err := os.Create(extra)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(file, io.NewSectionReader(archive, 0, 1<<30)); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("demo trailing")); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyArchiveFile(context.Background(), file, ed25519.PublicKey(public), workRoot); err == nil {
		t.Fatal("trailing archive bytes accepted")
	}
	file.Close()
	closedRoot := value.Root
	if err := value.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(closedRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned capture remains after Close", err)
	}
}

func TestPrivatePackageCleanupPreservesReplacedOrUnprotectedDirectory(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(map[bool]string{false: "permissions changed", true: "different directory"}[replacement], func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "demo-capture")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			entry, err := os.Lstat(root)
			if err != nil {
				t.Fatal(err)
			}
			input := &packageInput{root: root, entry: entry, remove: true}
			if replacement {
				if err := os.Rename(root, root+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Chmod(root, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "demo-canary"), []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := input.close(); err == nil {
				t.Fatal("uncertain directory was claimed for cleanup")
			}
			if body, err := os.ReadFile(filepath.Join(root, "demo-canary")); err != nil || string(body) != "preserve" {
				t.Fatal("uncertain directory was deleted", err)
			}
		})
	}
}
