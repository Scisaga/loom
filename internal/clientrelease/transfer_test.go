package clientrelease

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"loom/internal/control"
)

func TestTransferRejectsUnownedMembersBeforeCatalogAcceptance(t *testing.T) {
	workRoot := transferTestDiskRoot(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, 32)).Public().(ed25519.PublicKey)
	for _, name := range []string{"../demo", "current.json", "bin/not-a-digest", "materials/demo.json"} {
		var body bytes.Buffer
		writer := tar.NewWriter(&body)
		writer.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: 1, Typeflag: tar.TypeReg})
		writer.Write([]byte("x"))
		writer.Close()
		if directory, err := ReceiveArchiveAt(&body, control.ReleaseDigest([]byte("demo")), key, workRoot); err == nil {
			os.RemoveAll(directory)
			t.Fatal("unreferenced transfer member accepted", name)
		}
		entries, err := os.ReadDir(workRoot)
		if err != nil || len(entries) != 0 {
			t.Fatal("rejected transfer retained its private capture", err)
		}
	}
}

func transferTestDiskRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := downloadWorkFilesystem(root); err != nil {
		t.Skip("transfer capture requires explicit disk-backed test scratch")
	}
	return root
}

func TestTransferCaptureRequiresExplicitProtectedDiskRoot(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, 32)).Public().(ed25519.PublicKey)
	for _, path := range []string{"", "relative-demo-root"} {
		if directory, err := ReceiveArchiveAt(bytes.NewReader(nil), control.ReleaseDigest([]byte("demo")), key, path); err == nil {
			os.RemoveAll(directory)
			t.Fatal("implicit or relative transfer work root accepted")
		}
	}
	if err := downloadWorkFilesystem("/run"); err != nil {
		if directory, err := ReceiveArchiveAt(bytes.NewReader(nil), control.ReleaseDigest([]byte("demo")), key, "/run"); err == nil {
			os.RemoveAll(directory)
			t.Fatal("memory filesystem accepted for transfer capture")
		}
	}
	root := t.TempDir()
	link := filepath.Join(root, "demo-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if directory, err := ReceiveArchiveAt(bytes.NewReader(nil), control.ReleaseDigest([]byte("demo")), key, link); err == nil {
		os.RemoveAll(directory)
		t.Fatal("symlink transfer work root accepted")
	}
	unsafe := filepath.Join(root, "demo-unprotected")
	if err := os.Mkdir(unsafe, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(unsafe, "demo-work")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	read := false
	input := &transferMutatingReader{reader: bytes.NewReader(nil), mutate: func() error { read = true; return nil }}
	if directory, err := ReceiveArchiveAt(input, control.ReleaseDigest([]byte("demo")), key, work); err == nil || read {
		os.RemoveAll(directory)
		t.Fatal("unprotected ancestor reached transfer capture", err)
	}
	if entries, err := os.ReadDir(work); err != nil || len(entries) != 0 {
		t.Fatal("rejected work root retained a transfer capture", err)
	}
}

type transferMutatingReader struct {
	reader io.Reader
	mutate func() error
}

func (reader *transferMutatingReader) Read(body []byte) (int, error) {
	if reader.mutate != nil {
		change := reader.mutate
		reader.mutate = nil
		if err := change(); err != nil {
			return 0, err
		}
	}
	return reader.reader.Read(body)
}

func TestTransferCaptureDoesNotDeleteReplacement(t *testing.T) {
	workRoot := transferTestDiskRoot(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, 32)).Public().(ed25519.PublicKey)
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{Name: digestPath("bin", control.ReleaseDigest([]byte("x")), ""), Mode: 0644, Size: 1, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	writer.Write([]byte("x"))
	writer.Close()
	var replaced string
	input := &transferMutatingReader{reader: bytes.NewReader(archive.Bytes()), mutate: func() error {
		entries, err := os.ReadDir(workRoot)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), ".loom-release-upload-") {
				continue
			}
			replaced = filepath.Join(workRoot, entry.Name())
			if err := os.Rename(replaced, replaced+".original"); err != nil {
				return err
			}
			if err := os.Mkdir(replaced, 0700); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(replaced, "demo-canary"), []byte("preserve"), 0600)
		}
		return os.ErrNotExist
	}}
	directory, err := ReceiveArchiveAt(input, control.ReleaseDigest([]byte("demo")), key, workRoot)
	if err == nil {
		os.RemoveAll(directory)
		t.Fatal("replaced capture accepted")
	}
	if replaced == "" {
		t.Fatal("replacement fixture did not reach the transfer capture", err)
	}
	if body, err := os.ReadFile(filepath.Join(replaced, "demo-canary")); err != nil || string(body) != "preserve" {
		t.Fatal("rejected transfer deleted the replacement directory", err)
	}
}

func TestReviewedPrepareAndTransferPreservePointerAndSignedBytes(t *testing.T) {
	if *reviewedStore == "" || *reviewedPublic == "" {
		t.Skip("requires explicit signed package store and independent public key")
	}
	workRoot := transferTestDiskRoot(t)
	key, err := control.ReadReleasePublicKey(*reviewedPublic)
	if err != nil {
		t.Fatal(err)
	}
	source, err := New(*reviewedStore, key)
	if err != nil {
		t.Fatal(err)
	}
	set, err := source.Read()
	if err != nil {
		t.Fatal(err)
	}
	archive, err := os.CreateTemp(workRoot, "demo-transfer-*")
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	if err = WriteArchive(*reviewedStore, set.ID, key, archive, nil); err != nil {
		t.Fatal(err)
	}
	archiveEntry, err := archive.Stat()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := ReceiveArchiveAt(io.NewSectionReader(archive, 0, archiveEntry.Size()), set.ID, key, workRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if _, err = os.Stat(filepath.Join(directory, "current.json")); !os.IsNotExist(err) {
		t.Fatal("source pointer was transferred")
	}
	destination := filepath.Join(t.TempDir(), "target")
	for i := 0; i < 2; i++ {
		got, err := Prepare(directory, destination, set.ID, key, "")
		if err != nil || !reflect.DeepEqual(got, set) {
			t.Fatal("prepare did not preserve original signed content", err)
		}
	}
	if _, err = os.Stat(filepath.Join(destination, "current.json")); !os.IsNotExist(err) {
		t.Fatal("prepare selected a pointer")
	}
	fresh, _ := New(destination, key)
	got, err := fresh.ReadCatalog(set.ID)
	if err != nil || !reflect.DeepEqual(got, set) {
		t.Fatal("restart lost prepared content", err)
	}
	if _, err = Import(directory, destination, set.ID, key, ""); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(filepath.Join(destination, "current.json"))
	if _, err = Prepare(directory, destination, set.ID, key, set.ID); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(destination, "current.json"))
	if !bytes.Equal(original, after) {
		t.Fatal("prepare changed accepted pointer")
	}
	if directory, err := ReceiveArchiveAt(io.MultiReader(io.NewSectionReader(archive, 0, archiveEntry.Size()), bytes.NewReader([]byte{'x'})), set.ID, key, workRoot); err == nil {
		os.RemoveAll(directory)
		t.Fatal("trailing archive bytes accepted")
	}
}

func TestReviewedPreparedCatalogRechecksConcurrentPointerBeforeSelection(t *testing.T) {
	if *reviewedStore == "" || *reviewedPublic == "" {
		t.Skip("requires real signed package store with previous catalog")
	}
	key, err := control.ReadReleasePublicKey(*reviewedPublic)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := New(*reviewedStore, key)
	next, err := source.Read()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(*reviewedStore, "catalogs"))
	if err != nil {
		t.Fatal(err)
	}
	var priorID string
	var generation control.U64
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(*reviewedStore, "catalogs", entry.Name(), "catalog.json"))
		if err != nil {
			continue
		}
		signature, err := os.ReadFile(filepath.Join(*reviewedStore, "catalogs", entry.Name(), "catalog.sig"))
		if err != nil {
			continue
		}
		catalog, err := control.VerifyReleaseCatalog(body, signature, key)
		if err == nil && catalog.Generation < next.Catalog.Generation && catalog.Generation > generation {
			priorID = control.ReleaseDigest(body)
			generation = catalog.Generation
		}
	}
	if priorID == "" {
		t.Skip("store has no earlier signed catalog")
	}
	target := filepath.Join(t.TempDir(), "target")
	if _, err = Import(*reviewedStore, target, priorID, key, ""); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(target, "current.json"))
	if _, err = Prepare(*reviewedStore, target, next.ID, key, priorID); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(target, "current.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("preparation advanced an existing pointer")
	}
	if _, err = Import(target, target, next.ID, key, control.ReleaseDigest([]byte("demo-stale-plan"))); err == nil {
		t.Fatal("stale publisher selected prepared catalog")
	}
	after, _ = os.ReadFile(filepath.Join(target, "current.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("rejected stale plan changed current")
	}
	if _, err = Import(target, target, next.ID, key, priorID); err != nil {
		t.Fatal(err)
	}
	if _, err = Import(*reviewedStore, target, priorID, key, next.ID); err == nil {
		t.Fatal("later invocation rolled back accepted generation")
	}
}
