package clientrelease

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"loom/internal/control"
)

func TestTransferRejectsUnownedMembersBeforeCatalogAcceptance(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, 32)).Public().(ed25519.PublicKey)
	for _, name := range []string{"../demo", "current.json", "bin/not-a-digest", "materials/demo.json"} {
		var body bytes.Buffer
		writer := tar.NewWriter(&body)
		writer.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: 1, Typeflag: tar.TypeReg})
		writer.Write([]byte("x"))
		writer.Close()
		if directory, err := ReceiveArchive(&body, control.ReleaseDigest([]byte("demo")), key); err == nil {
			os.RemoveAll(directory)
			t.Fatal("unreferenced transfer member accepted", name)
		}
	}
}

func TestReviewedPrepareAndTransferPreservePointerAndSignedBytes(t *testing.T) {
	if *reviewedStore == "" || *reviewedPublic == "" {
		t.Skip("requires explicit signed package store and independent public key")
	}
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
	var archive bytes.Buffer
	if err = WriteArchive(*reviewedStore, set.ID, key, &archive, nil); err != nil {
		t.Fatal(err)
	}
	directory, err := ReceiveArchive(bytes.NewReader(archive.Bytes()), set.ID, key)
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
	if directory, err := ReceiveArchive(bytes.NewReader(append(archive.Bytes(), 'x')), set.ID, key); err == nil {
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
