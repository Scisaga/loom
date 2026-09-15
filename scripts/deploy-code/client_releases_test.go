//go:build !windows

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"loom/internal/clientrelease"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientReleasePublicationCopiesOnlyDesignatedMirrorsThenActivatesCatalog(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	source := t.TempDir()
	input := filepath.Join(t.TempDir(), "demo-client.zip")
	os.WriteFile(input, []byte("demo release"), 0600)
	catalog, err := clientrelease.Build(source, []clientrelease.Input{{Path: input, Platform: "windows-desktop", Version: "demo", SourceCommit: strings.Repeat("c", 40), Signing: "Preview"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	mirror := t.TempDir()
	store := t.TempDir()
	c := config{clientReleases: source, clientStore: store, outputs: []string{mirror}}
	var out bytes.Buffer
	if err = publishClientReleases(c, pub, &out); err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(mirror, "client-releases", catalog.Artifacts[0].Path)
	before, err := os.Stat(blob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(mirror, "client-releases", "current.json")); !os.IsNotExist(err) {
		t.Fatal("mutable pointer exposed on public mirror")
	}
	if err = publishClientReleases(c, pub, &out); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(blob)
	if !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
		t.Fatal("unchanged artifact copied again")
	}
	s := clientrelease.Store{Root: store, Key: pub}
	if _, err = s.Load(); err != nil {
		t.Fatal(err)
	}
}
