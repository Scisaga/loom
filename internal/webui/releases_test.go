package webui

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"loom/internal/clientrelease"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseCatalogAndDownloadsUseTheSameVerifiedBytes(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	input := filepath.Join(t.TempDir(), "demo-client.zip")
	body := []byte("demo client content")
	os.WriteFile(input, body, 0600)
	_, err := clientrelease.Build(root, []clientrelease.Input{{Path: input, Platform: "windows-desktop", Arch: "amd64", Variant: "installed", Version: "demo", SourceCommit: strings.Repeat("a", 40), Signing: "Preview · no Authenticode"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	d := clientUIDeps()
	d.Admin = true
	d.Control.Clients.Releases = &clientrelease.Store{Root: root, Key: pub}
	w := browserRequest(d, "GET", "/api/control/ui/releases", "")
	var catalog struct {
		Artifacts []struct {
			URL string `json:"url"`
		}
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &catalog) != nil || len(catalog.Artifacts) != 1 {
		t.Fatalf("catalog %d %s", w.Code, w.Body.String())
	}
	w = browserRequest(d, "GET", catalog.Artifacts[0].URL, "")
	if w.Code != 200 || w.Body.String() != string(body) || !strings.Contains(w.Header().Get("Content-Disposition"), "demo-client.zip") {
		t.Fatal("normal package download differs from catalog")
	}
	d.Admin = false
	if browserRequest(d, "GET", catalog.Artifacts[0].URL, "").Code != 403 {
		t.Fatal("download bypassed administrator boundary")
	}
}
