package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/publish"
	"loom/internal/render"
	"loom/internal/snapshot"
)

func TestVerifyPublishedEvidenceThroughCLI(t *testing.T) {
	// Match the publisher's actual layout: raw signature, JSON node bundles,
	// and content-addressed binaries alongside the snapshot directory.
	for _, test := range []struct {
		name    string
		edit    func(t *testing.T, root string, manifest *snapshot.Manifest, write func(string, []byte))
		rewrite func([]byte) []byte
		bad     bool
	}{
		{name: "publisher-layout"},
		{name: "signed-unknown-field", bad: true, rewrite: func(body []byte) []byte {
			return append([]byte(`{"unrecognized":true,`), body[1:]...)
		}},
		{name: "signed-duplicate-field", bad: true, rewrite: func(body []byte) []byte {
			return append([]byte(`{"id":"aaaaaaaaaaaa",`), body[1:]...)
		}},
		{name: "tampered-bundle", bad: true, edit: func(t *testing.T, root string, manifest *snapshot.Manifest, write func(string, []byte)) {
			body, _ := json.Marshal(publish.Bundle{Owner: "demo-node", Files: map[string]string{"demo.conf": "changed"}})
			write(manifest.ID+"/nodes/demo-node.json", body)
		}},
		{name: "tampered-binary-same-length", bad: true, edit: func(t *testing.T, root string, manifest *snapshot.Manifest, write func(string, []byte)) {
			write(manifest.Binaries[0].Path(), []byte("demo-binarz"))
		}},
		{name: "missing-binary", bad: true, edit: func(t *testing.T, root string, manifest *snapshot.Manifest, write func(string, []byte)) {
			if err := os.Remove(filepath.Join(root, manifest.Binaries[0].Path())); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "duplicate-bundle", bad: true, edit: func(t *testing.T, root string, manifest *snapshot.Manifest, write func(string, []byte)) {
			manifest.Bundles = append(manifest.Bundles, manifest.Bundles[0])
		}},
		{name: "escaped-bundle", bad: true, edit: func(t *testing.T, root string, manifest *snapshot.Manifest, write func(string, []byte)) {
			manifest.Bundles[0].Owner = "../demo-outside"
		}},
		{name: "escaped-binary-link", bad: true, edit: func(t *testing.T, root string, manifest *snapshot.Manifest, write func(string, []byte)) {
			outside := filepath.Join(t.TempDir(), "demo-binary")
			if err := os.WriteFile(outside, []byte("demo-binary"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, manifest.Binaries[0].Path())
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			pub, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			write := func(relative string, data []byte) {
				t.Helper()
				path := filepath.Join(root, relative)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			bundle := render.Bundle{Owner: "demo-node", Files: []render.File{{Path: "demo.conf", Content: "demo value\n"}}}
			binary := []byte("demo-binary")
			digest := sha256.Sum256(binary)
			manifest := snapshot.Manifest{ID: "aaaaaaaaaaaa", CreatedAt: "2026-01-01T00:00:00Z",
				Bundles:  []snapshot.BundleRef{{Owner: bundle.Owner, Hash: bundle.Hash()}},
				Binaries: []snapshot.BinaryRef{{OS: "linux", Arch: "amd64", SHA256: hex.EncodeToString(digest[:]), Size: len(binary)}}}
			body, _ := json.Marshal(publish.Bundle{Owner: bundle.Owner, Files: map[string]string{bundle.Files[0].Path: bundle.Files[0].Content}})
			write(manifest.ID+"/nodes/demo-node.json", body)
			write(manifest.Binaries[0].Path(), binary)
			write("platform.pub", []byte(base64.StdEncoding.EncodeToString(pub)+"\n"))
			if test.edit != nil {
				test.edit(t, root, &manifest, write)
			}
			body, err = manifest.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if test.rewrite != nil {
				body = test.rewrite(body)
			}
			write(manifest.ID+"/snapshot.json", body)
			write(manifest.ID+"/snapshot.sig", ed25519.Sign(private, body))
			args := []string{filepath.Join(root, manifest.ID), "-pubkey", filepath.Join(root, "platform.pub")}
			err = cmdVerify(args)
			if (err != nil) != test.bad {
				t.Fatalf("verify error = %v; rejection wanted = %t", err, test.bad)
			}
			if !test.bad {
				write(manifest.ID+"/snapshot.sig", make([]byte, ed25519.SignatureSize))
				if err := cmdVerify(args); err == nil {
					t.Fatal("invalid manifest signature accepted")
				}
			}
		})
	}
}
