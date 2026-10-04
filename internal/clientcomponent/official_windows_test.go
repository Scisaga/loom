//go:build windows

package clientcomponent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"runtime"
	"testing"

	"loom/internal/clientruntime"
)

func TestReviewedComponentNativeInstall(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("unsupported native architecture")
	}
	files := sourceBuildFiles(t, runtime.GOARCH)
	wintunBody := pinnedWintun(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x57}, ed25519.SeedSize))
	artifact, err := Build(runtime.GOARCH, 1, files, wintunBody, key)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	installed, err := InstallWindows(root, artifact.Package, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !installed.Changed {
		t.Fatal("first native component install reported no change")
	}
	loaded, err := LoadWindows(root, key.Public().(ed25519.PublicKey), runtime.GOARCH, DataPlaneVersion)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SlotID != installed.Slot.ID {
		t.Fatal("native component load selected a different slot")
	}
	if err := VerifyAuthenticode(loaded.Wintun); err != nil {
		t.Fatalf("installed Wintun signature is invalid: %v", err)
	}
	if err := VerifyAuthenticode(loaded.SingBox); err == nil {
		t.Fatal("unsigned upstream sing-box unexpectedly passed Authenticode")
	}
	minimal := []byte(`{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}]}`)
	if err := clientruntime.RunSingBoxCheck(context.Background(), loaded.SingBox, minimal, t.TempDir()); err != nil {
		t.Fatalf("pinned sing-box executable check failed: %v", err)
	}
}
