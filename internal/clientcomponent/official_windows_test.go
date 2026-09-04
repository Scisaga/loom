//go:build windows

package clientcomponent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"runtime"
	"testing"

	"loom/internal/clientruntime"
)

func TestOfficialComponentNativeInstall(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("unsupported native architecture")
	}
	singPath := os.Getenv("LOOM_SING_BOX_AMD64_ARCHIVE")
	if runtime.GOARCH == "arm64" {
		singPath = os.Getenv("LOOM_SING_BOX_ARM64_ARCHIVE")
	}
	wintunPath := os.Getenv("LOOM_WINTUN_ARCHIVE")
	if singPath == "" || wintunPath == "" {
		t.Skip("set official archive paths to run the native component probe")
	}
	singBody, err := os.ReadFile(singPath)
	if err != nil {
		t.Fatal(err)
	}
	wintunBody, err := os.ReadFile(wintunPath)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x57}, ed25519.SeedSize))
	artifact, err := BuildOfficial(runtime.GOARCH, singBody, wintunBody, key)
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
	loaded, err := LoadWindows(root, key.Public().(ed25519.PublicKey), runtime.GOARCH, "1.11.4")
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
