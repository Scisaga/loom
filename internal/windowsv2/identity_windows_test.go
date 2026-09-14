//go:build windows

package windowsv2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"loom/internal/clientsecret"
	"loom/internal/wire"
)

func TestNativeDPAPIDescriptorUsesNonExportableCNGIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json.dpapi")
	protector := clientsecret.UserProtector{}
	identity, err := OpenOrCreateIdentity(path, protector, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityHash, _ := identity.IdentitySPKIHash()
	wrappingHash, _ := identity.WrappingSPKIHash()
	if identityHash == wrappingHash {
		t.Fatal("CNG identity 与 DPAPI wrapping key 被复用")
	}
	digest := make([]byte, crypto.SHA256.Size())
	if _, err := rand.Read(digest); err != nil {
		t.Fatal(err)
	}
	signature, err := identity.Signer().Sign(rand.Reader, digest, crypto.SHA256)
	public, ok := identity.Signer().Public().(*ecdsa.PublicKey)
	if err != nil || !ok || !ecdsa.VerifyASN1(public, digest, signature) {
		t.Fatalf("CNG crypto.Signer round trip 失败: %v", err)
	}
	identity.Close()

	body, err := clientsecret.ReadProtected(path, IdentityPurpose, protector)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	var descriptor protectedIdentityV1
	canonical, err := wire.DecodeStrict(body, maximumIdentityState, &descriptor)
	if err != nil || !bytes.Equal(canonical, body) {
		t.Fatalf("读取 native identity descriptor: %v", err)
	}
	if descriptor.IdentityProvider != windowsCNGIdentityProvider ||
		descriptor.IdentityPrivateKeyPKCS8 != "" || descriptor.IdentityKeyName == "" ||
		descriptor.IdentityMachineScope || descriptor.WrappingPrivateKeyPKCS8 == "" {
		t.Fatal("CNG/DPAPI identity descriptor 边界错误")
	}
	record := platformIdentityRecord{Provider: descriptor.IdentityProvider,
		KeyName: descriptor.IdentityKeyName, MachineScope: descriptor.IdentityMachineScope}
	keyHandle, err := openWindowsCNGKey(record)
	if err != nil {
		t.Fatal(err)
	}
	privateBlob, _ := windows.UTF16PtrFromString("ECCPRIVATEBLOB")
	var privateBlobSize uint32
	status, _, _ := ncryptExportKey.Call(keyHandle, 0, uintptr(unsafe.Pointer(privateBlob)), 0,
		0, 0, uintptr(unsafe.Pointer(&privateBlobSize)), 0)
	freeWindowsCNGObject(keyHandle)
	if status == 0 {
		t.Fatal("CNG identity key 允许导出 private blob")
	}

	reloaded, err := LoadIdentity(path, protector)
	if err != nil {
		t.Fatal(err)
	}
	reloadedHash, _ := reloaded.IdentitySPKIHash()
	reloaded.Close()
	if reloadedHash != identityHash {
		t.Fatal("CNG persisted identity reload 改变 SPKI")
	}
	if err := DestroyIdentity(path, protector); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(path, protector); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("删除 CNG/DPAPI identity 后仍可加载: %v", err)
	}
	if handle, err := openWindowsCNGKey(record); err == nil {
		freeWindowsCNGObject(handle)
		t.Fatal("删除 DPAPI descriptor 后 CNG persisted key 仍存在")
	}
}
