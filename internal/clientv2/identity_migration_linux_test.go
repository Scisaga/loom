//go:build linux

package clientv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

func TestLinuxMigrationKeepsOriginalKeyAndDurableWrapping(t *testing.T) {
	original, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "identity.json")
	first, err := ImportLinuxMigrationIdentity(path, original)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ImportLinuxMigrationIdentity(path, original)
	if err != nil || !wire.EqualCanonical(first, second) {
		t.Fatalf("重试改变了密钥: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := ImportLinuxMigrationIdentity(path, other); err == nil {
		t.Fatal("迁移覆盖了原身份")
	}
	body := wire.RuntimeDeviceMigrationRequestBodyV1{Schema: 1, DeviceID: "demo-server", Platform: "linux-server",
		PlatformKeyHash: wire.HashRaw("demo-platform", []byte("key")), IdentitySPKIDER: first.IdentityPublicKeySPKI,
		WrappingSPKIDER: first.WrappingPublicKeySPKI, WrappingKeyProfile: "p256-root-only-pkcs8-ecdh-v1",
		LegacyFloor: json.RawMessage(`{"generation":1,"schema":1}`)}
	request, err := first.SignMigrationRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := first.IdentitySPKIHash()
	if err != nil || wire.VerifyRuntimeDeviceMigrationRequest(&request, hash, body.PlatformKeyHash) != nil {
		t.Fatalf("原身份未验证迁移请求: %v", err)
	}
	request.Body.DeviceID = "demo-other"
	if wire.VerifyRuntimeDeviceMigrationRequest(&request, hash, body.PlatformKeyHash) == nil {
		t.Fatal("接受被改写的迁移设备")
	}
}
