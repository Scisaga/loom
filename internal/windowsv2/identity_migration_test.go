package windowsv2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityMigrationPreservesOriginalKeyAndRestartBinding(t *testing.T) {
	original, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroPrivateKey(original)
	expected, err := x509.MarshalPKIXPublicKey(&original.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.json.dpapi")
	migrated, err := ImportIdentity(path, testProtector{}, original, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrapping := migrated.WrappingSPKIDER()
	if !bytes.Equal(migrated.IdentitySPKIDER(), expected) || bytes.Equal(wrapping, expected) {
		t.Fatal("migration changed identity or reused signing key for wrapping")
	}
	digest := sha256.Sum256([]byte("demo-migration-signature"))
	signature, err := migrated.Signer().Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(&original.PublicKey, digest[:], signature) {
		t.Fatal("migrated signer is not original identity")
	}
	migrated.Close()
	t.Cleanup(func() {
		if err := DestroyIdentity(path, testProtector{}); err != nil {
			t.Error(err)
		}
	})
	replay, err := ImportIdentity(path, testProtector{}, original, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replay.IdentitySPKIDER(), expected) || !bytes.Equal(replay.WrappingSPKIDER(), wrapping) {
		t.Fatal("retry replaced a stable key")
	}
	replay.Close()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	different, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroPrivateKey(different)
	if result, err := ImportIdentity(path, testProtector{}, different, rand.Reader); err == nil {
		result.Close()
		t.Fatal("migration overwrote different installed key")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed migration changed durable identity")
	}
}
