package deviceclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testPublicCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-data-plane-ca"},
		NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4102444800, 0), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestSavePublicDataPlaneCAValidatesAndAtomicallyReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls", "ca.crt")
	value := testPublicCA(t)
	if err := SavePublicDataPlaneCA(path, value); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != value {
		t.Fatalf("saved CA mismatch: err=%v", err)
	}
	if err := SavePublicDataPlaneCA(path, "not a certificate"); err == nil {
		t.Fatal("invalid replacement was accepted")
	}
	body, _ = os.ReadFile(path)
	if string(body) != value {
		t.Fatal("invalid replacement damaged the prior CA")
	}
}
