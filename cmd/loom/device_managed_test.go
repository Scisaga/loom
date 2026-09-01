package main

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

func TestVerifiedManagedCertificateRequiresExactCAAndDeviceIdentity(t *testing.T) {
	certPath, caPath := managedCertificateFixture(t, "edge01")
	publicKey, notBefore, err := verifiedManagedCertificate("edge01", certPath, caPath)
	if err != nil || publicKey == "" || notBefore == "" {
		t.Fatalf("verified certificate key=%q notBefore=%q err=%v", publicKey, notBefore, err)
	}
	if _, _, err := verifiedManagedCertificate("other01", certPath, caPath); err == nil {
		t.Fatal("certificate with another Device SAN was accepted")
	}
	_, unrelatedCA := managedCertificateFixture(t, "unrelated")
	if _, _, err := verifiedManagedCertificate("edge01", certPath, unrelatedCA); err == nil {
		t.Fatal("certificate from another CA was accepted")
	}
}

func managedCertificateFixture(t *testing.T, deviceID string) (string, string) {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Loom CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dnsName := deviceID + ".node.internal"
	deviceTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	deviceDER, err := x509.CreateCertificate(rand.Reader, deviceTemplate, ca, &deviceKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.crt")
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: deviceDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, caPath
}
