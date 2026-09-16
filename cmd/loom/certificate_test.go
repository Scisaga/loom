package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/certmanager"
)

func TestExistingCertificateCommandProducesReloadablePublicBinding(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Demo root"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: root.NotBefore, NotAfter: root.NotAfter,
		DNSNames: []string{"demo-edge.example.test"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, leafKey.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	request := certmanager.ExistingCertificateRequestV1{Schema: 1, RequestID: "demo-import", ClusterID: "demo-cluster", DeviceID: "demo-edge",
		IdentityID: "demo-edge-tls", IdentityGeneration: 1, CertificateGeneration: 1, EndpointIDs: []string{"demo-bootstrap"},
		DNSNames: leaf.DNSNames, IssuerProfileRef: "public-webpki", CertificatePath: filepath.Join(dir, "certificate.pem"), PrivateKeyPath: filepath.Join(dir, "key.pem")}
	input, out, materials := filepath.Join(dir, "input.json"), filepath.Join(dir, "binding.json"), filepath.Join(dir, "materials")
	body, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string][]byte{input: body, request.CertificatePath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		request.PrivateKeyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})} {
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	args := []string{"-input", input, "-artifact-dir", materials, "-out", out}
	if err := prepareExistingCertificateCommand(args, roots, now); err != nil {
		t.Fatal(err)
	}
	var binding certmanager.ExistingCertificateBindingV1
	if err := readCanonicalFile(out, 2<<20, &binding); err != nil {
		t.Fatal(err)
	}
	if _, err := certmanager.LoadExistingRuntimeCertificate(materials, binding, binding.Identity, roots, now); err != nil {
		t.Fatal(err)
	}
	if err := prepareExistingCertificateCommand(args, roots, now); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("previous result"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepareExistingCertificateCommand(args, roots, now); err == nil {
		t.Fatal("覆盖了不同输出")
	}
	if err := cmdCertificate([]string{"prepare-existing", "-input", input, "-artifact-dir", materials, "-out", out}); err == nil {
		t.Fatal("生产 CLI 接受未受系统信任的证书")
	}
}
