//go:build linux

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/clientmigration"
	"loom/internal/clientv2"
	"loom/internal/wire"
)

func TestLinuxMigrationExportUsesOriginalIdentityAndPreservesInputs(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, issuer, issuerKey, err := makeCertificateAuthority("demo-original-ca", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject: pkix.Name{CommonName: "demo-server"}, DNSNames: []string{"demo-server.node.internal"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	platform, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := wire.MarshalCanonical(clientmigration.Floor{Schema: 1, Generation: 5,
		PayloadSHA256: strings.Repeat("a", 64), SelectedSnapshot: strings.Repeat("b", 12)})
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string][]byte{
		"original.key":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}),
		"original.crt":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}),
		"original-ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw}),
		"platform.pub":    []byte(base64.StdEncoding.EncodeToString(platform)), "floor.json": floor,
	}
	for name, body := range inputs {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(dir, "request.json")
	stateDir := filepath.Join(dir, "client-v2")
	args := []string{"export-migration-request", "-device", "demo-server", "-state-dir", stateDir,
		"-identity-key", filepath.Join(dir, "original.key"), "-identity-cert", filepath.Join(dir, "original.crt"),
		"-identity-ca", filepath.Join(dir, "original-ca.crt"), "-platform-pubkey", filepath.Join(dir, "platform.pub"),
		"-floor", filepath.Join(dir, "floor.json"), "-out", output}
	if err := cmdClient(args); err != nil {
		t.Fatal(err)
	}
	var first wire.RuntimeDeviceMigrationRequestV1
	if err := readCanonicalFile(output, 1<<20, &first); err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(key.Public())
	identityHash, _ := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, public)
	if err := wire.VerifyRuntimeDeviceMigrationRequest(&first, identityHash, fmt.Sprintf("sha256:%x", sha256.Sum256(platform))); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Body.LegacyFloor, floor) || first.Body.Platform != "linux-server" ||
		first.Body.IdentitySPKIDER != base64.RawURLEncoding.EncodeToString(public) {
		t.Fatal("正常 CLI 未保留原身份和 floor")
	}
	identity, err := clientv2.LoadEnrollmentIdentityForResume(filepath.Join(stateDir, "identity.json"))
	if err != nil || identity.WrappingPublicKeySPKI != first.Body.WrappingSPKIDER {
		t.Fatal("封装密钥未保存供迁移导入复用", err)
	}
	if err := cmdClient(args); err != nil {
		t.Fatal(err)
	}
	var second wire.RuntimeDeviceMigrationRequestV1
	if err := readCanonicalFile(output, 1<<20, &second); err != nil || !wire.EqualCanonical(first.Body, second.Body) {
		t.Fatal("重试改变了原身份迁移请求", err)
	}
	for name, body := range inputs {
		actual, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(body, actual) {
			t.Fatal("迁移导出改写了原始材料", name, err)
		}
	}
	args[2] = "demo-other-server"
	if err := cmdClient(args); err == nil {
		t.Fatal("原证书被用于另一个 Device 的迁移请求")
	}
}
