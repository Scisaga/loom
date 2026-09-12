//go:build linux

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
	"strings"
	"testing"
	"time"
)

func TestLinuxInternalCAPoolRequiresExactCanonicalCAProfile(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Loom internal CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if roots, err := linuxInternalCAPool(body); err != nil || roots == nil {
		t.Fatalf("valid internal CA 被拒绝: %v", err)
	}
	if _, err := linuxInternalCAPool(append([]byte(" \n"), body...)); err == nil {
		t.Fatal("接受了带前置垃圾的 PEM")
	}
	leaf := *template
	leaf.IsCA = false
	leaf.KeyUsage = x509.KeyUsageDigitalSignature
	leafDER, err := x509.CreateCertificate(rand.Reader, &leaf, &leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := linuxInternalCAPool(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})); err == nil {
		t.Fatal("把非 CA leaf 接受为 internal trust root")
	}
}

func TestReadExactLinuxV2JSONRejectsEquivalentNoncanonicalInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "value.json")
	if err := os.WriteFile(path, []byte(" {\"schema\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var value struct {
		Schema int `json:"schema"`
	}
	if err := readExactLinuxV2JSON(path, 1024, &value); err == nil || !strings.Contains(err.Error(), "exact canonical") {
		t.Fatalf("非 canonical private 输入未被拒绝: %v", err)
	}
}

func TestLinuxPrivateV2CommandsRequirePinnedAuthorityInputs(t *testing.T) {
	for _, args := range [][]string{{"sync-v2-view"}, {"report-v2"}} {
		if err := cmdClient(args); err == nil ||
			(!strings.Contains(err.Error(), "用法") && !strings.Contains(err.Error(), "[D131 Linux private]")) {
			t.Fatalf("%v 缺 authority 输入未失败关闭: %v", args, err)
		}
	}
}
