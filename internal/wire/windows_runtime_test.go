package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestWindowsRuntimeArtifactRequiresExactRedactionAndCanonicalCA(t *testing.T) {
	ca := windowsRuntimeTestCertificate(t, true)
	artifact := WindowsRuntimeArtifactV1{
		Schema: 1, ClusterID: "demo-cluster", DeviceID: "demo-device",
		DeviceGeneration: 2, Generation: 7, SingBoxVersion: "v1.11.4",
		CABundlePEM: string(ca), CredentialRefs: []string{"agent-api", "edge-password"},
		Files: []WindowsRuntimeFileV1{
			{Path: "agent/config.json", Content: `{"api_secret":"${secret:agent-api}"}`},
			{Path: "sing-box/config.json", Content: `{"password":"${secret:edge-password}"}`},
		},
	}
	if err := ValidateWindowsRuntimeArtifact(&artifact); err != nil {
		t.Fatal(err)
	}

	literal := artifact
	literal.Files = append([]WindowsRuntimeFileV1(nil), artifact.Files...)
	literal.Files[1].Content = `{"password":"literal"}`
	if err := ValidateWindowsRuntimeArtifact(&literal); err == nil {
		t.Fatal("公开 Windows runtime 接受了明文 password")
	}

	unsorted := artifact
	unsorted.CredentialRefs = []string{"edge-password", "agent-api"}
	if err := ValidateWindowsRuntimeArtifact(&unsorted); err == nil {
		t.Fatal("未排序 credential refs 被接受")
	}

	extra := artifact
	extra.CredentialRefs = []string{"agent-api", "edge-password", "unused"}
	if err := ValidateWindowsRuntimeArtifact(&extra); err == nil {
		t.Fatal("未被 placeholder 引用的 credential ref 被接受")
	}

	nonCA := artifact
	nonCA.CABundlePEM = string(windowsRuntimeTestCertificate(t, false))
	if err := ValidateWindowsRuntimeArtifact(&nonCA); err == nil {
		t.Fatal("非 CA certificate 被接受为 runtime trust bundle")
	}

	nonCanonical := artifact
	nonCanonical.CABundlePEM += "\n"
	if err := ValidateWindowsRuntimeArtifact(&nonCanonical); err == nil {
		t.Fatal("非规范 PEM bundle 被接受")
	}
}

func windowsRuntimeTestCertificate(t *testing.T, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Loom test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
