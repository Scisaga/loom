package controlplane

import (
	"bytes"
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

	"loom/internal/wire"
)

func TestWindowsRuntimeArtifactProducerPublishesExactDeviceRef(t *testing.T) {
	input := WindowsRuntimeProjectionV1{
		ClusterID: "demo-cluster", DeviceID: "demo-device", DeviceGeneration: 3,
		Generation: 8, SingBoxVersion: "v1.11.4", CABundlePEM: controlWindowsTestCA(t),
		CredentialRefs: []string{"agent-api", "edge-password"},
		AgentConfig:    []byte(`{"api_secret":"${secret:agent-api}"}`),
		SingBoxConfig:  []byte(`{"password":"${secret:edge-password}"}`),
	}
	one, err := BuildWindowsRuntimeArtifact(input)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildWindowsRuntimeArtifact(input)
	if err != nil || !bytes.Equal(one, two) {
		t.Fatalf("Windows runtime producer 不确定: err=%v", err)
	}
	root := t.TempDir()
	ref, publishedPath, err := PublishWindowsRuntimeArtifact(root, input)
	if err != nil {
		t.Fatal(err)
	}
	wantHash, _ := wire.DeviceConfigArtifactContentHash(one)
	if ref.ArtifactID != wire.WindowsRuntimeArtifactID || ref.Generation != input.Generation ||
		ref.Platform != "windows-desktop" || ref.RenderContractID != wire.WindowsRuntimeRenderContract ||
		ref.ContentHash != wantHash || ref.SizeBytes != int64(len(one)) {
		t.Fatalf("unexpected Windows runtime ref: %+v", ref)
	}
	published, err := os.ReadFile(filepath.Join(root,
		filepath.FromSlash(strings.TrimPrefix(publishedPath, "/"))))
	if err != nil || !bytes.Equal(published, one) {
		t.Fatalf("published exact Windows runtime bytes mismatch: err=%v", err)
	}

	input.CredentialRefs = []string{"edge-password", "agent-api"}
	if _, err := BuildWindowsRuntimeArtifact(input); err == nil {
		t.Fatal("producer 接受了非规范 credential ref 顺序")
	}
}

func controlWindowsTestCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Loom test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
