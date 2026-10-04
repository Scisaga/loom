package linuxclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/control"
)

func resourceExecutionFixture(t *testing.T) (control.DeviceView, string, time.Time) {
	t.Helper()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Demo resource root"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, public, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"demo.example"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input := ResourceListenerInput{ResourceID: "demo-resource", Listen: "192.0.2.10:443", CertificateFile: filepath.Join(dir, "certificate.pem"), KeyFile: filepath.Join(dir, "key.pem")}
	for path, block := range map[string]*pem.Block{input.CertificateFile: {Type: "CERTIFICATE", Bytes: der}, input.KeyFile: {Type: "PRIVATE KEY", Bytes: keyDER}} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "inputs.json")
	if err := atomicJSON(path, ResourceInputs{Schema: 3, Listeners: []ResourceListenerInput{input}}); err != nil {
		t.Fatal(err)
	}
	name, roots := "demo.example", []string{base64.RawURLEncoding.EncodeToString(caDER)}
	view := control.DeviceView{DeviceID: "demo-exit", Resources: []control.TransportResource{{ID: input.ResourceID, Kind: "hysteria2", OwnerNodeID: "demo-exit", ListenerID: "demo-listener", DialHost: "192.0.2.10", DialPort: 443,
		Authentication: control.ResourceAuthentication{ServerName: &name, CACertificates: &roots}}}, InboundCredentials: []control.InboundCredential{}}
	return view, path, now
}

func TestResourceExecutionRequiresProtectedInputsAndCertifiedTLS(t *testing.T) {
	view, path, now := resourceExecutionFixture(t)
	executions, err := prepareHY2Executions(view, path, now)
	if err != nil || len(executions) != 1 {
		t.Fatal("valid execution material rejected", err)
	}
	if _, err := nodeRuntimeConfig(view, "demo-secret", nil, "tun", executions); err == nil {
		t.Fatal("server listener was coupled to access TUN")
	}
	if _, err := prepareHY2Executions(view, path, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired leaf could start a listener")
	}
	wrongName := "other.example"
	view.Resources[0].Authentication.ServerName = &wrongName
	if _, err := prepareHY2Executions(view, path, now); err == nil {
		t.Fatal("local certificate bypassed the signed verification name")
	}
	view, path, now = resourceExecutionFixture(t)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareHY2Executions(view, path, now); err == nil {
		t.Fatal("unprotected execution inputs were accepted")
	}
}

func TestUnusedResourceInputsCannotCreateServerAuthority(t *testing.T) {
	view, path, now := resourceExecutionFixture(t)
	view.Resources = []control.TransportResource{}
	executions, err := prepareHY2Executions(view, path, now)
	if err != nil || len(executions) != 0 {
		t.Fatal("local inputs manufactured an owned resource", err)
	}
	config, err := nodeRuntimeConfig(view, "demo-secret", nil, "mixed", executions)
	if err != nil || strings.Contains(config, "hysteria2") || strings.Contains(config, "certificate_path") {
		t.Fatal("withdrawn resource retained a server listener", err)
	}
}
