package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/bootstrapaccess"
	"loom/internal/rotation"
	"loom/internal/wire"
)

func TestBootstrapProbeOuterCommandWritesCanonicalSignedObservation(t *testing.T) {
	listener, rootsPEM, serverTLS, pin := bootstrapProbeTLSFixture(t)
	defer listener.Close()
	handshake := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			handshake <- err
			return
		}
		connection := tls.Server(raw, serverTLS)
		err = connection.Handshake()
		_ = connection.Close()
		handshake <- err
	}()

	now := time.Now().UTC().Truncate(time.Second)
	address := listener.Addr().(*net.TCPAddr)
	plan := bootstrapaccess.BootstrapOuterProbePlanV1{
		Schema: 1, ClusterID: "demo-cluster", RotationID: "rotation-a",
		FrozenDependenciesHash: bootstrapProbeTestHash(0x11), EndpointSetHash: bootstrapProbeTestHash(0x12),
		EndpointID: "bootstrap-tcp", LogicalServerID: "demo-server", Transport: "trojan_tls",
		ListenerGeneration: 2, ServerName: "bootstrap.example", SPKIPins: []string{pin},
		Targets:   []rotation.Tuple{{Transport: "tcp", Address: "127.0.0.1", Port: int64(address.Port)}},
		ValidFrom: now.Add(-time.Minute).Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339),
	}
	planBody, err := wire.MarshalCanonical(plan)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	planPath := filepath.Join(directory, "plan.json")
	keyPath := filepath.Join(directory, "observer.key")
	caPath := filepath.Join(directory, "roots.pem")
	outPath := filepath.Join(directory, "observation.json")
	files := []struct {
		path string
		body []byte
		mode os.FileMode
	}{
		{planPath, planBody, 0o644},
		{keyPath, []byte(base64.StdEncoding.EncodeToString(privateKey) + "\n"), 0o600},
		{caPath, rootsPEM, 0o644},
	}
	for _, file := range files {
		if err := os.WriteFile(file.path, file.body, file.mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmdBootstrap([]string{"probe-outer", "-plan", planPath, "-observer-id", "observer-a",
		"-key", keyPath, "-ca", caPath, "-o", outPath, "-timeout", "5s"}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-handshake:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("observer CLI 未完成真实 TLS handshake")
	}
	reportBody, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(outPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("observation mode=%v err=%v, want 0600", info, err)
	}
	var report bootstrapaccess.SignedBootstrapOuterProbeObservationV1
	canonical, err := wire.DecodeStrict(reportBody, 1<<20, &report)
	if err != nil || !bytes.Equal(reportBody, canonical) {
		t.Fatalf("observation 不是 exact canonical JSON: %v", err)
	}
	if report.Body.ObserverID != "observer-a" || len(report.Body.Results) != 1 ||
		report.Body.Results[0].Target != plan.Targets[0] || report.Body.Results[0].LeafSPKIHash != pin ||
		report.Body.Results[0].TLSVersion != int64(tls.VersionTLS13) || report.Body.Results[0].NegotiatedProtocol != "" {
		t.Fatalf("observation 内容异常: %#v", report)
	}
	observation, err := wire.MarshalCanonical(report.Body)
	if err != nil {
		t.Fatal(err)
	}
	message, err := wire.Frame("loom-bootstrap-outer-probe-signature-v1", observation)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(report.Signature.Signature)
	if err != nil || !ed25519.Verify(publicKey, message, signature) {
		t.Fatalf("CLI observation signature 无效: %v", err)
	}
	wantKeyID := sha256.Sum256(publicKey)
	if report.Signature.ObserverKeyID != "sha256:"+hex.EncodeToString(wantKeyID[:]) {
		t.Fatalf("observer key ID=%q", report.Signature.ObserverKeyID)
	}
}

func TestBootstrapProbeOuterCommandRejectsAmbiguousInputsWithoutOutput(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	plan := bootstrapaccess.BootstrapOuterProbePlanV1{
		Schema: 1, ClusterID: "demo-cluster", RotationID: "rotation-a",
		FrozenDependenciesHash: bootstrapProbeTestHash(0x21), EndpointSetHash: bootstrapProbeTestHash(0x22),
		EndpointID: "bootstrap-tcp", LogicalServerID: "demo-server", Transport: "trojan_tls",
		ListenerGeneration: 1, ServerName: "bootstrap.example", SPKIPins: []string{bootstrapProbeTestHash(0x23)},
		Targets:   []rotation.Tuple{{Transport: "tcp", Address: "127.0.0.1", Port: 1}},
		ValidFrom: now.Add(-time.Minute).Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339),
	}
	canonical, err := wire.MarshalCanonical(plan)
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	planPath := filepath.Join(directory, "plan.json")
	keyPath := filepath.Join(directory, "observer.key")
	outPath := filepath.Join(directory, "observation.json")
	if err := os.WriteFile(planPath, append([]byte(" "), canonical...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outPath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdBootstrap([]string{"probe-outer", "-plan", planPath, "-observer-id", "observer-a",
		"-key", keyPath, "-o", outPath}); err == nil {
		t.Fatal("非 canonical plan 被接受")
	}
	if body, err := os.ReadFile(outPath); err != nil || string(body) != "keep" {
		t.Fatalf("失败探测覆盖了既有 observation: body=%q err=%v", body, err)
	}

	if err := os.WriteFile(planPath, canonical, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdBootstrap([]string{"probe-outer", "-plan", planPath, "-observer-id", "observer-a",
		"-key", keyPath, "-o", outPath}); err == nil {
		t.Fatal("权限过宽的 observer 私钥被接受")
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(directory, "observer-link.key")
	if err := os.Symlink(keyPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if err := cmdBootstrap([]string{"probe-outer", "-plan", planPath, "-observer-id", "observer-a",
		"-key", linkPath, "-o", outPath}); err == nil {
		t.Fatal("symlink observer 私钥被接受")
	}
	caPath := filepath.Join(directory, "mixed-ca.pem")
	if err := os.WriteFile(caPath, []byte("untrusted-prefix\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdBootstrap([]string{"probe-outer", "-plan", planPath, "-observer-id", "observer-a",
		"-key", keyPath, "-ca", caPath, "-o", outPath}); err == nil {
		t.Fatal("混杂非 PEM 内容的 CA bundle 被接受")
	}
	if err := cmdBootstrap([]string{"probe-outer", "-plan", planPath, "-observer-id", "observer-a",
		"-key", keyPath, "-o", keyPath}); err == nil {
		t.Fatal("observation 获准覆盖 observer 私钥")
	}
}

func bootstrapProbeTLSFixture(t *testing.T) (net.Listener, []byte, *tls.Config, string) {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Bootstrap Observer Test CA"},
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
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "bootstrap.example"},
		DNSNames: []string{"bootstrap.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}},
		MinVersion:   tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	}
	return listener, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), serverTLS,
		"sha256:" + hex.EncodeToString(digest[:])
}

func bootstrapProbeTestHash(fill byte) string {
	return "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{fill}, sha256.Size))
}
