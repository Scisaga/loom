package clientenroll

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareServerEnrollmentUsesStrictConfigAndKeepsPrivateKeyLocal(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "device.yaml")
	keyPath := filepath.Join(root, "wireguard", "node.key")
	config := `server:
  public_endpoint: edge.example.net
  direction: bidirectional
  country: cn
  city: Beijing
  provider: example
`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareServerEnrollment(configPath, keyPath, bytes.NewReader(bytes.Repeat([]byte{0x21}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if prepared.PublicEndpoint != "edge.example.net" || prepared.InboundPort != defaultServerInboundPort ||
		prepared.Direction != "bidirectional" || prepared.Country != "CN" || prepared.WGPublicKey == "" {
		t.Fatalf("prepared=%+v", prepared)
	}
	keyBody, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(keyBody), prepared.WGPublicKey) {
		t.Fatal("stored private key was replaced by the public key")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(keyBody)))
	if err != nil || len(decoded) != 32 {
		t.Fatalf("private key format=%q err=%v", keyBody, err)
	}
	again, err := PrepareServerEnrollment(configPath, keyPath, bytes.NewReader(bytes.Repeat([]byte{0x44}, 32)))
	if err != nil || again.WGPublicKey != prepared.WGPublicKey {
		t.Fatalf("reused server=%+v err=%v", again, err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("WireGuard key mode=%v", info.Mode())
	}
}

func TestPrepareServerEnrollmentIsOptionalAndFailsBeforeClaimOnBadConfig(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing.yaml")
	prepared, err := PrepareServerEnrollment(missing, filepath.Join(root, "node.key"), nil)
	if err != nil || prepared != nil {
		t.Fatalf("optional config=%+v err=%v", prepared, err)
	}
	bad := filepath.Join(root, "bad.yaml")
	if err := os.WriteFile(bad, []byte("server:\n  public_endpoint: 10.0.0.1\n  direction: automatic\n  invented: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareServerEnrollment(bad, filepath.Join(root, "node.key"), nil); err == nil {
		t.Fatal("unknown/private/automatic server config was accepted")
	}
}
