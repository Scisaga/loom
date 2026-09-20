package linuxclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectLegacyServerRuntimeRefusesServerOwnedInbound(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, []byte(`{"inbounds":[{"type":"hysteria2"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := protectLegacyServerRuntime(path); err == nil || !strings.Contains(err.Error(), "server data-plane") {
		t.Fatalf("server-owned runtime was not protected: %v", err)
	}
}

func TestProtectLegacyServerRuntimeAllowsAbsentOrClientOnlyConfig(t *testing.T) {
	directory := t.TempDir()
	if err := protectLegacyServerRuntime(filepath.Join(directory, "missing.json")); err != nil {
		t.Fatalf("missing legacy config: %v", err)
	}
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, []byte(`{"inbounds":[{"type":"tun"},{"type":"mixed"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := protectLegacyServerRuntime(path); err != nil {
		t.Fatalf("client-only config was rejected: %v", err)
	}
}
