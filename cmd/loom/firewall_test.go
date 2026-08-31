package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFirewallKeepsNewPublicIngressOpenForFutureClients(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssot.yaml")
	content := []byte(`nodes:
  - id: public-entry
    public_endpoint: edge.example
    server:
      direction: bidirectional
      inbound_port: 61698
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := cmdFirewall([]string{"-access", "roaming-client", path})
	_ = w.Close()
	os.Stdout = old
	out, readErr := io.ReadAll(r)
	_ = r.Close()
	if runErr != nil {
		t.Fatal(runErr)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	got := string(out)
	if !strings.Contains(got, "roaming-client") || !strings.Contains(got, "Hysteria2 入站") {
		t.Fatalf("public ingress was not rendered for future clients:\n%s", got)
	}
	if strings.Contains(got, "只经隧道内地址到达") {
		t.Fatalf("public ingress was mislabeled tunnel-only:\n%s", got)
	}
}
