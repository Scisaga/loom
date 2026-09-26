package linuxclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequireDifferentNetworkNamespaceRejectsInitialNamespace(t *testing.T) {
	directory := t.TempDir()
	initial := filepath.Join(directory, "initial")
	current := filepath.Join(directory, "current")
	if err := os.WriteFile(initial, []byte("namespace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(initial, current); err != nil {
		t.Fatal(err)
	}
	if err := requireDifferentNetworkNamespace(current, initial); err == nil ||
		!strings.Contains(err.Error(), "initial network namespace") {
		t.Fatalf("initial namespace error=%v", err)
	}
}

func TestRequireDifferentNetworkNamespaceAcceptsIsolation(t *testing.T) {
	directory := t.TempDir()
	initial := filepath.Join(directory, "initial")
	current := filepath.Join(directory, "current")
	for _, path := range []string{initial, current} {
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := requireDifferentNetworkNamespace(current, initial); err != nil {
		t.Fatal(err)
	}
}

func TestRequireDifferentNetworkNamespaceFailsClosed(t *testing.T) {
	directory := t.TempDir()
	err := requireDifferentNetworkNamespace(filepath.Join(directory, "missing"), filepath.Join(directory, "initial"))
	if err == nil || !strings.Contains(err.Error(), "read current network namespace") {
		t.Fatalf("missing namespace error=%v", err)
	}
}
