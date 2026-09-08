//go:build windows

package clientruntime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	"loom/internal/clientsecret"
)

func TestPrepareWindowsCandidateNativeDPAPI(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	node, root := "win-native", t.TempDir()
	tree := makeRuntimeTree(t, private, 1, "111111111111", node,
		validWindowsBundle(node, "warn"))
	_, server := installVerifiedRuntimeBundle(t, root, node, public, &tree)
	defer server.Close()

	protector := clientsecret.MachineProtector{}
	vaultPath := filepath.Join(root, "secrets", "vault.json.dpapi")
	if err := clientsecret.WriteVault(vaultPath, map[string]string{
		"vault:cred/win01": "native-password", "api/win01": "native-api",
	}, protector); err != nil {
		t.Fatal(err)
	}
	result, err := PrepareWindowsCandidate(root, node, public, vaultPath, protector)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.SecretsUsed != 2 {
		t.Fatalf("native DPAPI prepare result = %+v", result)
	}
	body, state, err := ReadCandidateConfig(root, protector)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	if !bytes.Contains(body, []byte("native-password")) || state.Current != result.Version {
		t.Fatal("native DPAPI candidate did not round trip through its pointer")
	}
}
