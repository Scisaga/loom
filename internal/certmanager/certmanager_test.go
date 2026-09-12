package certmanager

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/dnsprovider"
)

func TestLocalKeyIsReusedAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls", "key.pem")
	one, err := EnsureLocalIdentity(path, "edge.example.test")
	if err != nil {
		t.Fatal(err)
	}
	two, err := EnsureLocalIdentity(path, "edge.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if one.SPKIHash != two.SPKIHash {
		t.Fatal("node-local identity key was regenerated")
	}
	if !bytes.Equal(one.CSRDER, two.CSRDER) || one.CSRPath != path+".csr" {
		t.Fatal("reconcile restart regenerated a different CSR artifact")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode=%o", info.Mode().Perm())
	}
}

func TestDNS01OnlyDeletesOwnedValue(t *testing.T) {
	provider := dnsprovider.NewMemory()
	dns01 := DNS01{Provider: provider, Zone: "example.test", TTL: 60}
	ctx := context.Background()
	if err := dns01.Present(ctx, "edge.example.test", "order-a"); err != nil {
		t.Fatal(err)
	}
	if err := dns01.Present(ctx, "edge.example.test", "order-b"); err != nil {
		t.Fatal(err)
	}
	if err := dns01.Cleanup(ctx, "edge.example.test", "order-a"); err != nil {
		t.Fatal(err)
	}
	got, err := provider.Read(ctx, "example.test", "_acme-challenge.edge", "TXT")
	if err != nil || len(got.RRSet.Values) != 1 || got.RRSet.Values[0] != "order-b" {
		t.Fatalf("parallel order was removed: %#v err=%v", got, err)
	}
}

func TestDNS01CleanupIsIdempotentWhenRecordAlreadyAbsent(t *testing.T) {
	dns01 := DNS01{Provider: dnsprovider.NewMemory(), Zone: "example.test", TTL: 60}
	if err := dns01.Cleanup(context.Background(), "edge.example.test", "finished-order"); err != nil {
		t.Fatalf("crash 恢复重复 cleanup 应视为已收敛: %v", err)
	}
}
