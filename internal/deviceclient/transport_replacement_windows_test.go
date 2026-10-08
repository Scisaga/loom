//go:build windows

package deviceclient

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/clientsecret"
)

func TestTransportReplacementWithNativeDPAPI(t *testing.T) {
	for name, protector := range map[string]clientsecret.Protector{"user": clientsecret.UserProtector{}, "machine": clientsecret.MachineProtector{}} {
		t.Run(name, func(t *testing.T) {
			invite, envelope := windowsProtectedFixture(t)
			path := filepath.Join(t.TempDir(), "identity.dpapi")
			store, err := OpenProtected(path, invite, protector)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.SaveLKG(envelope(store.PublicKey(), 7)); err != nil {
				t.Fatal(err)
			}
			original := historicalTransportState(t, store.state)
			if err := clientsecret.WriteProtected(path, protectedStatePurpose, original, protector); err != nil {
				t.Fatal(err)
			}
			sealedBefore, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			evidence := filepath.Join(t.TempDir(), "historical.dpapi")
			if err := MigrateTransportFile(path, evidence, envelope(store.PublicKey(), 8, revokeView), protector); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadProtected(path, protector)
			if err != nil || !fixedIdentityEqual(loaded.state, store.state) || loaded.state.HighWater[0].Sequence != 8 || len(loaded.LKG().View.Routes) != 0 {
				t.Fatal("native DPAPI migration lost identity, floor or revocation", err)
			}
			before, err := clientsecret.ReadProtected(evidence, protectedStatePurpose, protector)
			if err != nil || !bytes.Equal(before, original) {
				t.Fatal("native DPAPI evidence changed", err)
			}
			sealedEvidence, err := os.ReadFile(evidence)
			if err != nil || !bytes.Equal(sealedBefore, sealedEvidence) {
				t.Fatal("migration re-encrypted original evidence", err)
			}
		})
	}
}
