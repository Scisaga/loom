package deviceclient

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/control"
)

func TestIdentityReadbackPreservesUnclaimedIdentityAndExcludesSecrets(t *testing.T) {
	invite, envelope := schema3Fixture(t, "linux")
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenForPlatform(path, invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := store.IdentityReadback()
	if err != nil || identity.Joined || identity.DeviceID != "demo-access" || identity.TransactionID != "demo-transaction" || identity.DevicePublicKey != store.PublicKey() || identity.ClaimRequestID != store.ClaimRequestID() {
		t.Fatal("an unclaimed durable identity cannot be mistaken for an empty target", err)
	}
	body, err := control.CanonicalEncode(identity)
	if err != nil {
		t.Fatal(err)
	}
	encodedInvite, _ := control.EncodeInvite(invite)
	if bytes.Contains(body, []byte(store.state.PrivateKey)) || bytes.Contains(body, []byte(encodedInvite)) {
		t.Fatal("inspection exported a secret or invitation capability")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("inspection changed the protected device state", err)
	}
	if err := store.SaveLKG(envelope(store.PublicKey(), 7)); err != nil {
		t.Fatal(err)
	}
	reopened, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := reopened.IdentityReadback()
	if err != nil || !joined.Joined {
		t.Fatal("joined identity inspection did not survive restart", err)
	}
	joined.Joined = false
	if joined != identity {
		t.Fatal("claim or restart changed the original identity coordinates")
	}
}
