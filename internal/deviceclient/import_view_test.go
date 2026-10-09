package deviceclient

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"loom/internal/control"
)

func TestExplicitViewDeliveryUsesCurrentAcceptanceAndPreservesIdentity(t *testing.T) {
	invite, envelope := schema3Fixture(t, "linux")
	path := filepath.Join(t.TempDir(), "device.json")
	store, err := OpenForPlatform(path, invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	old := envelope(store.PublicKey(), 7)
	if err := store.SaveLKG(old); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveReportSequence(); err != nil {
		t.Fatal(err)
	}
	before := store.state
	next := envelope(store.PublicKey(), 8, revokeView)
	body, err := control.CanonicalEncode(next)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := ImportView(store, body); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reopened.LKG(), &next) || len(reopened.LKG().View.Routes) != 0 ||
		!fixedIdentityEqual(before, reopened.state) || reopened.state.ReportSequence != before.ReportSequence ||
		!reflect.DeepEqual(reopened.state.Preference, before.Preference) {
		t.Fatal("explicit delivery lost revocation, identity, report sequence, or preference across restart")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	older, _ := control.CanonicalEncode(old)
	other, _ := control.CanonicalEncode(envelope(invite.ControlProof.Genesis.Payload.(control.Genesis).ControlConfig.Members[0].PublicKey, 9))
	tampered := bytes.Replace(body, []byte(`"name":"Demo access"`), []byte(`"name":"Changed access"`), 1)
	if bytes.Equal(tampered, body) {
		t.Fatal("fixture has no signed name")
	}
	unknown := append([]byte(`{"unknown":true,`), body[1:]...)
	for _, rejected := range [][]byte{older, other, tampered, append([]byte(" "), body...), unknown} {
		if _, err := ImportView(reopened, rejected); err == nil {
			t.Fatal("old, wrong-identity, forged, or noncanonical view accepted")
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(after, unchanged) {
			t.Fatal("rejected delivery modified persistent state", err)
		}
	}
}
