package deviceclient

import (
	"bytes"
	"errors"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type testProtector struct{ fail bool }

func (p *testProtector) Protect(purpose string, plain []byte) ([]byte, error) {
	if p.fail {
		return nil, errors.New("injected protection failure")
	}
	return append([]byte(purpose+":"), plain...), nil
}
func (*testProtector) Unprotect(purpose string, cipher []byte) ([]byte, error) {
	prefix := []byte(purpose + ":")
	if !bytes.HasPrefix(cipher, prefix) {
		return nil, errors.New("invalid protected fixture")
	}
	return append([]byte{}, cipher[len(prefix):]...), nil
}

func TestProtectedProfileIndependentHandlesPreserveRevocationAndPreference(t *testing.T) {
	invite, envelope := windowsProtectedFixture(t)
	protector := &testProtector{}
	path := filepath.Join(t.TempDir(), "profile.dpapi")
	runtime, err := OpenProtected(path, invite, protector)
	if err != nil {
		t.Fatal(err)
	}
	previous := envelope(runtime.PublicKey(), 7)
	if err := runtime.SaveLKG(previous); err != nil {
		t.Fatal(err)
	}
	gui, err := LoadProtected(path, protector)
	if err != nil {
		t.Fatal(err)
	}
	revoked := envelope(runtime.PublicKey(), 8, revokeView)
	if err := runtime.SaveLKG(revoked); err != nil {
		t.Fatal(err)
	}
	pref := clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeDirect}
	if err := gui.SetPreference(pref); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gui.LKG(), &revoked) {
		t.Fatal("stale GUI overwrote revocation")
	}
	if err := gui.SaveLKG(previous); err == nil {
		t.Fatal("old GUI revived permissions")
	}
	if err := runtime.SaveLKG(envelope(runtime.PublicKey(), 9, revokeView)); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadProtected(path, protector)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Preference() != pref || loaded.state.HighWater[0].Sequence != 9 || !loaded.state.AuthenticatedLatch {
		t.Fatal("reload lost preferences, identity or high-water")
	}
}
func TestProtectedProfilePersistenceFailureKeepsDiskAndStopsFurtherWrites(t *testing.T) {
	invite, envelope := windowsProtectedFixture(t)
	protector := &testProtector{}
	path := filepath.Join(t.TempDir(), "profile.dpapi")
	store, err := OpenProtected(path, invite, protector)
	if err != nil {
		t.Fatal(err)
	}
	original := envelope(store.PublicKey(), 7)
	if err := store.SaveLKG(original); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	protector.fail = true
	if err := store.SaveLKG(envelope(store.PublicKey(), 8, revokeView)); err == nil {
		t.Fatal("protection failure accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || !reflect.DeepEqual(store.LKG(), &original) {
		t.Fatal("failed replacement changed authority")
	}
	protector.fail = false
	if err := store.SaveLKG(envelope(store.PublicKey(), 9)); err == nil {
		t.Fatal("failed handle continued writing")
	}
	if _, err := store.Reload(); err == nil {
		t.Fatal("failed handle silently resumed")
	}
	reopened, err := LoadProtected(path, protector)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.SaveLKG(envelope(reopened.PublicKey(), 8, revokeView)); err != nil {
		t.Fatal(err)
	}
}
func TestProtectedIdentityRejectsPlatformMismatchAndOldPlaintext(t *testing.T) {
	invite, envelope := windowsProtectedFixture(t)
	protector := &testProtector{}
	path := filepath.Join(t.TempDir(), "profile.dpapi")
	store, err := OpenProtected(path, invite, protector)
	if err != nil {
		t.Fatal(err)
	}
	wrong := envelope(store.PublicKey(), 7, func(v *control.DeviceView) { v.Platform = "linux" })
	if err := store.SaveLKG(wrong); err == nil {
		t.Fatal("Linux view accepted by Windows identity")
	}
	body := []byte(`{"schema":2,"v2_latch":true}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProtected(path, protector); err == nil {
		t.Fatal("plaintext historical identity accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(body, after) {
		t.Fatal("rejection overwrote historical identity")
	}
}
