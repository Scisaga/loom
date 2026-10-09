package deviceclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/clientsecret"
	"loom/internal/control"
)

func TestTransportReplacementPreservesProtectedBytesAndFailureLeavesAuthority(t *testing.T) {
	invite, envelope := schema3Fixture(t, "windows")
	path := filepath.Join(t.TempDir(), "identity")
	protector := &testProtector{}
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
	evidence := filepath.Join(t.TempDir(), "evidence")
	next := envelope(store.PublicKey(), 8)
	protector.fail = true
	if MigrateTransportFile(path, evidence, next, protector) == nil {
		t.Fatal("protection failure admitted migration")
	}
	protector.fail = false
	if err := MigrateTransportFile(path, evidence, next, protector); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadProtected(path, protector)
	if err != nil || !fixedIdentityEqual(loaded.state, store.state) || loaded.state.HighWater[0].Sequence != 8 {
		t.Fatal("protected migration lost identity or authenticated progress", err)
	}
	before, err := clientsecret.ReadProtected(evidence, protectedStatePurpose, protector)
	if err != nil || !bytes.Equal(before, original) {
		t.Fatal("protected original bytes changed", err)
	}
}

func historicalTransportState(t *testing.T, state State, independentWG ...bool) []byte {
	t.Helper()
	current, err := EncodeIdentityState(state)
	if err != nil {
		t.Fatal(err)
	}
	var identity, envelope, view map[string]json.RawMessage
	json.Unmarshal(current, &identity)
	json.Unmarshal(identity["certified_lkg"], &envelope)
	json.Unmarshal(envelope["view"], &view)
	if len(independentWG) == 0 {
		delete(view, "network_id")
	} else {
		view["runtime_profile"], _ = json.Marshal(map[string]any{"config": `{"endpoints":[{"type":"wireguard","tag":"wg-send.demo-receiver"}]}`})
	}
	envelope["view"], _ = json.Marshal(view)
	sum := sha256.Sum256(append([]byte("loom-device-view-digest-v3\x00"), envelope["view"]...))
	envelope["view_digest"], _ = json.Marshal("sha256:" + hex.EncodeToString(sum[:]))
	delete(envelope, "signature")
	unsigned, _ := json.Marshal(envelope)
	seed := sha256.Sum256([]byte("demo-device-control-b"))
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), append([]byte("loom-device-view-v3\x00"), unsigned...))
	envelope["signature"], _ = json.Marshal(base64.RawURLEncoding.EncodeToString(signature))
	identity["certified_lkg"], _ = json.Marshal(envelope)
	original, _ := json.Marshal(identity)
	return original
}

func TestTransportReplacementPreservesIdentityAndOnlyAdvancesAuthenticatedProgress(t *testing.T) {
	invite, envelope := schema3Fixture(t, "linux")
	path := filepath.Join(t.TempDir(), "identity")
	store, err := OpenForPlatform(path, invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveLKG(envelope(store.PublicKey(), 7)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveReportSequence(); err != nil {
		t.Fatal(err)
	}
	original := historicalTransportState(t, store.state)
	if _, err := DecodeIdentityState(original); err == nil {
		t.Fatal("ordinary decoder admitted historical execution")
	}
	nextEnvelope := envelope(store.PublicKey(), 8, revokeView)
	next, err := ReplaceTransportLKG(original, nextEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if !fixedIdentityEqual(next, store.state) || next.ReportSequence != 1 || next.HighWater[0].Sequence != 8 || len(next.LKG.View.Routes) != 0 {
		t.Fatal("identity, floor, report sequence or revocation lost")
	}
	for name, input := range map[string][]byte{"tampered": bytes.Replace(original, []byte("Demo access"), []byte("Fake access"), 1), "space": append([]byte(" "), original...), "current": mustStateBytes(t, store.state)} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReplaceTransportLKG(input, nextEnvelope); err == nil {
				t.Fatal("invalid replacement admitted")
			}
		})
	}
	for _, bad := range []control.DeviceViewEnvelope{envelope(store.PublicKey(), 6), envelope(store.PublicKey(), 7)} {
		if _, err := ReplaceTransportLKG(original, bad); err == nil {
			t.Fatal("non-forward replacement admitted")
		}
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(t.TempDir(), "original-state")
	if err := MigrateTransportFile(path, evidence, envelope(store.PublicKey(), 7), nil); err == nil {
		t.Fatal("non-forward disk replacement admitted")
	}
	read, _ := os.ReadFile(path)
	if !bytes.Equal(read, original) {
		t.Fatal("failed migration changed state")
	}
	if err := MigrateTransportFile(path, evidence, nextEnvelope, nil); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(evidence)
	if !bytes.Equal(saved, original) {
		t.Fatal("historical bytes changed")
	}
	restarted, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.state.ReportSequence != 1 || !fixedIdentityEqual(restarted.state, store.state) || restarted.LKG().ViewDigest != nextEnvelope.ViewDigest {
		t.Fatal("forward state did not survive restart")
	}
	if err := MigrateTransportFile(path, evidence, nextEnvelope, nil); err == nil {
		t.Fatal("migration became a normal second writer")
	}
}
func mustStateBytes(t *testing.T, state State) []byte {
	t.Helper()
	body, err := EncodeIdentityState(state)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestSharedWGReplacementPreservesCurrentProductionIdentity(t *testing.T) {
	invite, envelope := schema3Fixture(t, "linux")
	path := filepath.Join(t.TempDir(), "identity")
	store, err := OpenForPlatform(path, invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveLKG(envelope(store.PublicKey(), 7)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveReportSequence(); err != nil {
		t.Fatal(err)
	}
	original := historicalTransportState(t, store.state, true)
	if _, err := DecodeIdentityState(original); err == nil {
		t.Fatal("retired WG entered ordinary runtime decoder")
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(t.TempDir(), "original")
	for _, sameOrOlder := range []control.DeviceViewEnvelope{envelope(store.PublicKey(), 6), envelope(store.PublicKey(), 7)} {
		if MigrateTransportFile(path, evidence, sameOrOlder, nil) == nil {
			t.Fatal("WG replacement lowered or reused the frontier")
		}
	}
	next := envelope(store.PublicKey(), 8, revokeView)
	if err := MigrateTransportFile(path, evidence, next, nil); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(evidence)
	loaded, err := Load(path)
	if err != nil || !bytes.Equal(saved, original) || !fixedIdentityEqual(loaded.state, store.state) || loaded.state.ReportSequence != 1 || loaded.state.HighWater[0].Sequence != 8 || len(loaded.LKG().View.Routes) != 0 {
		t.Fatal("shared WG migration lost original evidence, identity, progress or revocation", err)
	}
	if _, err := ReplaceTransportLKG(bytes.Replace(original, []byte("wg-send.demo-receiver"), []byte("wg-send.demo-tampered"), 1), next); err == nil {
		t.Fatal("historical WG signature ignored")
	}
}
