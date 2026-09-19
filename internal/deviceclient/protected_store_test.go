package deviceclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

type testProtector struct{ fail bool }

func (protector *testProtector) Protect(_ string, plaintext []byte) ([]byte, error) {
	if protector.fail {
		return nil, errors.New("injected protection failure")
	}
	return append([]byte("protected:"), plaintext...), nil
}

func (*testProtector) Unprotect(_ string, ciphertext []byte) ([]byte, error) {
	if !bytes.HasPrefix(ciphertext, []byte("protected:")) {
		return nil, errors.New("invalid protected fixture")
	}
	return append([]byte(nil), ciphertext[len("protected:"):]...), nil
}

func windowsProtectedFixture(t *testing.T) (control.BootstrapInvite, func(string, uint64) control.DeviceViewEnvelope) {
	t.Helper()
	memberPublic, memberPrivate, _ := ed25519.GenerateKey(rand.Reader)
	memberID := "demo-control"
	config := control.StableConfig([]control.Member{{ID: memberID, Node: "demo-node",
		PublicKey: base64.RawURLEncoding.EncodeToString(memberPublic)}})
	digest := "sha256:" + strings.Repeat("0", 64)
	endpoint := control.EndpointReference{EndpointID: "demo-entry", Generation: 1, Transport: "tls_tunnel",
		Address: "192.0.2.1:443", ServerName: "demo.example", SPKISHA256: strings.Repeat("1", 64), State: "serving"}
	capability, err := control.SignBootstrapCapability(control.BootstrapCapability{Schema: 1, TransactionID: "demo-transaction",
		IssuedHead: digest, ConfigMaterial: digest, ControlConfig: config, ExpiresAt: "2030-01-01T00:00:00Z",
		Actions: []string{"claim", "resume"}, Endpoints: []control.EndpointReference{endpoint}, ConstraintDigest: digest,
		IssuerMemberID: memberID}, control.NodeConfig{MemberID: memberID,
		IdentityPrivateKey: base64.RawURLEncoding.EncodeToString(memberPrivate)})
	if err != nil {
		t.Fatal(err)
	}
	makeEnvelope := func(publicKey string, floor uint64) control.DeviceViewEnvelope {
		routes := []control.RouteCandidate{{ID: "one-hop", FinalExit: "demo-exit", Chain: []string{"demo-exit"}, Scope: "internet"},
			{ID: "relay", FinalExit: "demo-exit", Chain: []string{"demo-relay", "demo-exit"}, Scope: "internet"}}
		raw := `{"inbounds":[{"type":"tun","tag":"tun-in","auto_route":true}],"outbounds":[{"type":"hysteria2","tag":"one-hop"},{"type":"hysteria2","tag":"relay"},{"type":"selector","tag":"internet","outbounds":["one-hop","relay"]}],"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-secret"}}}`
		runtimeConfig, err := clientmodel.CanonicalizeRuntimeConfig([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		view := control.DeviceView{Schema: 1, DeviceID: "demo-windows", Name: "Demo Windows", Platform: "windows",
			Roles: []string{"access"}, DevicePublicKey: publicKey, Floor: floor, Endpoints: []control.EndpointReference{endpoint},
			Routes: routes, Runtime: &control.RuntimeProfile{Kind: "sing_box", Config: runtimeConfig}}
		head := control.GovernanceHead{Schema: 1, Index: floor, LogDigest: digest, ProjectionDigest: digest,
			DeviceViewsDigest: singleViewRoot(t, view), ConfigMaterial: digest}
		head = signTestHead(t, head, memberID, memberPrivate)
		return control.DeviceViewEnvelope{Schema: 1, View: view, Head: head, ControlConfig: config,
			Proof: control.DeviceViewProof{Index: 0, Size: 1}}
	}
	return control.BootstrapInvite{Schema: 1, Capability: capability}, makeEnvelope
}

func TestProtectedProfileRoundTripAndFailedReplacePreservesAuthority(t *testing.T) {
	invite, makeEnvelope := windowsProtectedFixture(t)
	protector := &testProtector{}
	path := filepath.Join(t.TempDir(), "profile.json.dpapi")
	store, err := OpenProtected(path, invite, protector)
	if err != nil {
		t.Fatal(err)
	}
	store.SetLKGPreflight(func(control.DeviceViewEnvelope) error { return nil })
	envelope := makeEnvelope(store.PublicKey(), 7)
	if err := store.SaveLKG(envelope); err != nil {
		t.Fatal(err)
	}
	preference := clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeFixed, Exit: "demo-exit"}
	if err := store.SetPreference(preference); err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(onDisk, []byte(store.state.PrivateKey)) {
		t.Fatal("protected profile exposed its Ed25519 private key")
	}
	reopened, err := LoadProtected(path, protector)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reopened.LKG(), &envelope) || reopened.Preference() != preference ||
		reopened.state.Floor != 7 || !reopened.state.V2Latch || reopened.PublicKey() != store.PublicKey() {
		t.Fatal("protected profile did not round trip its authoritative state")
	}
	before := append([]byte(nil), onDisk...)
	protector.fail = true
	if err := reopened.SetPreference(clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeAuto}); err == nil {
		t.Fatal("injected atomic replacement failure succeeded")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || reopened.Preference() != preference {
		t.Fatal("failed protected replacement changed persisted or in-memory authority")
	}
}

func TestProtectedProfileRejectsPlaintextAndUnknownState(t *testing.T) {
	invite, _ := windowsProtectedFixture(t)
	protector := &testProtector{}
	path := filepath.Join(t.TempDir(), "profile.json.dpapi")
	store, err := OpenProtected(path, invite, protector)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(store.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProtected(path, protector); err == nil {
		t.Fatal("plaintext profile state was accepted")
	}
}
