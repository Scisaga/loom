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

	"loom/internal/clientmodel"
	"loom/internal/control"
)

func historicalPolicyState(t *testing.T, state State) []byte {
	t.Helper()
	var identity, envelope, view map[string]json.RawMessage
	json.Unmarshal(mustStateBytes(t, state), &identity)
	json.Unmarshal(identity["certified_lkg"], &envelope)
	json.Unmarshal(envelope["view"], &view)
	var routes []map[string]json.RawMessage
	json.Unmarshal(view["routes"], &routes)
	for _, route := range routes {
		delete(route, "policy_id")
	}
	view["routes"], _ = json.Marshal(routes)
	envelope["view"], _ = json.Marshal(view)
	sum := sha256.Sum256(append([]byte("loom-device-view-digest-v3\x00"), envelope["view"]...))
	envelope["view_digest"], _ = json.Marshal("sha256:" + hex.EncodeToString(sum[:]))
	delete(envelope, "signature")
	unsigned, _ := json.Marshal(envelope)
	seed := sha256.Sum256([]byte("demo-device-control-b"))
	envelope["signature"], _ = json.Marshal(base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), append([]byte("loom-device-view-v3\x00"), unsigned...))))
	identity["certified_lkg"], _ = json.Marshal(envelope)
	if state.Preference != nil {
		identity["preference"] = json.RawMessage(`{"mode":"auto","schema":3}`)
	}
	body, _ := json.Marshal(identity)
	return body
}

func TestHistoricalRestrictionRequiresEquivalentReplacementRules(t *testing.T) {
	unrestricted := control.PolicyScope{Mode: "any", NodeIDs: []string{}}
	none := control.PolicyScope{Mode: "none", NodeIDs: []string{}}
	service := control.Service{ID: "demo-service", Name: "Demo service", Kind: "internet", Matchers: []control.ServiceMatcher{{Kind: "dns_exact", Value: "demo.example"}}}
	direct := control.NetworkPolicy{ID: "demo-policy", ServiceID: service.ID, Name: "Demo direct only", Action: "allow", EntryScope: none, RelayScope: unrestricted, ExitScope: &unrestricted, AllowDirect: new(true), LocalEgressDevices: new([]string{})}
	fixed := direct
	fixed.AllowDirect, fixed.EntryScope, fixed.ExitScope = new(false), unrestricted, new(control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-exit"}})
	historical := func(policy control.NetworkPolicy) []byte {
		fields := map[string]json.RawMessage{}
		for name, value := range map[string]any{"policies": []control.NetworkPolicy{policy}, "policy_ids": []string{policy.ID}, "services": []control.Service{service}, "device_id": "demo-device"} {
			body, err := control.CanonicalEncode(value)
			if err != nil {
				t.Fatal(err)
			}
			fields[name] = body
		}
		body, _ := json.Marshal(fields)
		envelope, _ := json.Marshal(map[string]json.RawMessage{"view": body})
		return envelope
	}
	for _, test := range []struct {
		name, legacy string
		old, current control.NetworkPolicy
		want         string
	}{
		{"Direct equivalent", `{"mode":"direct","schema":3}`, direct, direct, direct.ID},
		{"Direct widened entry", `{"mode":"direct","schema":3}`, direct, func() control.NetworkPolicy { p := direct; p.EntryScope = unrestricted; return p }(), ""},
		{"fixed equivalent", `{"exit":"demo-exit","mode":"fixed_exit","schema":3}`, fixed, fixed, fixed.ID},
		{"fixed widened exit", `{"exit":"demo-exit","mode":"fixed_exit","schema":3}`, fixed, func() control.NetworkPolicy { p := fixed; p.ExitScope = &unrestricted; return p }(), ""},
		{"fixed changed relay rules", `{"exit":"demo-exit","mode":"fixed_exit","schema":3}`, fixed, func() control.NetworkPolicy { p := fixed; p.RelayScope = none; return p }(), ""},
		{"missing preference", "", direct, direct, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			next := control.DeviceView{DeviceID: "demo-device", PolicyIDs: []string{test.current.ID}, Policies: []control.NetworkPolicy{test.current}, Services: []control.Service{service}}
			preference, err := migratePolicyPreference(historical(test.old), []byte(test.legacy), next)
			if err != nil || preference.Policy(service.ID) != test.want || !preference.Equal(clientmodel.Preference{Schema: 3, Services: []clientmodel.ServicePreference{{ServiceID: service.ID, PolicyID: test.want}}}) {
				t.Fatal("legacy restriction was widened or lost initialized waiting state", err)
			}
		})
	}
}

func TestPolicyReplacementPreservesIdentityFloorsAndEvidence(t *testing.T) {
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
	original := historicalPolicyState(t, store.state)
	if _, err := DecodeIdentityState(original); err == nil {
		t.Fatal("startup accepted historical candidates")
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(t.TempDir(), "original")
	next := envelope(store.PublicKey(), 8)
	for _, prior := range []control.DeviceViewEnvelope{envelope(store.PublicKey(), 6), envelope(store.PublicKey(), 7)} {
		if _, _, err := ReplacePolicySelectionLKG(original, prior, []byte(`{"mode":"auto","schema":3}`)); err == nil {
			t.Fatal("non-forward policy cutover accepted")
		}
	}
	preference, err := MigratePolicySelectionFile(path, evidence, next, []byte(`{"mode":"auto","schema":3}`), nil)
	if err != nil || preference.Policy("demo-service") != "demo-policy" {
		t.Fatal("policy migration did not preserve Auto's singleton", err)
	}
	loaded, err := Load(path)
	if err != nil || !fixedIdentityEqual(loaded.state, store.state) || loaded.state.ReportSequence != 1 || loaded.state.HighWater[0].Sequence != 8 {
		t.Fatal("policy cutover lost identity or authenticated progress", err)
	}
	saved, _ := os.ReadFile(evidence)
	if !bytes.Equal(saved, original) {
		t.Fatal("original signed bytes changed")
	}
	if _, err := MigratePolicySelectionFile(path, evidence, next, []byte(`{"mode":"auto","schema":3}`), nil); err != nil {
		t.Fatal("same explicit cutover could not finish a retry", err)
	}
}

func TestUnprovableLegacyRestrictionBecomesPending(t *testing.T) {
	invite, envelope := schema3Fixture(t, "linux")
	store, err := OpenForPlatform(filepath.Join(t.TempDir(), "identity"), invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveLKG(envelope(store.PublicKey(), 7)); err != nil {
		t.Fatal(err)
	}
	original := historicalPolicyState(t, store.state)
	_, preference, err := ReplacePolicySelectionLKG(original, envelope(store.PublicKey(), 8), []byte(`{"exit":"demo-exit","mode":"fixed_exit","schema":3}`))
	if err != nil || preference.Policy("demo-service") != "" || len(preference.Services) != 1 {
		t.Fatal("unprovable restriction widened permissions", err)
	}
}
