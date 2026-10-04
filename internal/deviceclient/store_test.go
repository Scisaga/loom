package deviceclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"loom/internal/control"
)

func schema3Fixture(t *testing.T, platform string, changes ...func(*control.Invite)) (control.BootstrapInvite, func(string, uint64, ...func(*control.DeviceView)) control.DeviceViewEnvelope) {
	t.Helper()
	members := []control.Member{}
	keys := []ed25519.PrivateKey{}
	for _, suffix := range []string{"a", "b"} {
		seed := sha256.Sum256([]byte("demo-device-control-" + suffix))
		key := ed25519.NewKeyFromSeed(seed[:])
		keys = append(keys, key)
		members = append(members, control.Member{ControlID: "demo-control-" + suffix, NodeID: "demo-node-" + suffix, PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))})
	}
	keyID, _ := control.KeyID(members[1].PublicKey)
	config := control.ControlConfig{Schema: 3, NetworkID: "demo-network", Operation: "genesis", Members: members, SealedKeys: []control.ControlSealedKey{}}
	genesis, err := control.SignMaterial(control.Material{Schema: 3, NetworkID: "demo-network", IssuerControlID: members[1].ControlID, IssuerKeyID: keyID, Operation: "genesis", Payload: control.Genesis{ControlConfig: config, NetworkIntent: control.EmptyNetworkIntent(), AdminCertificates: []control.AdminCertificate{}}}, keys[1])
	if err != nil {
		t.Fatal(err)
	}
	anchor, _ := control.MaterialID(genesis)
	configID, _ := control.ConfigID(config)
	endpoint := control.EndpointGeneration{ID: "demo-entry", Generation: 1, OwnerControlID: members[1].ControlID, Host: "192.0.2.1", Port: 443, ServerName: "demo.example", SPKISHA256: "sha256:" + strings.Repeat("1", 64), CertificateDigest: "sha256:" + strings.Repeat("2", 64), Modes: []string{"bootstrap", "device"}, State: "serving"}
	invitation := control.Invite{ID: "demo-transaction", GenesisDigest: anchor, IssuerControlID: members[1].ControlID, DeviceID: "demo-access", Name: "Demo access", Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-policy"}, Medium: "qr", Endpoint: endpoint, ExpiresAt: 1893456000000}
	for _, change := range changes {
		change(&invitation)
	}
	material, err := control.SignMaterial(control.Material{Schema: 3, NetworkID: "demo-network", IssuerControlID: members[1].ControlID, IssuerKeyID: keyID, ControlConfigID: configID, Sequence: 1, PreviousMaterialID: control.EmptyMaterialChainID(), Dependencies: []string{}, RequestID: "demo-issue", TargetKind: "invite", TargetID: invitation.ID, Operation: "invite.issue", Payload: invitation}, keys[1])
	if err != nil {
		t.Fatal(err)
	}
	invite := control.BootstrapInvite{Schema: 3, NetworkID: "demo-network", GenesisDigest: anchor, ControlProof: control.ControlProof{Genesis: genesis, Successors: []control.ControlCertificate{}}, Material: material}
	if err := invite.Validate(); err != nil {
		t.Fatal(err)
	}
	makeEnvelope := func(public string, sequence uint64, changes ...func(*control.DeviceView)) control.DeviceViewEnvelope {
		p, err := control.Project(genesis, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		scope := control.PolicyScope{Mode: "any", NodeIDs: []string{}}
		p.NetworkIntent.Services = []control.Service{{ID: "demo-service", Name: "Demo service", Kind: "internet", Matchers: []control.ServiceMatcher{{Kind: "dns_exact", Value: "demo.example"}}}}
		p.NetworkIntent.Policies = []control.NetworkPolicy{{ID: "demo-policy", Name: "Demo policy", ServiceID: "demo-service", Action: "allow", EntryScope: scope, RelayScope: scope, ExitScope: scope, AllowDirect: true, LocalEgressDevices: []string{}}}
		inviteID, _ := control.MaterialID(material)
		p.DeviceAuthorizations = []control.DeviceAuthorization{{ID: invitation.DeviceID, Name: invitation.Name, Platform: platform, DevicePublicKey: public, Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-policy"}, DistributionURLs: []string{}, RuntimeKey: members[0].PublicKey, TransactionID: invitation.ID, InviteMaterialID: inviteID, BindingMaterialID: anchor}}
		p.EndpointGenerations = []control.EndpointGeneration{endpoint}
		view, err := control.ProjectDeviceView(p, invitation.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range changes {
			change(&view)
		}
		view.Routes, view.RuntimeProfile, err = control.ProjectAccessRuntime(view)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("demo-prefix-%d", sequence)))
		result, err := control.SignDeviceViewEnvelope(control.DeviceViewEnvelope{Schema: 3, NetworkID: "demo-network", GenesisDigest: anchor, IssuerControlID: members[1].ControlID, IssuerKeyID: keyID, ControlProof: invite.ControlProof, FactFrontier: []control.FactFrontier{{KeyID: keyID, Sequence: control.U64(sequence), TipMaterialID: "sha256:" + hex.EncodeToString(sum[:])}}, View: view}, keys[1])
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	return invite, makeEnvelope
}
func windowsProtectedFixture(t *testing.T) (control.BootstrapInvite, func(string, uint64, ...func(*control.DeviceView)) control.DeviceViewEnvelope) {
	return schema3Fixture(t, "windows")
}
func revokeView(view *control.DeviceView) {
	view.Policies[0].Action = "deny"
	view.BusinessProbeTargets = []control.ServiceProbeTargets{}
}

func TestAcceptedLKGSurvivesRestartAndRejectsOldOrConflictingProgress(t *testing.T) {
	invite, envelope := schema3Fixture(t, "linux")
	path := filepath.Join(t.TempDir(), "identity")
	store, err := OpenForPlatform(path, invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	old := envelope(store.PublicKey(), 7)
	if err := store.SaveLKG(old); err != nil {
		t.Fatal(err)
	}
	revoked := envelope(store.PublicKey(), 8, revokeView)
	if err := store.SaveLKG(revoked); err != nil {
		t.Fatal(err)
	}
	if len(store.LKG().View.Routes) != 0 {
		t.Fatal("revoked runtime is not closed")
	}
	loaded, err := Load(path)
	if err != nil || !reflect.DeepEqual(loaded.LKG(), &revoked) {
		t.Fatalf("restart: %v", err)
	}
	before, _ := os.ReadFile(path)
	for _, bad := range []control.DeviceViewEnvelope{old, envelope(store.PublicKey(), 8), envelope(invite.ControlProof.Genesis.Payload.(control.Genesis).ControlConfig.Members[0].PublicKey, 9)} {
		if loaded.SaveLKG(bad) == nil {
			t.Fatal("old/conflicting/other identity accepted")
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("rejection mutated authority")
	}
	if !loaded.state.AuthenticatedLatch || loaded.state.HighWater[0].Sequence != 8 || loaded.PublicKey() != store.PublicKey() {
		t.Fatal("identity or high-water lost")
	}
	copy := loaded.LKG()
	copy.View.Name = "Changed caller copy"
	if loaded.LKG().View.Name == copy.View.Name {
		t.Fatal("caller mutated accepted LKG")
	}
	for i := control.U64(1); i <= 2; i++ {
		seq, err := loaded.ReserveReportSequence()
		if err != nil || seq != i {
			t.Fatalf("sequence: %v", err)
		}
	}
	changed, err := store.Reload()
	if err != nil || changed {
		t.Fatalf("unchanged authorization reload: %v", err)
	}
	if _, err := loaded.ReserveReportSequence(); err != nil {
		t.Fatal(err)
	}
	changed, err = store.Reload()
	if err != nil || changed {
		t.Fatalf("report progress restarted runtime: %v", err)
	}
}
func TestPlainStateRejectsOldUnknownOrNoncanonicalBytesWithoutMigration(t *testing.T) {
	invite, _ := schema3Fixture(t, "linux")
	path := filepath.Join(t.TempDir(), "identity")
	for _, body := range [][]byte{[]byte(`{"schema":2,"v2_latch":true}`), []byte(`{"schema":3,"schema":3}`), []byte(`{"schema":3,"unknown":1}`)} {
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenForPlatform(path, invite, "linux"); err == nil {
			t.Fatal("invalid persistent state accepted")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(body, after) {
			t.Fatal("reader migrated historical bytes")
		}
	}
}
func TestConcurrentIdentityCreationDoesNotReplaceExistingKey(t *testing.T) {
	invite, _ := schema3Fixture(t, "linux")
	path := filepath.Join(t.TempDir(), "identity")
	store, err := OpenForPlatform(path, invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	other, err := OpenForPlatform(path, invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if store.PublicKey() != other.PublicKey() {
		t.Fatal("resume generated another identity")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveReportSequence(); err == nil {
		t.Fatal("missing accepted file was regenerated")
	}
}

func TestReportSequenceIsDurablyReservedAcrossIndependentHandles(t *testing.T) {
	invite, envelope := schema3Fixture(t, "linux")
	path := filepath.Join(t.TempDir(), "identity")
	first, err := OpenForPlatform(path, invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if err := first.SaveLKG(envelope(first.PublicKey(), 7)); err != nil {
		t.Fatal(err)
	}
	second, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	type reserved struct {
		sequence control.U64
		err      error
	}
	results := make(chan reserved, 2)
	for _, store := range []*Store{first, second} {
		go func(store *Store) { sequence, err := store.ReserveReportSequence(); results <- reserved{sequence, err} }(store)
	}
	seen := map[control.U64]bool{}
	for range 2 {
		result := <-results
		if result.err != nil || result.sequence == 0 || seen[result.sequence] {
			t.Fatalf("duplicate reservation: %v", result.err)
		}
		seen[result.sequence] = true
	}
	loaded, err := Load(path)
	if err != nil || loaded.state.ReportSequence != 2 {
		t.Fatalf("report reservation was not durable: %v", err)
	}
	sequence, err := loaded.ReserveReportSequence()
	if err != nil || sequence != 3 {
		t.Fatalf("restart reused report sequence: %v", err)
	}
}
