package linuxclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"loom/internal/control"
	"loom/internal/deviceclient"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The same contract signer and decoder used by the daemon supply this client
// failure test. Full bind/join and tunnel acceptance are exercised by control.
func linuxAcceptanceFixture(t *testing.T) (*deviceclient.Store, string, func(uint64, bool) control.DeviceViewEnvelope) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicValue := base64.RawURLEncoding.EncodeToString(public)
	keyID, err := control.KeyID(publicValue)
	if err != nil {
		t.Fatal(err)
	}
	member := control.Member{ControlID: "demo-control", NodeID: "demo-node", PublicKey: publicValue}
	config := control.ControlConfig{Schema: 3, NetworkID: "demo-network", Operation: "genesis", Members: []control.Member{member}, SealedKeys: []control.ControlSealedKey{}}
	genesis, err := control.SignMaterial(control.Material{Schema: 3, NetworkID: config.NetworkID, IssuerControlID: member.ControlID, IssuerKeyID: keyID, Operation: "genesis", Payload: control.Genesis{ControlConfig: config, NetworkIntent: control.EmptyNetworkIntent(), AdminCertificates: []control.AdminCertificate{}}}, private)
	if err != nil {
		t.Fatal(err)
	}
	_, genesisID, err := control.EncodeMaterial(genesis)
	if err != nil {
		t.Fatal(err)
	}
	configID, err := control.ConfigID(config)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("0", 64)
	endpoint := control.EndpointGeneration{ID: "demo-entry", Generation: 1, OwnerControlID: member.ControlID, Host: "192.0.2.1", Port: 443, ServerName: "demo.example", SPKISHA256: digest, CertificateDigest: digest, Modes: []string{"bootstrap", "device"}, State: "serving"}
	inviteValue := control.Invite{ID: "demo-transaction", GenesisDigest: genesisID, IssuerControlID: member.ControlID, DeviceID: "demo-device", Name: "Demo device", Responsibilities: []string{"access"}, PolicyIDs: []string{}, Medium: "qr", Endpoint: endpoint, ExpiresAt: time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()}
	material, err := control.SignMaterial(control.Material{Schema: 3, NetworkID: config.NetworkID, IssuerControlID: member.ControlID, IssuerKeyID: keyID, ControlConfigID: configID, Sequence: 1, PreviousMaterialID: func() string {
		sum := sha256.Sum256([]byte("loom-empty-material-chain-v3\x00"))
		return "sha256:" + hex.EncodeToString(sum[:])
	}(), Dependencies: []string{}, RequestID: "demo-invite", TargetKind: "invite", TargetID: inviteValue.ID, Operation: "invite.issue", Payload: inviteValue}, private)
	if err != nil {
		t.Fatal(err)
	}
	proof := control.ControlProof{Genesis: genesis, Successors: []control.ControlCertificate{}}
	invite := control.BootstrapInvite{Schema: 3, NetworkID: config.NetworkID, GenesisDigest: genesisID, ControlProof: proof, Material: material}
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := deviceclient.OpenForPlatform(path, invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	makeView := func(sequence uint64, permit bool) control.DeviceViewEnvelope {
		view := control.DeviceView{Schema: 3, DeviceID: "demo-device", Name: "Demo device", Platform: "linux", DevicePublicKey: store.PublicKey(), Responsibilities: []string{"access"}, PolicyIDs: []string{}, Services: []control.Service{}, Policies: []control.NetworkPolicy{}, Resources: []control.TransportResource{}, Links: []control.NetworkLink{}, Endpoints: []control.EndpointGeneration{endpoint}, DNSServers: []string{}, BusinessProbeTargets: []control.ServiceProbeTargets{}, Routes: []control.RouteCandidate{}, InboundCredentials: []control.InboundCredential{}, ExpectedComponents: []control.ComponentReadback{}}
		if permit {
			scope := control.PolicyScope{Mode: "any", NodeIDs: []string{}}
			view.PolicyIDs = []string{"demo-policy"}
			view.Services = []control.Service{{ID: "demo-service", Name: "Demo service", Kind: "internet", Matchers: []control.ServiceMatcher{{Kind: "dns_exact", Value: "demo-service.example"}}}}
			view.Policies = []control.NetworkPolicy{{ID: "demo-policy", Name: "Demo policy", ServiceID: "demo-service", Action: "allow", EntryScope: scope, RelayScope: scope, ExitScope: scope, AllowDirect: true, LocalEgressDevices: []string{}}}
		}
		view.Routes, view.RuntimeProfile, err = control.ProjectAccessRuntime(view)
		if err != nil {
			t.Fatal(err)
		}
		tip := sha256.Sum256([]byte(fmt.Sprintf("demo-fact-%d", sequence)))
		envelope, err := control.SignDeviceViewEnvelope(control.DeviceViewEnvelope{Schema: 3, NetworkID: config.NetworkID, GenesisDigest: genesisID, IssuerControlID: member.ControlID, IssuerKeyID: keyID, ControlProof: proof, FactFrontier: []control.FactFrontier{{KeyID: keyID, Sequence: control.U64(sequence), TipMaterialID: "sha256:" + hex.EncodeToString(tip[:])}}, View: view}, private)
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	return store, path, makeView
}

func TestFrontierProgressPersistsWithoutChangingExecution(t *testing.T) {
	store, path, makeView := linuxAcceptanceFixture(t)
	previous, next := makeView(7, true), makeView(8, true)
	if previous.ViewDigest != next.ViewDigest || previous.Signature == next.Signature {
		t.Fatal("fixture does not distinguish authentication progress from execution")
	}
	if err := store.SaveLKG(previous); err != nil {
		t.Fatal(err)
	}
	changed, err := acceptCertifiedView(store, next)
	if err != nil || changed {
		t.Fatalf("same View interrupted execution: changed=%v err=%v", changed, err)
	}
	restarted, err := deviceclient.Load(path)
	if err != nil || !reflect.DeepEqual(restarted.LKG(), &next) {
		t.Fatal("unchanged execution discarded the newer authenticated frontier")
	}
	if err := restarted.SaveLKG(previous); err == nil {
		t.Fatal("same View allowed authentication progress to roll back")
	}
}

func TestAcceptedRevocationSurvivesRuntimeFailureAndRestart(t *testing.T) {
	store, path, makeView := linuxAcceptanceFixture(t)
	previous, next := makeView(7, true), makeView(8, false)
	if err := store.SaveLKG(previous); err != nil {
		t.Fatal(err)
	}
	stale, err := deviceclient.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := acceptCertifiedView(store, next)
	if err != nil || !changed {
		t.Fatalf("accept authenticated revocation: changed=%v err=%v", changed, err)
	}
	if err := stale.SaveLKG(previous); err == nil {
		t.Fatal("an older CLI handle overwrote the accepted persistent floor")
	}
	// Refresh must notice another handle's accepted revocation before making
	// any network request (including one to an offline or stale control).
	changed, err = certifiedViewChanged(context.Background(), stale, io.Discard)
	if err != nil || !changed || !reflect.DeepEqual(stale.LKG(), &next) {
		t.Fatalf("runtime ignored the persistent revocation: changed=%v err=%v", changed, err)
	}
	root := t.TempDir()
	// Missing execution material forces application failure before any host
	// network operation, independent of the test runner's namespace.
	config := filepath.Join(root, "config.json")
	if err := os.Mkdir(config, 0o700); err != nil {
		t.Fatal(err)
	}
	options := Options{DeviceState: path, Capture: "mixed", Config: config, LocalState: filepath.Join(root, "local.json"),
		SingBox: filepath.Join(root, "missing-sing-box"), Status: filepath.Join(root, "status.json"), Generation: func() (string, error) { return "demo-generation", nil }}
	if err := runGeneration(context.Background(), options, store); err == nil {
		t.Fatal("runtime applied an invalid local config path")
	}
	restarted, err := deviceclient.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restarted.LKG(), &next) || restarted.PublicKey() != store.PublicKey() {
		t.Fatal("runtime failure or restart lost the accepted revocation or identity")
	}
	if _, err := acceptCertifiedView(restarted, previous); err == nil {
		t.Fatal("replayed view restored the revoked service")
	}
	if _, err := acceptCertifiedView(restarted, makeView(8, true)); err == nil {
		t.Fatal("a conflicting head at the same floor restored the revoked service")
	}
	if err := runGeneration(context.Background(), options, restarted); err == nil {
		t.Fatal("restart did not preserve the application failure")
	}
	if _, err := ReadStatus(options.Status); err == nil {
		t.Fatal("failed application reported a running generation")
	}
}
