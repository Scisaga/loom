package deviceclient

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"loom/internal/control"
)

// The fixture contains the retired shared native resource endpoint, real /64
// execution DNS pool and the historical six-node, eighteen-direction graph.
// Its old executable sections remain raw signed evidence throughout migration.
func sharedNativeReplacementFixture(t *testing.T, state State, sequence uint64) (control.DeviceViewEnvelope, []byte) {
	t.Helper()
	p, err := control.Project(state.Invite.ControlProof.Genesis, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	anyScope := control.PolicyScope{Mode: "any", NodeIDs: []string{}}
	p.NetworkIntent.Services = []control.Service{{ID: "demo-service", Name: "Demo service", Kind: "internet", RestrictToProbeTargets: new(false)}}
	p.NetworkIntent.Policies = []control.NetworkPolicy{{ID: "demo-policy", Name: "Demo policy", ServiceID: "demo-service", Action: "allow", EntryScope: anyScope, RelayScope: anyScope, ExitScope: new(anyScope), AllowDirect: new(true), LocalEgressDevices: new([]string{}), MaxHops: 2}}
	ids := []string{state.Invite.Material.Payload.(control.Invite).DeviceID, "demo-cn-a", "demo-cn-b", "demo-edge-a", "demo-edge-b", "demo-edge-c"}
	for i, id := range ids {
		seed := sha256.Sum256([]byte(id))
		public := base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
		roles := []string{"forward", "internet_egress"}
		policies := []string{}
		if i == 0 {
			public = base64.RawURLEncoding.EncodeToString(mustPrivate(t, state.PrivateKey).Public().(ed25519.PublicKey))
			roles = []string{"access", "forward", "internet_egress"}
			policies = []string{"demo-policy"}
		}
		p.DeviceAuthorizations = append(p.DeviceAuthorizations, control.DeviceAuthorization{ID: id, Name: id, Platform: "linux", DevicePublicKey: public, Responsibilities: roles, PolicyIDs: policies, DistributionURLs: []string{}, RuntimeKey: base64.RawURLEncoding.EncodeToString(seed[:]), TransactionID: "demo-transaction", InviteMaterialID: state.Invite.GenesisDigest, BindingMaterialID: state.Invite.GenesisDigest})
		wg, err := ecdh.X25519().NewPrivateKey(seed[:])
		if err != nil {
			t.Fatal(err)
		}
		wgPublic := base64.RawURLEncoding.EncodeToString(wg.PublicKey().Bytes())
		p.DeviceAuthorizations[len(p.DeviceAuthorizations)-1].WireGuardPublicKey = wgPublic
		addresses := []string{fmt.Sprintf("198.51.100.%d/32", i+1)}
		p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, control.TransportResource{ID: fmt.Sprintf("demo-wg-%d", i), Kind: "wireguard", OwnerNodeID: id, ListenerID: fmt.Sprintf("demo-wg-%d", i), DialHost: fmt.Sprintf("192.0.2.%d", i+1), DialPort: 51820, AccessEnabled: i != 0, Authentication: control.ResourceAuthentication{PublicKey: &wgPublic, LocalAddresses: &addresses}})
	}
	sort.Slice(p.DeviceAuthorizations, func(i, j int) bool { return p.DeviceAuthorizations[i].ID < p.DeviceAuthorizations[j].ID })
	view, err := control.ProjectDeviceView(p, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	keySeed := sha256.Sum256([]byte("demo-device-control-b"))
	key := ed25519.NewKeyFromSeed(keySeed[:])
	keyID, _ := control.KeyID(base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
	tip := sha256.Sum256([]byte(fmt.Sprintf("demo-shared-prefix-%d", sequence)))
	envelope, err := control.SignDeviceViewEnvelope(control.DeviceViewEnvelope{Schema: 3, NetworkID: p.NetworkID, GenesisDigest: state.Invite.GenesisDigest, IssuerControlID: "demo-control-b", IssuerKeyID: keyID, ControlProof: state.Invite.ControlProof, FactFrontier: []control.FactFrontier{{KeyID: keyID, Sequence: control.U64(sequence), TipMaterialID: "sha256:" + hex.EncodeToString(tip[:])}}, View: view}, key)
	if err != nil {
		t.Fatal(err)
	}
	oldLinks := []control.NetworkLink{}
	positions := map[string]int{}
	for i, id := range ids {
		positions[id] = i
	}
	for _, link := range testDeviceExecution(view).Links {
		if (positions[link.FromNodeID] < 3) == (positions[link.ToNodeID] < 3) {
			continue
		}
		link.ProbeTarget.Action = "wireguard_dns"
		link.ID = "demo-manual-" + link.FromNodeID + "-" + link.ToNodeID
		oldLinks = append(oldLinks, link)
	}
	sort.Slice(oldLinks, func(i, j int) bool { return oldLinks[i].ID < oldLinks[j].ID })
	if len(oldLinks) != 18 {
		t.Fatal("fixture did not retain the actual historical eighteen-direction graph", len(oldLinks))
	}
	viewBody, err := control.CanonicalEncode(view)
	if err != nil {
		t.Fatal(err)
	}
	var historical map[string]json.RawMessage
	historical = testHistoricalView(t, view)
	_ = viewBody
	delete(historical, "access_grants")
	delete(historical, "policy_exits")
	var legacyRoutes []map[string]json.RawMessage
	json.Unmarshal(historical["routes"], &legacyRoutes)
	for index, row := range legacyRoutes {
		candidate := testDeviceExecution(view).Routes[index]
		chain, ids, err := control.CandidateTopologyEstimate(testDeviceExecution(view), candidate)
		if err != nil {
			t.Fatal(err)
		}
		if candidate.FirstResourceID == "" {
			chain = []string{}
			ids = []string{}
		}
		delete(row, "entry_node_id")
		row["node_chain"], _ = json.Marshal(chain)
		row["link_ids"], _ = json.Marshal(ids)
	}
	historical["routes"], _ = json.Marshal(legacyRoutes)

	historical["links"], err = control.CanonicalEncode(oldLinks)
	if err != nil {
		t.Fatal(err)
	}
	// Remove the newly introduced candidate diagnostic rules. The existing
	// native resource diagnostics and the complete shared endpoint remain.
	var profile map[string]any
	json.Unmarshal([]byte(testDeviceExecution(view).RuntimeProfile.Config), &profile)
	for _, raw := range profile["outbounds"].([]any) {
		row := raw.(map[string]any)
		delete(row, "execution")
		delete(row, "execution_source")
		delete(row, "hop")
	}
	for _, raw := range profile["endpoints"].([]any) {
		endpoint := raw.(map[string]any)
		for _, resource := range view.Resources {
			if resource.Kind == "wireguard" && resource.OwnerNodeID == view.DeviceID {
				endpoint["tag"] = control.ResourceInboundTag(resource.ID)
				// The retired producer bound the resource's public port locally.
				// Preserve that historical meaning explicitly: today's renderer
				// correctly leaves the local port to protected execution inputs.
				endpoint["listen_port"] = resource.DialPort
			}
		}
		delete(endpoint, "execution")
		delete(endpoint, "execution_address")
		// The retired stack bound its per-resource sender principals. Today's
		// stable loopback anchors are a different execution shape and cannot
		// stand in for those historical signed bytes.
		principals := map[string]bool{}
		for _, rawRoute := range endpoint["source_routes"].([]any) {
			row := rawRoute.(map[string]any)
			source, err := netip.ParseAddr(row["source"].(string))
			if err != nil || !source.Is6() || !source.IsPrivate() {
				t.Fatal("retired sender principal is not a private IPv6 address")
			}
			principals[netip.PrefixFrom(source, 128).String()] = true
			delete(row, "execution")
		}
		addresses := make([]string, 0, len(principals))
		for address := range principals {
			addresses = append(addresses, address)
		}
		sort.Strings(addresses)
		endpoint["address"] = addresses
	}

	route := profile["route"].(map[string]any)
	rules := []any{}
	for _, raw := range route["rules"].([]any) {
		rule := raw.(map[string]any)
		children, _ := rule["rules"].([]any)
		if len(children) == 2 {
			scope, _ := children[0].(map[string]any)
			users, _ := scope["auth_user"].([]any)
			if len(users) == 1 && strings.HasPrefix(fmt.Sprint(users[0]), "sha256:") {
				continue
			}
		}
		rules = append(rules, raw)
	}
	route["rules"] = rules
	configBody := testCanonicalHistoricalJSON(t, profile)
	for _, resource := range view.Resources {
		if resource.Kind == "wireguard" && resource.OwnerNodeID == view.DeviceID {
			oldTag, _ := json.Marshal(control.ResourceInboundTag(resource.ID))
			configBody = bytes.ReplaceAll(configBody, []byte(`"wg-shared"`), oldTag)
		}
	}
	historical["runtime_profile"], err = control.CanonicalEncode(control.RuntimeProfile{Kind: "sing_box", Config: string(configBody)})
	if err != nil {
		t.Fatal(err)
	}
	var originalEnvelope map[string]json.RawMessage
	body, _ := control.CanonicalEncode(envelope)
	json.Unmarshal(body, &originalEnvelope)
	originalEnvelope["view"] = testCanonicalHistoricalJSON(t, historical)
	sum := sha256.Sum256(append([]byte("loom-device-view-digest-v3\x00"), originalEnvelope["view"]...))
	originalEnvelope["view_digest"], _ = json.Marshal("sha256:" + hex.EncodeToString(sum[:]))
	delete(originalEnvelope, "signature")
	unsigned := testCanonicalHistoricalJSON(t, originalEnvelope)
	originalEnvelope["signature"], _ = json.Marshal(base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte("loom-device-view-v3\x00"), unsigned...))))
	old, _ := json.Marshal(originalEnvelope)
	return envelope, old
}

func mustPrivate(t *testing.T, encoded string) ed25519.PrivateKey {
	t.Helper()
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.PrivateKey(key)
}

func TestCurrentSharedNativeManualGraphMigrationPreservesProtectedIdentityAndRejectsRollback(t *testing.T) {
	invite, _ := schema3Fixture(t, "linux")
	path := filepath.Join(t.TempDir(), "identity")
	store, err := OpenForPlatform(path, invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	current, oldEnvelope := sharedNativeReplacementFixture(t, store.state, 7)
	if err := store.SaveLKG(current); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveReportSequence(); err != nil {
		t.Fatal(err)
	}
	before := store.state
	body := mustStateBytes(t, before)
	var identity map[string]json.RawMessage
	json.Unmarshal(body, &identity)
	identity["certified_lkg"] = oldEnvelope
	original, _ := json.Marshal(identity)
	if _, err := DecodeIdentityState(original); err == nil {
		t.Fatal("manual native graph became an ordinary runtime fallback")
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	next, _ := sharedNativeReplacementFixture(t, before, 8)
	same, _ := sharedNativeReplacementFixture(t, before, 7)
	older, _ := sharedNativeReplacementFixture(t, before, 6)
	evidence := filepath.Join(t.TempDir(), "original")
	for _, bad := range []control.DeviceViewEnvelope{same, older} {
		if MigrateTransportFile(path, evidence, bad, nil) == nil {
			t.Fatal("same or lower frontier admitted")
		}
	}
	tampered := bytes.Replace(original, []byte("demo-manual-"), []byte("demo-tamper-"), 1)
	if _, err := ReplaceTransportLKG(tampered, next); err == nil {
		t.Fatal("manual native original signature ignored")
	}
	if err := MigrateTransportFile(path, evidence, next, nil); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(evidence)
	if err != nil || !bytes.Equal(saved, original) {
		t.Fatal("old shared native original bytes changed", err)
	}
	loaded, err := Load(path)
	if err != nil || !fixedIdentityEqual(before, loaded.state) || loaded.state.ReportSequence != before.ReportSequence || !loaded.state.AuthenticatedLatch || loaded.state.HighWater[0].Sequence != 8 || len(testDeviceExecution(loaded.LKG().View).Links) != 30 {
		t.Fatal("migration lost identity, progress or current automatic graph", err)
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReplaceTransportLKG(actual, next); err == nil {
		t.Fatal("current automatic LKG was admitted as historical evidence")
	}
	if MigrateTransportFile(path, evidence, next, nil) == nil {
		t.Fatal("completed migration became a second ordinary writer")
	}
	info, err := os.Stat(evidence)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("protected evidence did not survive", err)
	}
}
