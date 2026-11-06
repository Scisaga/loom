package control

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestWireGuardRegistrationUsesNormalDeviceWriteAndPreservesIdentityOnRestart(t *testing.T) {
	server, invite, _, claim, _, dependencies := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("normal joining failed", response.Code)
	}
	runtime := server.Runtime
	original := runtime.Authority.Snapshot().DeviceAuthorizations[0]
	derived, err := DerivedWireGuardPublicKey(runtime.Config.NetworkID, original)
	if err != nil || original.WireGuardPublicKey != derived {
		t.Fatal("initial enrollment did not record its original derived identity", err)
	}
	root := runtime.Authority.root
	unchanged := map[string][]byte{}
	entries, _ := os.ReadDir(filepath.Join(root, "materials"))
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			body, err := os.ReadFile(filepath.Join(root, "materials", entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			unchanged[entry.Name()] = body
		}
	}
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	target, _ := runtime.Authority.Snapshot().CurrentTarget("device", original.ID)
	command := Operation{Schema: 3, RequestID: "demo-register-fixed-wg", Operation: "device.put", TargetKind: "device", TargetID: original.ID,
		Dependencies: sortedUniqueDependencies(append(dependencies, target.MaterialIDs...)), Payload: DevicePut{WireGuardPublicKey: public, ID: original.ID, Name: original.Name, Responsibilities: original.Responsibilities, PolicyIDs: original.PolicyIDs, DistributionURLs: []string{}}}
	registered := submitAuthority(t, runtime, command)
	value := registered.Projection.DeviceAuthorizations[0]
	if value.WireGuardPublicKey != public || value.RuntimeKey != original.RuntimeKey || value.DevicePublicKey != original.DevicePublicKey || value.BindingMaterialID != original.BindingMaterialID {
		t.Fatal("registration changed the original identity, root or binding")
	}
	command.RequestID, command.Dependencies = "demo-rename-registered-node", sortedUniqueDependencies(append(dependencies, registered.MaterialID))
	fields := command.Payload.(DevicePut)
	fields.WireGuardPublicKey, fields.Name = "", "Demo renamed node"
	command.Payload = fields
	renamed := submitAuthority(t, runtime, command)
	frontier := runtime.Authority.Frontier()
	retried := submitAuthority(t, runtime, command)
	if retried.MaterialID != renamed.MaterialID || !reflect.DeepEqual(frontier, runtime.Authority.Frontier()) {
		t.Fatal("retry re-signed a preserved registration")
	}
	if renamed.Projection.DeviceAuthorizations[0].WireGuardPublicKey != public {
		t.Fatal("ordinary edit removed or restored a historical key")
	}
	revoked := submitAuthority(t, runtime, Operation{Schema: 3, RequestID: "demo-revoke-registered-node", Operation: "device.revoke", TargetKind: "device", TargetID: original.ID, Dependencies: []string{renamed.MaterialID}, Payload: DeleteTarget{ID: original.ID}})
	command.RequestID, command.Dependencies = "demo-regrant-registered-node", sortedUniqueDependencies(append(dependencies, revoked.MaterialID))
	regranted := submitAuthority(t, runtime, command)
	if regranted.Projection.DeviceAuthorizations[0].WireGuardPublicKey != public {
		t.Fatal("regrant lost the original registered identity")
	}
	for name, body := range unchanged {
		actual, err := os.ReadFile(filepath.Join(root, "materials", name))
		if err != nil || !bytes.Equal(body, actual) {
			t.Fatal("registration overwrote an original signed fact", err)
		}
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restored := restarted.Authority.Snapshot().DeviceAuthorizations[0]
	if restored.WireGuardPublicKey != public || restored.RuntimeKey != original.RuntimeKey || restored.DevicePublicKey != original.DevicePublicKey {
		t.Fatal("restart replaced registered or device identity")
	}
	devices := projectWebDevices(restarted.Authority.Snapshot())
	found := false
	for _, device := range devices {
		if device.ID == original.ID {
			found = true
			if device.WireGuardPublicKey != public {
				t.Fatal("normal identity readback lost registration")
			}
		}
	}
	if !found {
		t.Fatal("registered node disappeared from normal readback")
	}
	if retried := submitAuthority(t, restarted, command); retried.MaterialID != regranted.MaterialID {
		t.Fatal("same request did not survive restart")
	}
}

func TestRegisteredWireGuardIdentitySurvivesReceivingResourceRemoval(t *testing.T) {
	p := relayProjectionFixture(t)
	before, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	registered := before.WireGuardPublicKey
	if registered == "" || before.WireGuardPrivateKey != "" {
		t.Fatal("fixture must retain a registered fixed private key locally")
	}
	first := accessWireGuardOutbounds(t, before)
	if len(first) != 1 || first[0]["tag"] != WireGuardEndpointTag {
		t.Fatal("WG instance identity depends on its receiving resource")
	}
	p.NetworkIntent.Resources = slices.DeleteFunc(p.NetworkIntent.Resources, func(r TransportResource) bool { return r.Kind == "wireguard" && r.OwnerNodeID == before.DeviceID })
	after, err := ProjectDeviceView(p, before.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if after.WireGuardPublicKey != registered || after.WireGuardPrivateKey != "" {
		t.Fatal("deleting a receiver changed its registered sender identity or selected another private key")
	}
	next := accessWireGuardOutbounds(t, after)
	if len(next) != 1 || next[0]["tag"] != first[0]["tag"] || next[0]["private_key"] != nil || next[0]["execution"] != nil || next[0]["listen_port"] != nil {
		t.Fatal("outgoing-only WG retained receiving authority or invented a private key")
	}
	if !reflect.DeepEqual(next[0]["source_routes"], first[0]["source_routes"]) {
		t.Fatal("same-key outgoing source bindings changed")
	}
	exit, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range exit.Nodes {
		if node.ID == before.DeviceID && node.WireGuardPublicKey != registered {
			t.Fatal("receiver and sender disagree on registered identity")
		}
	}
	for i := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[i].ID == before.DeviceID {
			p.DeviceAuthorizations[i].WireGuardPublicKey = ""
		}
	}
	unregistered, err := ProjectDeviceView(p, before.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if unregistered.WireGuardPublicKey != "" || unregistered.WireGuardPrivateKey != "" {
		t.Fatal("runtime silently re-registered an identity")
	}
	links, err := DerivedViewLinks(unregistered)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		if link.FromNodeID == before.DeviceID && link.ProbeTarget.Action == "wireguard_echo" {
			t.Fatal("unregistered sender received WG forwarding permission")
		}
	}
}

func TestRegisteredWireGuardValuesRoundTripWithoutChangingHistoricalAbsence(t *testing.T) {
	p := wireGuardAccessFixture(t)
	value := p.DeviceAuthorizations[0]
	for _, current := range []bool{false, true} {
		original := value
		if !current {
			original.WireGuardPublicKey = ""
		}
		body, err := CanonicalEncode(original)
		if err != nil {
			t.Fatal(err)
		}
		var restored DeviceAuthorization
		if err := DecodeCanonical(body, &restored, ContractDecodeLimits{MaxBytes: 64 << 10, MaxDepth: 32, MaxItems: 1000}); err != nil {
			t.Fatal(err)
		}
		again, _ := CanonicalEncode(restored)
		if !bytes.Equal(body, again) || !reflect.DeepEqual(original, restored) {
			t.Fatal("registered or historical authorization changed on round trip")
		}
		if bytes.Contains(body, []byte("wireguard_public_key")) != current {
			t.Fatal("historical missing key was rewritten")
		}
	}
	view, err := ProjectDeviceView(p, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	private := view.WireGuardPrivateKey
	view.WireGuardPublicKey = p.DeviceAuthorizations[1].WireGuardPublicKey
	if view.Validate() == nil {
		t.Fatal("private material was accepted for a different registered identity")
	}
	if private == "" {
		t.Fatal("derived sender lost its original private material")
	}
	value.WireGuardPublicKey = "demo-invalid"
	if value.Validate() == nil {
		t.Fatal("invalid public registration accepted")
	}
	view, _ = ProjectDeviceView(p, p.DeviceAuthorizations[1].ID)
	var document map[string]any
	_ = json.Unmarshal([]byte(testDeviceExecution(view).RuntimeProfile.Config), &document)
	if document["endpoints"].([]any)[0].(map[string]any)["private_key"] != nil {
		t.Fatal("fixed receiver key leaked into signed inputs")
	}
}

func TestWireGuardResourceCannotSupplyMissingOrMismatchedNodeIdentity(t *testing.T) {
	for _, absent := range []bool{false, true} {
		p := wireGuardAccessFixture(t)
		for i := range p.DeviceAuthorizations {
			if p.DeviceAuthorizations[i].ID == "demo-exit" {
				if absent {
					p.DeviceAuthorizations[i].WireGuardPublicKey = ""
				} else {
					p.DeviceAuthorizations[i].WireGuardPublicKey = p.DeviceAuthorizations[0].WireGuardPublicKey
				}
			}
		}
		if _, err := ProjectDeviceView(p, "demo-access"); err == nil {
			t.Fatal("receiving resource supplied or overrode its owner's identity")
		}
		if _, err := DerivedNetworkLinks(p); err == nil {
			t.Fatal("graph ignored an unregistered or mismatched receiving identity")
		}
	}
}
