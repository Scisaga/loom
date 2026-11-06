package clientadapter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"loom/internal/control"
)

const resourcePoolSource = `{"endpoints":[{"type":"wireguard","tag":"wg-shared","system":false,"address":["127.0.0.1/32","::1/128"],"private_key":"demo-key","source_routes":[{"source":"2001:db8:1::1","destination":"2001:db8:2::/64","execution":"2001:db8:3::1"},{"source":"2001:db8:1::2","destination":"2001:db8:4::/64","execution":"2001:db8:5::1"}],"peers":[{"public_key":"demo-a","address":"192.0.2.10","port":51820,"allowed_ips":["2001:db8:2::/64","2001:db8:3::1/128","2001:db8:ff::1/128"]},{"public_key":"demo-b","address":"192.0.2.11","port":51820,"allowed_ips":["2001:db8:4::/64","2001:db8:5::1/128"]}]}],"outbounds":[{"type":"block","tag":"reject"},{"type":"direct","tag":"loom-internet-egress","public_internet":true},{"type":"selector","tag":"access","outbounds":["reject","demo-wg-a","demo-wg-b","demo-hy2"],"access":{"entries":{"demo-resource-a":{"outbound":"demo-wg-a"},"demo-resource-b":{"outbound":"demo-wg-b"},"demo-resource-c":{"outbound":"demo-hy2"}},"egress_outbounds":{},"forward_outbounds":{}}},{"type":"direct","tag":"demo-wg-a","detour":"wg-shared","inet6_bind_address":"2001:db8:1::1","execution":{"policy_id":""}},{"type":"direct","tag":"demo-wg-b","detour":"wg-shared","inet6_bind_address":"2001:db8:1::2","execution":{"policy_id":""}},{"type":"hysteria2","tag":"demo-hy2","server":"demo.example","server_port":443,"password":"demo-credential","execution":{"policy_id":""}}],"route":{"final":"reject"}}`

func TestNativeResourceBaseSeparatesAuthorityFromSenderDescriptions(t *testing.T) {
	value, err := decodeRuntimeResources(resourcePoolSource)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.outbounds) != 3 {
		t.Fatal("sender descriptions were lost or physical egress became a sender")
	}
	body, err := NativeResourceBase(resourcePoolSource)
	if err != nil {
		t.Fatal(err)
	}
	var base map[string]any
	if json.Unmarshal([]byte(body), &base) != nil {
		t.Fatal("invalid base projection")
	}
	outbounds := base["outbounds"].([]any)
	if len(outbounds) != 3 || outbounds[2].(map[string]any)["access"] == nil {
		t.Fatal("base eagerly materialized resources or lost complete source permission")
	}
	wg := base["endpoints"].([]any)[0].(map[string]any)
	if len(wg["source_routes"].([]any)) != 0 {
		t.Fatal("base eagerly installed sender bindings")
	}
	peers := wg["peers"].([]any)
	if len(peers) != 1 || !reflect.DeepEqual(peers[0].(map[string]any)["allowed_ips"], []any{"2001:db8:ff::1/128"}) {
		t.Fatal("base dropped receiving ownership or retained all sending peers")
	}
	request, err := resourceRequest(value)
	if err != nil || len(request["outbounds"].([]any)) != len(value.outbounds) {
		t.Fatal("complete sender descriptions were lost", err)
	}
	working := request["wireguard"].(map[string]any)
	if len(working["source_routes"].([]any)) != 2 || len(working["peers"].([]any)) != 2 {
		t.Fatal("full WG constructor description was lost")
	}

}

func TestSenderAdditionAndRevocationDoNotReplaceStableFacilities(t *testing.T) {
	var document map[string]any
	_ = json.Unmarshal([]byte(resourcePoolSource), &document)
	outbounds := document["outbounds"].([]any)
	access := outbounds[2].(map[string]any)["access"].(map[string]any)
	entries := access["entries"].(map[string]any)
	delete(entries, "demo-resource-a")
	entries["demo-new"] = map[string]any{"outbound": "demo-new"}
	outbounds[2].(map[string]any)["outbounds"] = []any{"demo-hy2", "demo-new", "demo-wg-b", "reject"}
	// The initial fixture's member table follows the renderer's canonical order.
	var original map[string]any
	_ = json.Unmarshal([]byte(resourcePoolSource), &original)
	original["outbounds"].([]any)[2].(map[string]any)["outbounds"] = []any{"demo-hy2", "demo-wg-a", "demo-wg-b", "reject"}
	before, _ := json.Marshal(original)
	document["outbounds"] = append(outbounds[:3], outbounds[4:]...)
	document["outbounds"] = append(document["outbounds"].([]any), map[string]any{"type": "hysteria2", "tag": "demo-new", "server": "new.example", "server_port": 443, "password": "demo-new-credential", "execution": map[string]any{}})
	after, _ := json.Marshal(document)
	changes, hot, err := RuntimePermissionChanges(string(before), string(after))
	if err != nil || !hot || len(changes) != 1 || changes[0].Tag != "access" {
		t.Fatal("sender materialization blocked current permission delta", hot, err)
	}
	updated, err := WithRuntimePermissions(string(before), changes)
	if err != nil {
		t.Fatal(err)
	}
	permissions, err := RuntimePermissionProjections(updated)
	current, otherErr := RuntimePermissionProjections(string(after))
	if err != nil || otherErr != nil || !reflect.DeepEqual(permissions, current) {
		t.Fatal("permission update retained revoked entry or lost new grant")
	}
}

func TestRuntimePermissionHashesAcceptOnlyCurrentWGListenerOperation(t *testing.T) {
	source := `{"outbounds":[],"endpoints":[{"type":"wireguard","tag":"wg-shared","listen_port":51820,"execution":{"node_id":"demo-node","policies":[],"bindings":[],"sender_authentication_digests":{}}}]}`
	permissions, err := RuntimePermissionProjections(source)
	if err != nil || len(permissions) != 1 {
		t.Fatal(err)
	}
	hashes, err := runtimePermissionHashes(source, permissions[0])
	if err != nil || len(hashes) != 2 {
		t.Fatal("current auth/listener acknowledgements not represented", err)
	}
	for _, bad := range []map[string]any{
		{"execution": permissions[0].Projection["execution"], "wireguard_listener": map[string]any{"port": 51821}},
		{"execution": map[string]any{"node_id": "demo-other", "policies": []any{}, "bindings": []any{}, "sender_authentication_digests": map[string]any{}}, "wireguard_listener": map[string]any{"port": 51820}},
	} {
		hash, err := permissionProjectionHash(bad)
		if err != nil || slices.Contains(hashes, hash) {
			t.Fatal("old port or unrelated permission qualified current authorization", err)
		}
	}
}

func TestResourceDescriptionsConfirmWithoutMaterializingUnusedSenders(t *testing.T) {
	view, _, _ := resourceProbeFixture(t)
	source, err := AccessRuntimeSource(view, "demo-secret")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := decodeRuntimeResources(source)
	if err != nil {
		t.Fatal(err)
	}
	permissions, err := RuntimePermissionProjections(source)
	if err != nil || len(permissions) != 1 {
		t.Fatal(err)
	}
	permissionHash, _ := permissionProjectionHash(permissions[0].Projection)
	state := resourceReadback{Revision: "demo-initial", AuthorizationRevisions: map[string]string{"access": "demo-auth"},
		DescribedOutbounds: map[string]string{}, Outbounds: map[string]string{}, Forwarding: map[string]string{}}
	puts := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer demo-secret" {
			t.Error("local authentication lost")
			http.Error(w, "denied", 403)
			return
		}
		switch r.URL.Path {
		case "/loom/access/access":
			_ = json.NewEncoder(w).Encode(receiverReadback{Revision: "demo-auth", ConfigHash: permissionHash})
		case "/loom/resources":
			if r.Method == http.MethodPut {
				var request map[string]any
				decoder := json.NewDecoder(r.Body)
				decoder.UseNumber()
				if decoder.Decode(&request) != nil || request["expected_revision"] != state.Revision {
					t.Error("description CAS lost its exact base")
					return
				}
				resources := request["outbounds"].([]any)
				if len(resources) != len(parsed.outbounds) {
					t.Error("current full descriptions were filtered by historical use")
				}
				state.DescribedOutbounds = map[string]string{}
				for _, raw := range resources {
					value := raw.(map[string]any)
					hash, _ := permissionProjectionHash(value)
					state.DescribedOutbounds[value["tag"].(string)] = hash
				}
				delete(request, "expected_revision")
				hash, _ := permissionProjectionHash(request)
				state.Revision, state.DesiredConfigHash, state.ConfigHash = "demo-described", hash, hash
				state.WireGuard = true
				puts++
			}
			_ = json.NewEncoder(w).Encode(state)
		default:
			t.Error("unexpected native operation")
			http.Error(w, "unexpected", 404)
		}
	}))
	defer api.Close()
	selector, err := NewHTTPSelector(source)
	if err != nil {
		t.Fatal(err)
	}
	selector.SetDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, api.Listener.Addr().String())
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if ready, err := selector.ReconcileRuntimeResources(ctx, source); err != nil || !ready || puts != 1 || len(state.Outbounds) != 0 {
		t.Fatal("descriptions required unused actual objects", ready, puts, err)
	}
	// Borrowing changes actual objects, never the installed description hash.
	for tag, hash := range state.DescribedOutbounds {
		state.Outbounds[tag] = hash
		break
	}
	if ready, err := selector.ReconcileRuntimeResources(ctx, source); err != nil || !ready || puts != 1 {
		t.Fatal("actual facility existence changed stable description hash", ready, puts, err)
	}
}

func TestResourceDescriptionHashIgnoresActualFacilityExistence(t *testing.T) {
	value, err := decodeRuntimeResources(resourcePoolSource)
	if err != nil {
		t.Fatal(err)
	}
	auth := map[string]string{"access": "demo-auth"}
	a, first, err := currentResourceRequest(value, auth)
	if err != nil {
		t.Fatal(err)
	}
	b, second, err := currentResourceRequest(value, auth)
	if err != nil || first != second || !reflect.DeepEqual(a, b) {
		t.Fatal("constructor definition changed without source change", err)
	}
	if a["wireguard"].(map[string]any)["initializer"] == nil {
		t.Fatal("pure sender lacks its stable first-use initializer")
	}
	var receiver map[string]any
	_ = json.Unmarshal([]byte(resourcePoolSource), &receiver)
	receiver["endpoints"].([]any)[0].(map[string]any)["execution"] = map[string]any{"node_id": "demo-node"}
	body, _ := json.Marshal(receiver)
	received, err := decodeRuntimeResources(string(body))
	if err != nil {
		t.Fatal(err)
	}
	request, _, err := currentResourceRequest(received, auth)
	if err != nil || request["wireguard"].(map[string]any)["initializer"] != nil {
		t.Fatal("receiving facility acquired a sender initializer", err)
	}
}

func TestResourceReadbackRejectsOldOrIncompleteDescriptionSchema(t *testing.T) {
	valid := resourceReadback{Revision: "demo-current", AuthorizationRevisions: map[string]string{}, DescribedOutbounds: map[string]string{}, Outbounds: map[string]string{}, Forwarding: map[string]string{}}
	body, _ := json.Marshal(valid)
	if _, err := decodeResourceReadback(body); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(map[string]any){
		func(v map[string]any) { delete(v, "described_outbounds") },
		func(v map[string]any) { v["requested_outbounds"] = []any{} },
		func(v map[string]any) { v["described_outbounds"] = map[string]any{"demo-a": "invalid"} },
	} {
		var v map[string]any
		_ = json.Unmarshal(body, &v)
		change(v)
		bad, _ := json.Marshal(v)
		if _, err := decodeResourceReadback(bad); err == nil {
			t.Fatal("old or malformed resource proof was accepted")
		}
	}
	if _, err := decodeResourceReadback(append(body, []byte("{}")...)); err == nil {
		t.Fatal("trailing resource proof accepted")
	}
}

// A new preference changes candidates, never the current authorization or the
// descriptions still needed by an authorized connection on the old Policy.
func TestCurrentViewDescriptionsDoNotShrinkWithSelectedCandidates(t *testing.T) {
	view, _, _ := resourceProbeFixture(t)
	for i := range view.Policies {
		if view.Policies[i].ID == "demo-b" {
			view.Policies[i].EntryScope = control.PolicyScope{Mode: "none", NodeIDs: []string{}}
		}
	}
	first, err := control.ProjectDeviceExecution(view, []string{"demo-a"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := control.ProjectDeviceExecution(view, []string{"demo-b"})
	if err != nil {
		t.Fatal(err)
	}
	firstHasResource := false
	for _, route := range first.Routes {
		firstHasResource = firstHasResource || route.FirstResourceID != ""
	}
	for _, route := range second.Routes {
		if route.FirstResourceID != "" {
			t.Fatal("fixture did not separate selected candidates")
		}
	}
	a, err := decodeRuntimeResources(first.RuntimeProfile.Config)
	if err != nil {
		t.Fatal(err)
	}
	b, err := decodeRuntimeResources(second.RuntimeProfile.Config)
	if err != nil {
		t.Fatal(err)
	}
	ah, err := describedResourceHashes(a)
	if err != nil {
		t.Fatal(err)
	}
	bh, err := describedResourceHashes(b)
	if err != nil {
		t.Fatal(err)
	}
	if !firstHasResource || len(ah) == 0 || !reflect.DeepEqual(ah, bh) {
		t.Fatal("preference retired still-authorized sender descriptions")
	}
	for _, source := range []runtimeResourceSource{a, b} {
		for _, outbound := range source.outbounds {
			execution, ok := outbound["execution"].(map[string]any)
			if !ok || execution["policy_id"] != "" || execution["authentication_digest"] == "" {
				t.Fatal("sender description differs from the native typed execution shape")
			}
		}
	}
}

func TestReceivingBaseDoesNotInheritDescriptorKeepalive(t *testing.T) {
	var source map[string]any
	if err := json.Unmarshal([]byte(resourcePoolSource), &source); err != nil {
		t.Fatal(err)
	}
	endpoint := source["endpoints"].([]any)[0].(map[string]any)
	endpoint["execution"] = map[string]any{"node_id": "demo-forward"}
	for _, raw := range endpoint["peers"].([]any) {
		raw.(map[string]any)["persistent_keepalive_interval"] = 25
	}
	body, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	base, err := NativeResourceBase(string(body))
	if err != nil {
		t.Fatal(err)
	}
	var running map[string]any
	if err = json.Unmarshal([]byte(base), &running); err != nil {
		t.Fatal(err)
	}
	receiving := running["endpoints"].([]any)[0].(map[string]any)
	peers := receiving["peers"].([]any)
	if len(peers) != 1 || len(receiving["source_routes"].([]any)) != 0 {
		t.Fatal("base lost its receiving peer or retained idle senders")
	}
	peer := peers[0].(map[string]any)
	if peer["public_key"] != "demo-a" || peer["address"] != "192.0.2.10" || peer["port"] != float64(51820) || !reflect.DeepEqual(peer["allowed_ips"], []any{"2001:db8:ff::1/128"}) {
		t.Fatal("idle projection changed receiving identity, coordinates or ACL")
	}
	if interval, present := peer["persistent_keepalive_interval"]; present && interval != float64(0) {
		t.Fatal("idle receiving base inherited sending keepalive")
	}
	description, err := decodeRuntimeResources(string(body))
	if err != nil {
		t.Fatal(err)
	}
	request, err := resourceRequest(description)
	if err != nil {
		t.Fatal(err)
	}
	wg := request["wireguard"].(map[string]any)
	if len(wg["source_routes"].([]any)) != 2 || len(wg["peers"].([]any)) != 2 {
		t.Fatal("base stripping lost actual sending descriptions")
	}
	for _, raw := range wg["peers"].([]any) {
		if raw.(map[string]any)["persistent_keepalive_interval"] != float64(25) {
			t.Fatal("base changed the original sending keepalive description")
		}
	}
}

func TestAccessOnlyWGDescriptionKeepsActualDemandKeepalive(t *testing.T) {
	view, _, _ := resourceProbeFixture(t, "wireguard")
	if !reflect.DeepEqual(view.Responsibilities, []string{"access"}) {
		t.Fatal("fixture is not access-only")
	}
	source, err := AccessRuntimeSource(view, "demo-secret")
	if err != nil {
		t.Fatal(err)
	}
	descriptions, err := decodeRuntimeResources(source)
	if err != nil {
		t.Fatal(err)
	}
	request, err := resourceRequest(descriptions)
	if err != nil {
		t.Fatal(err)
	}
	wg, ok := request["wireguard"].(map[string]any)
	if !ok || len(wg["source_routes"].([]any)) == 0 || len(wg["peers"].([]any)) == 0 {
		t.Fatal("access-only actual sending description missing")
	}
	for _, raw := range wg["peers"].([]any) {
		if raw.(map[string]any)["persistent_keepalive_interval"] != float64(25) {
			t.Fatal("outgoing keepalive incorrectly depends on owning a receiving resource")
		}
	}
	base, err := NativeResourceBase(source)
	if err != nil {
		t.Fatal(err)
	}
	var running map[string]any
	if err = json.Unmarshal([]byte(base), &running); err != nil {
		t.Fatal(err)
	}
	for _, raw := range running["endpoints"].([]any) {
		endpoint := raw.(map[string]any)
		if endpoint["tag"] == "wg-shared" && (len(endpoint["peers"].([]any)) != 0 || len(endpoint["source_routes"].([]any)) != 0) {
			t.Fatal("access-only startup retained idle sending peers or keepalive")
		}
	}
}

func TestRenderedWGBaseKeepsOnlyActualReceivingAdmission(t *testing.T) {
	view, _, _ := resourceProbeFixture(t, "wireguard")
	other, _, _ := resourceProbeFixture(t, "wireguard")
	view.Responsibilities = []string{"access", "forward"}
	remote := view.Resources[0]
	owned := remote
	owned.ID, owned.OwnerNodeID, owned.ListenerID, owned.DialHost = "demo-owned-wg", view.DeviceID, "demo-owned-listener", "192.0.2.20"
	owned.Authentication.PublicKey = new(view.WireGuardPublicKey)
	owned.Authentication.LocalAddresses = new([]string{"203.0.113.20/32"})
	incoming := remote
	incoming.ID, incoming.OwnerNodeID, incoming.ListenerID, incoming.DialHost = "demo-peer-wg", "demo-peer", "demo-peer-listener", "192.0.2.30"
	incoming.Authentication.PublicKey = new(other.WireGuardPublicKey)
	incoming.Authentication.LocalAddresses = new([]string{"203.0.113.30/32"})
	view.Nodes = append(view.Nodes, control.ViewNode{ID: incoming.OwnerNodeID, WireGuardPublicKey: other.WireGuardPublicKey, Responsibilities: []string{"forward"}, PolicyIDs: []string{}})
	view.Resources = append(view.Resources, owned, incoming)
	slices.SortFunc(view.Resources, func(a, b control.TransportResource) int { return strings.Compare(a.ID, b.ID) })
	facts, err := control.ProjectDeviceExecution(view, nil)
	if err != nil {
		t.Fatal(err)
	}
	receivingPeer := false
	for _, peer := range facts.WireGuardPeers {
		if peer.PublicKey == *remote.Authentication.PublicKey {
			t.Fatal("fixture remote is not outgoing-only")
		}
		receivingPeer = receivingPeer || peer.PublicKey == other.WireGuardPublicKey
	}
	if !receivingPeer {
		t.Fatal("fixture lacks an independently authorized receiving peer")
	}
	source := facts.RuntimeProfile.Config
	base, err := NativeResourceBase(source)
	if err != nil {
		t.Fatal(err)
	}
	var running map[string]any
	if err = json.Unmarshal([]byte(base), &running); err != nil {
		t.Fatal(err)
	}
	endpoint := running["endpoints"].([]any)[0].(map[string]any)
	peers := endpoint["peers"].([]any)
	if len(peers) != 1 {
		t.Fatal("outgoing-only peer survived as a false receiving base", len(peers))
	}
	peer := peers[0].(map[string]any)
	rawKey, err := base64.RawURLEncoding.DecodeString(other.WireGuardPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := control.WireGuardAccessAddress(owned, other.WireGuardPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if peer["public_key"] != base64.StdEncoding.EncodeToString(rawKey) || peer["address"] != incoming.DialHost || peer["port"] != float64(incoming.DialPort) || !reflect.DeepEqual(peer["allowed_ips"], []any{principal.String() + "/128"}) {
		t.Fatal("actual receiving identity, principal or dial coordinates changed")
	}
	if interval, present := peer["persistent_keepalive_interval"]; present && interval != float64(0) {
		t.Fatal("receiving base acquired sending keepalive")
	}
	if len(endpoint["source_routes"].([]any)) != 0 || endpoint["host_sources"] != nil || endpoint["system"] != false {
		t.Fatal("ordinary business projected host access or idle sending routes")
	}
}
