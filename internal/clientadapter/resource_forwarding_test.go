package clientadapter

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
	"time"
)

func resourceForwardingFixture(policy string, expanded bool) map[string]any {
	nodes := []any{"demo-exit", "demo-node"}
	edges := []any{map[string]any{"from": "demo-node", "to": "demo-exit"}}
	bindings := map[string]any{"demo-wg-a": "demo-exit"}
	choices := []any{"demo-wg-a"}
	if expanded {
		nodes = []any{"demo-exit", "demo-next", "demo-node"}
		edges = []any{map[string]any{"from": "demo-next", "to": "demo-exit"}, map[string]any{"from": "demo-node", "to": "demo-exit"}, map[string]any{"from": "demo-node", "to": "demo-next"}}
		bindings["demo-hy2"] = "demo-next"
		choices = append(choices, "demo-hy2")
	}
	return map[string]any{
		"policy":  map[string]any{"policy_id": policy, "service_id": "demo-service", "kind": "internet", "origins": []any{}, "exits": []any{"demo-exit"}, "nodes": nodes, "entry_scope": map[string]any{"mode": "any", "node_ids": []any{}}, "relay_scope": map[string]any{"mode": "any", "node_ids": []any{}}, "max_hops": float64(0), "edges": edges},
		"node_id": "demo-node", "nodes": bindings, "exit_choices": map[string]any{"demo-exit": choices},
	}
}

func resourceSourceWithForwarding(t *testing.T, descriptors map[string]map[string]any) string {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal([]byte(resourcePoolSource), &document); err != nil {
		t.Fatal(err)
	}
	values := document["outbounds"].([]any)
	members, err := accessMemberReferences(values[2].(map[string]any)["access"])
	if err != nil {
		t.Fatal(err)
	}
	values[2].(map[string]any)["outbounds"] = members
	tags := []string{}
	for tag := range descriptors {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		hop := descriptors[tag]
		nodes := hop["nodes"].(map[string]any)
		members := []any{"reject"}
		bindings := map[string]any{}
		keys := []string{}
		for candidate := range nodes {
			keys = append(keys, candidate)
		}
		sort.Strings(keys)
		for _, candidate := range keys {
			members = append(members, candidate)
			bindings[candidate] = hop["policy"].(map[string]any)["policy_id"]
		}
		values = append(values, map[string]any{"type": "selector", "tag": tag, "outbounds": members, "default": "reject", "candidate_policies": bindings, "hop": hop})
	}
	document["outbounds"] = values
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestRuntimeForwardingGraphAndContainerChangesDoNotReplaceFacilities(t *testing.T) {
	before := resourceSourceWithForwarding(t, map[string]map[string]any{"forward:demo-policy": resourceForwardingFixture("demo-policy", false)})
	after := resourceSourceWithForwarding(t, map[string]map[string]any{"forward:demo-policy": resourceForwardingFixture("demo-policy", true), "forward:demo-extra": resourceForwardingFixture("demo-extra", false)})
	changes, hot, err := RuntimePermissionChanges(before, after)
	if err != nil || !hot || len(changes) != 0 {
		t.Fatal("a disposable forwarding graph or container changed native facilities", hot, err)
	}
	value, err := decodeRuntimeResources(after)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range value.base["outbounds"].([]any) {
		if raw.(map[string]any)["hop"] != nil {
			t.Fatal("startup eagerly created disposable forwarding containers")
		}
	}
	request, err := resourceRequest(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(request["outbounds"].([]any)) != len(value.outbounds) {
		t.Fatal("a forwarding descriptor lost current leaf constructor descriptions")
	}
	expected := map[string]any{"forward:demo-policy": resourceForwardingFixture("demo-policy", true), "forward:demo-extra": resourceForwardingFixture("demo-extra", false)}
	if !reflect.DeepEqual(request["forwarding"], expected) {
		t.Fatal("the resource operation lost the complete current forwarding descriptors")
	}
	updated, err := WithRuntimeResourceDescriptions(before, after)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	_ = json.Unmarshal([]byte(updated), &document)
	found := map[string]any{}
	for _, raw := range document["outbounds"].([]any) {
		entry := raw.(map[string]any)
		if hop := entry["hop"]; hop != nil {
			found[entry["tag"].(string)] = hop
		}
	}
	if !reflect.DeepEqual(found, expected) {
		t.Fatal("prepared profile retained an old forwarding template")
	}
	without := resourceSourceWithForwarding(t, map[string]map[string]any{})
	if _, hot, err := RuntimePermissionChanges(after, without); err != nil || !hot {
		t.Fatal("retiring a forwarding container required instance replacement", err)
	}
}

func TestRuntimeForwardingReferencesAreDerivedFromTheSameDescriptor(t *testing.T) {
	before := resourceSourceWithForwarding(t, map[string]map[string]any{"forward:demo-policy": resourceForwardingFixture("demo-policy", false)})
	var document map[string]any
	_ = json.Unmarshal([]byte(before), &document)
	values := document["outbounds"].([]any)
	entry := values[len(values)-1].(map[string]any)
	entry["outbounds"] = append(entry["outbounds"].([]any), "demo-foreign")
	body, _ := json.Marshal(document)
	if _, _, err := RuntimePermissionChanges(before, string(body)); err == nil {
		t.Fatal("an arbitrary member was hidden as a disposable graph update")
	}
}

func TestForwardingReadbackCannotAcknowledgeAnOldGraph(t *testing.T) {
	withAPI := func(source string) string {
		var value map[string]any
		_ = json.Unmarshal([]byte(source), &value)
		value["experimental"] = map[string]any{"clash_api": map[string]any{"external_controller": "127.0.0.1:61800", "secret": "demo-secret"}}
		body, _ := json.Marshal(value)
		return string(body)
	}
	before := withAPI(resourceSourceWithForwarding(t, map[string]map[string]any{"forward:demo-policy": resourceForwardingFixture("demo-policy", false)}))
	after := withAPI(resourceSourceWithForwarding(t, map[string]map[string]any{"forward:demo-policy": resourceForwardingFixture("demo-policy", true)}))
	permissions, err := RuntimePermissionProjections(before)
	if err != nil || len(permissions) != 1 {
		t.Fatal(err)
	}
	permissionHash, _ := permissionProjectionHash(permissions[0].Projection)
	old, err := decodeRuntimeResources(before)
	if err != nil {
		t.Fatal(err)
	}
	forwarding, _ := forwardingResourceHashes(old)
	state := resourceReadback{Revision: "demo-current", AuthorizationRevisions: map[string]string{"access": "demo-auth"}, DescribedOutbounds: map[string]string{}, Outbounds: map[string]string{}, Forwarding: forwarding, WireGuard: true}
	_, hash, err := currentResourceRequest(old, state.AuthorizationRevisions)
	if err != nil {
		t.Fatal(err)
	}
	state.DescribedOutbounds, _ = describedResourceHashes(old)
	state.ConfigHash, state.DesiredConfigHash = hash, hash
	puts := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer demo-secret" {
			t.Error("lost local authentication")
		}
		switch r.URL.Path {
		case "/loom/access/access":
			_ = json.NewEncoder(w).Encode(receiverReadback{Revision: "demo-auth", ConfigHash: permissionHash})
		case "/loom/resources":
			if r.Method == http.MethodPut {
				var body map[string]any
				decoder := json.NewDecoder(r.Body)
				decoder.UseNumber()
				if decoder.Decode(&body) != nil || body["forwarding"] == nil {
					t.Error("resource operation lost its current traversal")
				}
				delete(body, "expected_revision")
				currentHash, _ := permissionProjectionHash(body)
				state.Revision, state.ConfigHash, state.DesiredConfigHash = "demo-applied", currentHash, currentHash
				// Deliberately retain the old actual descriptor hash. An ACK for
				// another graph must not become current execution evidence.
				puts++
			}
			_ = json.NewEncoder(w).Encode(state)
		default:
			t.Error("unexpected local operation", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer api.Close()
	selector, err := NewHTTPSelector(before)
	if err != nil {
		t.Fatal(err)
	}
	selector.SetDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, api.Listener.Addr().String())
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	accepted, err := selector.ApplyRuntimeAuthorization(ctx, before, after, before)
	if err != nil || !accepted.PermissionCurrent || accepted.ResourcesReady {
		t.Fatal("old traversal ACK claimed the new graph was already applied", accepted.ResourcesReady, err)
	}
	if ready, err := selector.ReconcileRuntimeResources(ctx, after); ready || err == nil || puts != 1 {
		t.Fatal("wrong actual forwarding hash confirmed the new resource operation", ready, puts, err)
	}
}
