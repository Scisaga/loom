package control

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestWGStackDefaultsDoNotDependOnSenderResourcesOrReceiver(t *testing.T) {
	p := wireGuardAccessFixture(t)
	for _, node := range []string{"demo-access", "demo-entry"} {
		view, err := ProjectDeviceView(p, node)
		if err != nil {
			t.Fatal(err)
		}
		execution := testDeviceExecution(view)
		credentials, err := executionCredentials(view)
		if err != nil {
			t.Fatal(err)
		}
		// Receiving coordinates are not an ongoing sending demand. The complete
		// outgoing descriptors below may still carry their actual keepalive.
		receiving, err := sharedWireGuardEndpoint(execution, credentials, map[string]map[string]bool{})
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range receiving["peers"].([]any) {
			if interval, present := raw.(map[string]any)["persistent_keepalive_interval"]; present && interval != 0 {
				t.Fatal("receiving-only coordinates caused static keepalive")
			}
		}
		sources := map[string]map[string]bool{}
		for _, resource := range execution.Resources {
			if resource.Kind != "wireguard" || resource.OwnerNodeID == node {
				continue
			}
			sources[resource.ID] = map[string]bool{}
			endpoint, err := sharedWireGuardEndpoint(execution, credentials, sources)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(endpoint["address"], []string{"127.0.0.1/32", "::1/128"}) {
				t.Fatal("WG stack initialization changed with resource sources or receiving identity")
			}
			rows := endpoint["source_routes"].([]map[string]string)
			if len(rows) != len(sources) {
				t.Fatal("stable stack defaults discarded raw resource bindings")
			}
			for _, row := range rows {
				if row["source"] == "127.0.0.1" || row["source"] == "::1" {
					t.Fatal("stack initialization address became a sender principal")
				}
			}
		}
		if len(sources) == 0 {
			t.Fatal("fixture lacks an independent outgoing WG resource")
		}
		if owned, found, err := ownedWireGuard(execution.Resources, node); err != nil {
			t.Fatal(err)
		} else if found {
			var config struct {
				Endpoints []map[string]any `json:"endpoints"`
			}
			if err := json.Unmarshal([]byte(execution.RuntimeProfile.Config), &config); err != nil {
				t.Fatal(err)
			}
			address, err := WireGuardAccessAddress(owned, "")
			if err != nil || len(config.Endpoints) != 1 || config.Endpoints[0]["execution_address"] != address.String() || config.Endpoints[0]["execution"] == nil {
				t.Fatal("stable stack defaults removed or changed owned receiving execution", err)
			}
		}
	}
}

func TestNewWGEntryChangesPermissionAndResourceDescriptionsWithoutStaticDiagnostics(t *testing.T) {
	p := wireGuardAccessFixture(t)
	project := func() (DeviceExecution, map[string]any) {
		t.Helper()
		view, err := ProjectDeviceView(p, "demo-access")
		if err != nil {
			t.Fatal(err)
		}
		execution := testDeviceExecution(view)
		var document map[string]any
		if err := json.Unmarshal([]byte(execution.RuntimeProfile.Config), &document); err != nil {
			t.Fatal(err)
		}
		return execution, document
	}
	before, first := project()
	var added TransportResource
	for i := range p.NetworkIntent.Resources {
		if p.NetworkIntent.Resources[i].ID == "demo-entry-wg" {
			p.NetworkIntent.Resources[i].AccessEnabled = true
			added = p.NetworkIntent.Resources[i]
		}
	}
	after, next := project()
	if len(after.Routes) <= len(before.Routes) {
		t.Fatal("fixture did not add a legal WG entry")
	}
	source, err := WireGuardPacketSource(added, after.WireGuardPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	foundDescription := false
	for _, raw := range next["outbounds"].([]any) {
		outbound := raw.(map[string]any)
		if outbound["tag"] == mustTransportTag(added.ID) {
			foundDescription = outbound["type"] == "direct" && outbound["execution"] != nil && outbound["detour"] == WireGuardEndpointTag && outbound["inet6_bind_address"] == source.String()
		}
	}
	if !foundDescription {
		t.Fatal("adding an entry lost its complete original sender description")
	}
	for _, execution := range []DeviceExecution{before, after} {
		if strings.Contains(execution.RuntimeProfile.Config, "loom-link-probe") || strings.Contains(execution.RuntimeProfile.Config, "wg-base.") || strings.Contains(execution.RuntimeProfile.Config, "auth_user") {
			t.Fatal("raw runtime retained per-resource or per-scope diagnostic facilities")
		}
	}
	stableFacilities := func(document map[string]any) map[string]any {
		t.Helper()
		outbounds := []any{}
		for _, raw := range document["outbounds"].([]any) {
			outbound := raw.(map[string]any)
			tag, _ := outbound["tag"].(string)
			if strings.HasPrefix(tag, "transport:") || outbound["access"] != nil {
				continue // The complete source grant and raw sender descriptions may change.
			}
			outbounds = append(outbounds, raw)
		}
		document["outbounds"] = outbounds
		for _, raw := range document["endpoints"].([]any) {
			endpoint := raw.(map[string]any)
			delete(endpoint, "source_routes")
			delete(endpoint, "peers")
		}
		return document
	}
	if !reflect.DeepEqual(stableFacilities(first), stableFacilities(next)) {
		t.Fatal("adding an entry changed unrelated static facilities")
	}
	prior, err := FirstHopProbes(before)
	if err != nil {
		t.Fatal(err)
	}
	current, err := FirstHopProbes(after)
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range prior {
		found := false
		for _, value := range current {
			if value.Resource.ID == old.Resource.ID && value.PolicyID == old.PolicyID {
				found = value.SpecDigest == old.SpecDigest && value.Credential == old.Credential && value.Action() == old.Action() && value.Target() == old.Target()
			}
		}
		if !found {
			t.Fatal("diagnostic execution changes altered an existing measurement specification")
		}
	}
}

func TestSourceAndReceiverBindActualSenderAuthentication(t *testing.T) {
	p := wireGuardAccessFixture(t)
	for i := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[i].ID == "demo-exit" {
			p.DeviceAuthorizations[i].Responsibilities = []string{"internet_egress"}
		}
	}
	for _, id := range []string{"demo-access", "demo-entry", "demo-exit"} {
		view, err := ProjectDeviceView(p, id)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal([]byte(testDeviceExecution(view).RuntimeProfile.Config), &document); err != nil {
			t.Fatal(err)
		}
		descriptions := map[string]string{}
		outbounds := document["outbounds"].([]any)
		for _, raw := range outbounds {
			entry := raw.(map[string]any)
			if execution, ok := entry["execution"].(map[string]any); ok {
				digest, _ := execution["authentication_digest"].(string)
				if ValidateDigest(digest) != nil {
					t.Fatal("actual sender lacks a canonical authentication binding")
				}
				descriptions[entry["tag"].(string)] = digest
			}
		}
		for _, raw := range outbounds {
			access, ok := raw.(map[string]any)["access"].(map[string]any)
			if !ok {
				continue
			}
			for _, raw := range access["entries"].(map[string]any) {
				entry := raw.(map[string]any)
				if digest := descriptions[entry["outbound"].(string)]; digest == "" || entry["authentication_digest"] != digest {
					t.Fatal("source permission disagrees with its actual sender identity")
				}
			}
		}
		for _, section := range []string{"inbounds", "endpoints"} {
			entries, _ := document[section].([]any)
			for _, raw := range entries {
				execution, ok := raw.(map[string]any)["execution"].(map[string]any)
				if !ok {
					continue
				}
				digests, ok := execution["sender_authentication_digests"].(map[string]any)
				if !ok {
					t.Fatal("receiving permission omitted its complete sender binding map")
				}
				for tag, digest := range descriptions {
					if digests[tag] != digest {
						t.Fatal("receiving continuation disagrees with its actual sender identity")
					}
				}
				if id == "demo-exit" && len(digests) != 0 {
					t.Fatal("egress-only receiver acquired outgoing transport permission")
				}
			}
		}
	}
}
