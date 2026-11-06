package linuxclient

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"loom/internal/control"
)

func TestIsolatedTUNNamedResourcePreservesAuthenticationAndResolver(t *testing.T) {
	_, _, makeView := linuxAcceptanceFixture(t)
	envelope := makeView(7, true)
	base := envelope.View
	p, err := control.Project(envelope.ControlProof.Genesis, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	materialID, err := control.MaterialID(envelope.ControlProof.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	access := control.DeviceAuthorization{ID: base.DeviceID, Name: base.Name, Platform: base.Platform,
		DevicePublicKey: base.DevicePublicKey, RuntimeKey: base.DevicePublicKey,
		Responsibilities: base.Responsibilities, PolicyIDs: base.PolicyIDs, DistributionURLs: []string{},
		DNSServers: []string{"192.0.2.53"}, TransactionID: "demo-join", InviteMaterialID: materialID, BindingMaterialID: materialID}
	exit := access
	exit.ID, exit.Name, exit.Responsibilities, exit.PolicyIDs = "demo-exit", "Demo exit", []string{"internet_egress"}, []string{}
	p.DeviceAuthorizations = []control.DeviceAuthorization{access, exit}
	p.EndpointGenerations = base.Endpoints
	p.NetworkIntent.Services, p.NetworkIntent.Policies = base.Services, base.Policies
	p.NetworkIntent.Policies[0].AllowDirect = new(false)
	resourceView, _, _ := resourceExecutionFixture(t)
	resourceView.Resources[0].DialHost = "demo-relay.example"
	p.NetworkIntent.Resources = resourceView.Resources
	view, err := control.ProjectDeviceView(p, access.ID)
	if err != nil || len(testDeviceExecution(view).Routes) != 1 || testDeviceExecution(view).Routes[0].FirstResourceID == "" {
		t.Fatal("fixture has no certified remote resource", err)
	}
	before, err := control.CanonicalEncode(view)
	if err != nil {
		t.Fatal(err)
	}
	config, server, err := generationConfigs(view, "demo-api-secret", nil, "tun", nil)
	if err != nil || server != "" {
		t.Fatal("named resource cannot enter the isolated TUN runtime", err)
	}
	var original, actual map[string]any
	if json.Unmarshal([]byte(testDeviceExecution(view).RuntimeProfile.Config), &original) != nil || json.Unmarshal([]byte(config), &actual) != nil {
		t.Fatal("invalid runtime projection")
	}
	byTag := map[string]map[string]any{}
	for _, raw := range actual["outbounds"].([]any) {
		value := raw.(map[string]any)
		byTag[value["tag"].(string)] = value
	}
	for _, raw := range original["outbounds"].([]any) {
		want := raw.(map[string]any)
		if want["type"] != "hysteria2" {
			continue
		}
		got := byTag[want["tag"].(string)]
		if got["netns"] != tunUnderlayReference || got["server"] != "demo-relay.example" {
			t.Fatal("resource lost its underlay or certified dial name")
		}
		delete(got, "netns")
		if !reflect.DeepEqual(want, got) {
			t.Fatal("capture changed the credential, trust or TLS identity")
		}
	}
	if byTag["loom-underlay-dns"]["netns"] != tunUnderlayReference {
		t.Fatal("resource DNS could recurse into capture")
	}
	foundResolver := false
	for _, raw := range actual["dns"].(map[string]any)["servers"].([]any) {
		server := raw.(map[string]any)
		foundResolver = foundResolver || server["tag"] == "loom-resolver-0" && server["address"] == "udp://192.0.2.53:53" && server["detour"] == "loom-underlay-dns"
	}
	if !foundResolver {
		t.Fatal("resource resolution stopped using the authenticated resolver")
	}
	after, err := control.CanonicalEncode(view)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("local capture rewrote the authority")
	}
	view.DNSServers = []string{}
	noResolver, _, err := generationConfigs(view, "demo-api-secret", nil, "tun", nil)
	if err != nil {
		t.Fatal("an optional named candidate blocked runtime construction", err)
	}
	var denied map[string]any
	if json.Unmarshal([]byte(noResolver), &denied) != nil || denied["dns"].(map[string]any)["final"] != "loom-runtime-deny-dns" {
		t.Fatal("named candidate acquired an implicit system resolver")
	}
}
