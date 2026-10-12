package linuxclient

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/control"
)

func TestPreflightUsesCertifiedWGExecutionAddressWithoutChangingAuthority(t *testing.T) {
	p, keys, input, at := nativeProjectionFixture(t)
	for i := range p.DeviceAuthorizations {
		p.DeviceAuthorizations[i].DNSServers = []string{"192.0.2.53"}
	}
	for i := range p.NetworkIntent.Resources {
		if p.NetworkIntent.Resources[i].ID == "demo-exit-wg" {
			p.NetworkIntent.Resources[i].DialHost = "demo-peer.example"
		}
	}
	view, err := control.ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	original, err := control.CanonicalEncode(view)
	if err != nil {
		t.Fatal(err)
	}
	executions, err := prepareHY2Executions(view, input, at)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	config, server, err := preflightProjectedConfigs(ctx, view, "demo-local", "mixed", executions, clientadapter.WebsiteAccess{}, keys[view.DeviceID], nativePeerTestDNS(t))
	if err != nil || server != "" {
		t.Fatal("Named WG preflight did not render the shared endpoint", err)
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(config), &value); err != nil {
		t.Fatal(err)
	}
	endpoints, ok := value["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		t.Fatal("preflight duplicated the shared WG endpoint")
	}
	peers := endpoints[0].(map[string]any)["peers"].([]any)
	resolved := false
	for _, raw := range peers {
		peer := raw.(map[string]any)
		if peer["address"] == "192.0.2.12" && peer["port"] == float64(51822) {
			resolved = true
		}
	}
	if !resolved || strings.Contains(config, `"address":"demo-peer.example"`) {
		t.Fatal("Native preflight left a hostname for implicit resolution")
	}
	after, _ := control.CanonicalEncode(view)
	if string(after) != string(original) {
		t.Fatal("DNS result changed the authoritative View")
	}
	view.DNSServers = []string{}
	if _, _, err := preflightProjectedConfigs(ctx, view, "demo-local", "mixed", executions, clientadapter.WebsiteAccess{}, keys[view.DeviceID], nil); err == nil {
		t.Fatal("Preflight fell back to host DNS")
	}
}
