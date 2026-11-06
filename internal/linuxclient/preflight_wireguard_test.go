package linuxclient

import (
	"encoding/json"
	"strings"
	"testing"

	"loom/internal/clientadapter"
	"loom/internal/control"
)

func TestPreflightKeepsCertifiedWGNamesWithoutCreatingHostGeometry(t *testing.T) {
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
	executions, err := prepareResourceExecutions(view, input, at)
	if err != nil {
		t.Fatal(err)
	}
	config, server, err := preflightProjectedConfigs(view, "demo-local", "mixed", executions, clientadapter.WebsiteAccess{}, keys[view.DeviceID])
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
	endpoint := endpoints[0].(map[string]any)
	if endpoint["system"] == true || endpoint["name"] != nil || endpoint["host_sources"] != nil || endpoint["stack_address"] != nil {
		t.Fatal("preflight created host management geometry from a relay resource")
	}
	profile, _, err := projectWireGuard(view, executions)
	if err != nil || len(profile.WireGuard) != 0 || profile.ListenPort == 0 {
		t.Fatal("preflight lost its local receiver port or generated host peers", err)
	}
	if !strings.Contains(config, "demo-peer.example") {
		t.Fatal("pure preflight rewrote the certified sender DNS name")
	}
	after, _ := control.CanonicalEncode(view)
	if string(after) != string(original) {
		t.Fatal("DNS result changed the authoritative View")
	}
	view.DNSServers = []string{}
	denied, _, err := preflightProjectedConfigs(view, "demo-local", "mixed", executions, clientadapter.WebsiteAccess{}, keys[view.DeviceID])
	if err != nil || !strings.Contains(denied, "loom-runtime-deny-dns") {
		t.Fatal("preflight without certified DNS installed an implicit resolver", err)
	}
}
