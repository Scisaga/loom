package clientadapter

import (
	"encoding/json"
	"loom/internal/control"
	"reflect"
	"testing"
)

func TestOverlayDNSCaptureDoesNotManufactureNamesOrUnderlay(t *testing.T) {
	source := `{"inbounds":[{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"block","tag":"reject"}],"route":{"final":"reject","rules":[{"domain_suffix":["loom","demo.example"],"domain":["demo-missing.loom"],"outbound":"reject"}]},"dns":{"servers":[{"tag":"demo-resolver","address":"192.0.2.53","detour":"demo-underlay"}]},"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-local"}}}`
	record := control.DNSRecord{ID: "demo-dns", Name: "demo-present.loom", Addresses: []string{"192.0.2.10"}}
	config, err := WithOverlayDNS(source, []control.DNSRecord{record}, true)
	if err != nil {
		t.Fatal(err)
	}
	config, err = WithTUNDomainDNS(config)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	json.Unmarshal([]byte(config), &got)
	rules := got["dns"].(map[string]any)["rules"].([]any)
	fake := rules[0].(map[string]any)
	if !reflect.DeepEqual(fake["domain"], []any{"demo-present.loom"}) || !reflect.DeepEqual(fake["domain_suffix"], []any{"demo.example"}) || rules[1].(map[string]any)["server"] != "loom-overlay-dns" {
		t.Fatal("capture invented overlay names or lost refusal boundary", rules)
	}
	view := control.DeviceView{Resources: []control.TransportResource{{DialHost: "demo-present.loom"}}}
	if ValidateOverlayUnderlay(view) == nil {
		t.Fatal("overlay could recursively resolve underlay")
	}
	view.Resources[0].DialHost = "demo-underlay.example"
	name := "control.loom"
	view.Resources[0].Authentication.ServerName = &name
	if ValidateOverlayUnderlay(view) != nil {
		t.Fatal("TLS verification name was treated as a dial dependency")
	}
}
