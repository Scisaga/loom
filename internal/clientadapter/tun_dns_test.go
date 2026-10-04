package clientadapter

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestTUNDomainDNSPreservesAuthorityAndSeparatesUnderlay(t *testing.T) {
	source := `{"inbounds":[{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"block","tag":"reject"}],"route":{"final":"reject","rules":[{"type":"logical","mode":"or","rules":[{"domain":["demo-z.example","demo-a.example"]},{"domain_suffix":["demo.example"]}],"outbound":"reject"}]},"dns":{"servers":[{"tag":"demo-resolver","address":"192.0.2.53","detour":"demo-underlay"}]},"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-local"}}}`
	body, err := WithTUNDomainDNS(source)
	if err != nil {
		t.Fatal(err)
	}
	var old, got map[string]any
	_ = json.Unmarshal([]byte(source), &old)
	_ = json.Unmarshal([]byte(body), &got)
	for _, key := range []string{"inbounds", "outbounds", "route"} {
		if !reflect.DeepEqual(old[key], got[key]) {
			t.Fatal("DNS capture changed authorization or traffic source", key)
		}
	}
	dns := got["dns"].(map[string]any)
	if !reflect.DeepEqual(dns["servers"].([]any)[0], old["dns"].(map[string]any)["servers"].([]any)[0]) {
		t.Fatal("changed the certified underlay resolver")
	}
	want := map[string]any{"inbound": []any{"tun-in"}, "query_type": []any{"A", "AAAA"}, "domain": []any{"demo-a.example", "demo-z.example"}, "domain_suffix": []any{"demo.example"}, "server": "loom-tun-domain"}
	if !reflect.DeepEqual(dns["rules"], []any{want}) || dns["independent_cache"] != true || dns["reverse_mapping"] != nil {
		t.Fatal("domain capture is not restricted to TUN service-name queries")
	}
	if _, err := WithTUNDomainDNS(body); err == nil {
		t.Fatal("accepted a second capture projection")
	}
	if _, err := WithTUNDomainDNS(strings.Replace(source, `"domain_suffix":["demo.example"]`, `"ip_cidr":["198.18.0.0/24"]`, 1)); err == nil {
		t.Fatal("accepted a concrete target inside the synthetic address pool")
	}
}
