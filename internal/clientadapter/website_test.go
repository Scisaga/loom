package clientadapter

import (
	"encoding/json"
	"loom/internal/control"
	"reflect"
	"testing"
)

func TestWebsiteDNSKeepsReservedNameOffTUNFakeIP(t *testing.T) {
	source := `{"inbounds":[{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"block","tag":"reject"}],"route":{"final":"reject","rules":[{"domain_suffix":["loom"],"outbound":"reject"}]},"dns":{"servers":[{"tag":"demo-resolver","address":"192.0.2.53","detour":"demo-underlay"}]},"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-local"}}}`
	record := control.DNSRecord{ID: "demo-dns", Name: "demo-service.loom", Addresses: []string{"192.0.2.10"}}
	website := WebsiteAccess{Port: 8443, Addresses: []string{"192.0.2.20", "2001:db8::20"}}
	config, err := WithOverlayDNS(source, []control.DNSRecord{record}, true, website.Addresses...)
	if err != nil {
		t.Fatal(err)
	}
	config, err = WithWebsiteRoute(config, website)
	if err != nil {
		t.Fatal(err)
	}
	config, err = WithTUNDomainDNS(config)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		DNS struct {
			Servers []struct {
				Records map[string][]string `json:"static_records"`
			} `json:"servers"`
			Rules []struct {
				Domain []string `json:"domain"`
				Server string   `json:"server"`
			} `json:"rules"`
		} `json:"dns"`
		Route struct {
			Rules []json.RawMessage `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(config), &result); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.DNS.Rules[0].Domain, []string{record.Name}) || result.DNS.Rules[0].Server != "loom-tun-domain" {
		t.Fatal("business suffix captured the reserved website name")
	}
	if !reflect.DeepEqual(result.DNS.Servers[1].Records["control.loom"], website.Addresses) {
		t.Fatal("website DNS lost the actual underlay addresses")
	}
	var route map[string]any
	_ = json.Unmarshal(result.Route.Rules[0], &route)
	want := map[string]any{"domain": []any{"control.loom"}, "network": "tcp", "port": []any{float64(8443)}, "outbound": "website-underlay"}
	if !reflect.DeepEqual(route, want) {
		t.Fatal("website proxy permission was broadened")
	}
	exclusions, err := website.Exclusions()
	if err != nil || !reflect.DeepEqual(exclusions, []string{"192.0.2.20/32", "2001:db8::20/128"}) {
		t.Fatal("website exclusions are not exact", err)
	}
	for _, addresses := range [][]string{{"0.0.0.0"}, {"ff0e::1"}, {"192.0.2.20", "192.0.2.20"}, {"2001:db8::20", "192.0.2.20"}} {
		if (WebsiteAccess{Port: 8443, Addresses: addresses}).Validate() == nil {
			t.Fatal("invalid website addresses accepted")
		}
	}
}
