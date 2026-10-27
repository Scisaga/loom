package clientadapter

import (
	"encoding/json"
	"reflect"
	"testing"

	"loom/internal/control"
)

func TestLocalNetworkBoundaryRestrictsConflictsAndCapture(t *testing.T) {
	// This pure adapter consumes the prefixes in an already certified runtime.
	// Documentation ranges keep the test independent of real LAN addresses.
	source := `{"dns":{"servers":[{"tag":"loom-overlay-dns","address":"loom-static","static_records":{"demo-lan.loom":["192.0.2.17"],"demo-other.loom":["203.0.113.9"]}}]},"inbounds":[{"type":"tun","tag":"tun-in","address":["203.0.113.1/30"],"auto_route":true}],"outbounds":[{"type":"block","tag":"reject"},{"type":"selector","tag":"local_network:demo-lan","outbounds":["demo-candidate"],"default":"demo-candidate"}],"route":{"final":"reject","rules":[{"type":"logical","mode":"or","rules":[{"ip_cidr":["192.0.2.0/24"]},{"domain":["demo-lan.loom"]}],"outbound":"local_network:demo-lan"}]}}`
	for _, tc := range []struct {
		name      string
		connected *[]string
		blocked   bool
	}{
		{"known_disjoint", new([]string{"198.51.100.0/24"}), false},
		{"overlap", new([]string{"192.0.2.128/25"}), true},
		{"unknown_readback", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := WithLocalNetworkBoundary(source, tc.connected)
			if err != nil {
				t.Fatal(err)
			}
			var value struct {
				DNS struct {
					Servers []struct {
						Records map[string][]string `json:"static_records"`
					} `json:"servers"`
				} `json:"dns"`

				Inbounds []struct {
					Routes     []string `json:"route_address"`
					Exclusions []string `json:"route_exclude_address"`
				} `json:"inbounds"`
				Route struct {
					Rules []struct {
						Outbound string `json:"outbound"`
					} `json:"rules"`
				} `json:"route"`
			}
			if err := json.Unmarshal([]byte(body), &value); err != nil {
				t.Fatal(err)
			}
			_, named := value.DNS.Servers[0].Records["demo-lan.loom"]
			if named == tc.blocked || len(value.DNS.Servers[0].Records["demo-other.loom"]) != 1 {
				t.Fatal("conflicting DNS remained or unrelated name disappeared")
			}
			want := []string{"192.0.2.0/24", "203.0.113.0/30"}
			if tc.blocked {
				want = []string{"203.0.113.0/30"}
			}
			if !reflect.DeepEqual(value.Inbounds[0].Routes, want) || (value.Route.Rules[0].Outbound == "reject") != tc.blocked {
				t.Fatal("LAN capture or process restriction differs from local readback")
			}
			if tc.blocked && !reflect.DeepEqual(value.Inbounds[0].Exclusions, []string{"192.0.2.0/24"}) {
				t.Fatal("conflicting physical prefix remained in capture")
			}
		})
	}
}

func TestLocalNetworkIdentityGatewayKeepsItsLANOutsideAccessCapture(t *testing.T) {
	source := `{"dns":{"servers":[{"tag":"loom-overlay-dns","address":"loom-static","static_records":{"demo-lan.loom":["10.64.8.17"]}}]},"inbounds":[{"type":"tun","tag":"demo-capture","address":["192.0.2.1/30"]},{"type":"hysteria2","tag":"demo-resource"}],"outbounds":[{"type":"block","tag":"reject"},{"type":"direct","tag":"local-network-egress:demo-lan","prefix_mapping":{"virtual_prefix":"10.64.8.0/24","local_prefix":"10.64.8.0/24"}},{"type":"selector","tag":"local_network:demo-lan","outbounds":["demo-candidate"],"default":"reject"}],"route":{"final":"reject","rules":[{"inbound":["demo-resource"],"ip_cidr":["10.64.8.0/24"],"outbound":"local-network-egress:demo-lan"},{"type":"logical","mode":"or","rules":[{"ip_cidr":["10.64.8.0/24"]},{"domain":["demo-lan.loom"]}],"outbound":"local_network:demo-lan"}]}}`
	for _, tc := range []struct {
		name      string
		connected *[]string
		physical  bool
		allowed   bool
	}{
		{"own_physical_lan", new([]string{"10.64.8.0/24"}), true, true},
		{"not_a_physical_lan", new([]string{"10.64.8.0/24"}), false, false},
		{"other_overlapping_interface", new([]string{"10.64.8.0/24", "10.64.0.0/16"}), true, false},
		{"unknown_underlay", nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := WithLocalNetworkBoundary(source, tc.connected, control.LocalNetworkPrefix{Prefix: "10.64.8.0/24", LAN: tc.physical})
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal([]byte(body), &document); err != nil {
				t.Fatal(err)
			}
			route := document["route"].(map[string]any)
			globalReject, captureReject, namedReject := false, false, false
			for _, raw := range array(route["rules"]) {
				rule := raw.(map[string]any)
				if rule["outbound"] != "reject" {
					continue
				}
				if reflect.DeepEqual(stringArray(rule["ip_cidr"]), []string{"10.64.8.0/24"}) {
					globalReject = globalReject || len(stringArray(rule["inbound"])) == 0
					captureReject = captureReject || reflect.DeepEqual(stringArray(rule["inbound"]), []string{"demo-capture"})
				}
				namedReject = namedReject || rule["type"] == "logical"
			}
			if globalReject == tc.allowed || tc.allowed && !captureReject || !namedReject {
				t.Fatal("gateway exception removed an access restriction or blocked its authorized physical dial")
			}
			inbound := array(document["inbounds"])[0].(map[string]any)
			if !reflect.DeepEqual(stringArray(inbound["route_address"]), []string{"192.0.2.0/30"}) || !reflect.DeepEqual(stringArray(inbound["route_exclude_address"]), []string{"10.64.8.0/24"}) {
				t.Fatal("gateway's physical underlay was captured by its local access")
			}
			dns := document["dns"].(map[string]any)
			server := array(dns["servers"])[0].(map[string]any)
			records, _ := server["static_records"].(map[string]any)
			if (records["demo-lan.loom"] != nil) != tc.allowed {
				t.Fatal("gateway name resolution disagrees with its permitted final dial")
			}
		})
	}
}
