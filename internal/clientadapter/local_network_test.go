package clientadapter

import (
	"encoding/json"
	"reflect"
	"testing"
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
