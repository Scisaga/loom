package clientadapter

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestLocalPrefixReadbackKeepsUnderlayVPNAndUnavailableStates(t *testing.T) {
	for _, sample := range []struct {
		addresses []string
		want      *[]string
	}{
		{nil, nil},
		{[]string{}, new([]string{})},
		{[]string{"192.0.2.1/30", "172.19.0.1/30"}, new([]string{})},
		{[]string{"192.0.2.1/30", "192.0.2.10/24", "198.51.100.6/32", "203.0.113.2/24", "203.0.113.3/24"},
			new([]string{"192.0.2.0/24", "198.51.100.6/32", "203.0.113.0/24"})},
	} {
		actual, err := InterfaceIPv4Prefixes(sample.addresses)
		if err != nil || !reflect.DeepEqual(actual, sample.want) {
			t.Fatal("actual underlay/VPN addresses, capture exclusion or unavailable state changed", err)
		}
	}
	if value, err := InterfaceIPv4Prefixes([]string{"invalid"}); err == nil || value != nil {
		t.Fatal("invalid local observation became available")
	}
}

func TestObservedLocalPrefixEnforcesActualLANConflict(t *testing.T) {
	connected, err := InterfaceIPv4Prefixes([]string{"192.0.2.1/30", "192.0.2.10/24"})
	if err != nil {
		t.Fatal(err)
	}
	source := `{"inbounds":[],"outbounds":[{"type":"block","tag":"reject"}],"route":{"final":"reject","rules":[{"ip_cidr":["192.0.2.0/24"],"outbound":"local_network:demo-lan"}]}}`
	config, err := WithLocalNetworkBoundary(source, connected)
	if err != nil {
		t.Fatal(err)
	}
	var actual struct {
		Route struct {
			Rules []struct {
				Prefixes []string `json:"ip_cidr"`
				Outbound string   `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(config), &actual); err != nil || len(actual.Route.Rules) == 0 {
		t.Fatal("actual LAN guard is missing", err)
	}
	guard := actual.Route.Rules[0]
	if guard.Outbound != "reject" || !reflect.DeepEqual(guard.Prefixes, []string{"192.0.2.0/24"}) {
		t.Fatal("a real local underlay prefix did not restrict the conflicting LAN route")
	}
}
