package clientadapter

import (
	"encoding/json"
	"net/netip"
	"testing"

	"loom/internal/netx"
)

func TestInternetCaptureWithoutLANUsesPositiveRangesAndOwnedDNS(t *testing.T) {
	const source = `{"dns":{"servers":[{"tag":"loom-tun-domain","address":"fakeip"}],"fakeip":{"enabled":true,"inet4_range":"198.18.0.0/15","inet6_range":"2001:db8:8000::/49"}},"inbounds":[{"type":"tun","tag":"tun-in","address":["192.0.2.1/30","2001:db8::1/126"],"auto_route":true}],"outbounds":[{"type":"selector","tag":"access"}],"route":{"final":"reject","rules":[{"public_internet":true,"outbound":"access"}]}}`
	var input map[string]any
	if err := json.Unmarshal([]byte(source), &input); err != nil {
		t.Fatal(err)
	}
	// A current authenticated endpoint is generated from the public model;
	// no real machine address or network access is needed by this test.
	endpoint := netip.MustParsePrefix(netx.PublicInternetPrefixes()[0]).Addr().Next()
	inbound := array(input["inbounds"])[0].(map[string]any)
	inbound["route_exclude_address"] = []string{netip.PrefixFrom(endpoint, endpoint.BitLen()).String()}
	body, _ := json.Marshal(input)
	projected, err := WithLocalNetworkBoundary(string(body), new([]string{}))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(projected), &document); err != nil {
		t.Fatal(err)
	}
	inbound = array(document["inbounds"])[0].(map[string]any)
	ranges := stringArray(inbound["route_address"])
	exclusions := stringArray(inbound["route_exclude_address"])
	contains := func(values []string, address netip.Addr) bool {
		for _, value := range values {
			prefix := netip.MustParsePrefix(value)
			if prefix.Bits() == 0 {
				t.Fatal("an explicit Internet scope became a default route")
			}
			if prefix.Contains(address) {
				return true
			}
		}
		return false
	}
	localIPv6 := netip.MustParsePrefix("fc00::/7").Addr().Next().String()
	for _, text := range []string{"127.0.0.1", "::1", "10.0.0.1", "169.254.0.1", localIPv6} {
		if contains(ranges, netip.MustParseAddr(text)) {
			t.Fatal("Internet-only capture included loopback, LAN or underlay space")
		}
	}
	for _, text := range []string{"192.0.2.2", "2001:db8::2", "198.18.0.7", "2001:db8:8000::7"} {
		if !contains(ranges, netip.MustParseAddr(text)) {
			t.Fatal("the explicitly owned tunnel or domain DNS pool is not captured")
		}
	}
	for _, value := range netx.PublicInternetPrefixes() {
		if !contains(ranges, netip.MustParsePrefix(value).Addr()) {
			t.Fatal("ordinary Internet depends on a finite list of probe destinations")
		}
	}
	if !contains(exclusions, endpoint) {
		t.Fatal("current management endpoint exclusion was lost")
	}
	if document["route"].(map[string]any)["final"] != "reject" {
		t.Fatal("capture changed the permission fallback")
	}
}

func TestTUNCaptureKeepsReceiverPermissionsAndLANSeparateFromInternet(t *testing.T) {
	const source = `{"inbounds":[{"type":"tun","tag":"tun-in","address":["203.0.113.1/30"],"auto_route":true}],"outbounds":[{"type":"selector","tag":"access"},{"type":"selector","tag":"local_network:demo-lan"}],"route":{"final":"reject","rules":[{"ip_cidr":["192.0.2.0/24"],"outbound":"local_network:demo-lan"},{"type":"logical","mode":"and","rules":[{"inbound":["resource:demo-receiver"]},{"public_internet":true}],"outbound":"egress:demo-service"}]}}`
	for _, tc := range []struct {
		name      string
		internet  bool
		connected *[]string
		lan       bool
	}{
		{"receiver_only", false, new([]string{"198.51.100.0/24"}), true},
		{"internet_and_lan", true, new([]string{"198.51.100.0/24"}), true},
		{"lan_conflict", true, new([]string{"192.0.2.128/25"}), false},
		{"lan_unknown", true, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var input map[string]any
			if err := json.Unmarshal([]byte(source), &input); err != nil {
				t.Fatal(err)
			}
			if tc.internet {
				route := input["route"].(map[string]any)
				route["rules"] = append(array(route["rules"]), map[string]any{"public_internet": true, "outbound": "access"})
			}
			body, _ := json.Marshal(input)
			projected, err := WithLocalNetworkBoundary(string(body), tc.connected)
			if err != nil {
				t.Fatal(err)
			}
			var output map[string]any
			if err := json.Unmarshal([]byte(projected), &output); err != nil {
				t.Fatal(err)
			}
			inbound := array(output["inbounds"])[0].(map[string]any)
			captured := func(address netip.Addr) bool {
				for _, value := range stringArray(inbound["route_address"]) {
					if netip.MustParsePrefix(value).Contains(address) {
						return true
					}
				}
				return false
			}
			if captured(netip.MustParseAddr("192.0.2.17")) != tc.lan {
				t.Fatal("LAN capture bypassed its independent authorization or underlay conflict")
			}
			if captured(netip.MustParsePrefix(netx.PublicInternetPrefixes()[0]).Addr()) != tc.internet {
				t.Fatal("a receiving resource's permission became a local Internet capture grant")
			}
		})
	}
}
