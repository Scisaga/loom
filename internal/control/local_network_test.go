package control

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func localNetworkTestService(t *testing.T, network, id, gateway string) Service {
	t.Helper()
	prefix, err := AllocateLocalNetworkPrefix(network, id, 0, "192.0.2.0/24", nil)
	if err != nil {
		t.Fatal(err)
	}
	return Service{ID: id, Name: "Demo LAN", Kind: "local_network", LocalNetwork: &LocalNetwork{GatewayNodeID: gateway, LocalPrefix: "192.0.2.0/24", VirtualPrefix: prefix.String(), Enabled: true}, RestrictToProbeTargets: new(false)}
}

func TestLocalNetworkAndInternetShareCurrentCanonicalServiceShape(t *testing.T) {
	internet := Service{ID: "demo-service", Name: "Demo", Kind: "internet", RestrictToProbeTargets: new(false)}
	body, err := CanonicalEncode(internet)
	if err != nil || string(body) != `{"id":"demo-service","kind":"internet","name":"Demo","restrict_to_probe_targets":false}` {
		t.Fatal("internet Service bytes changed", err)
	}
	policy := materialTestPolicy("demo-policy", internet.ID)
	policy.AllowDirect = new(false)
	body, err = CanonicalEncode(policy)
	want := `{"action":"allow","allow_direct":false,"entry_scope":{"mode":"any","node_ids":[]},"exit_scope":{"mode":"any","node_ids":[]},"id":"demo-policy","local_egress_devices":[],"name":"Demo policy","relay_scope":{"mode":"any","node_ids":[]},"service_id":"demo-service"}`
	if err != nil || string(body) != want {
		t.Fatal("internet Policy false/empty fields changed", string(body), err)
	}
	lan := localNetworkTestService(t, "demo-network", "demo-service", "demo-gateway")
	for _, service := range []Service{internet, lan} {
		body, err := CanonicalEncode(service)
		var recovered Service
		if err != nil || DecodeCanonical(body, &recovered, contractTestLimits) != nil || !reflect.DeepEqual(service, recovered) {
			t.Fatal("Service value or exact bytes failed recovery", err)
		}
		if service.Kind == "local_network" && bytes.Contains(body, []byte(`"matchers"`)) {
			t.Fatal("LAN mapping was encoded as internet matchers")
		}
	}
	policy.ExitScope, policy.AllowDirect, policy.LocalEgressDevices = nil, nil, nil
	if policy.ValidateForService(lan) != nil || policy.ValidateForService(internet) == nil {
		t.Fatal("LAN Policy shape can be used for an internet Service")
	}
	body, err = CanonicalEncode(policy)
	var recovered NetworkPolicy
	if err != nil || DecodeCanonical(body, &recovered, contractTestLimits) != nil || !reflect.DeepEqual(policy, recovered) {
		t.Fatal("LAN Policy did not round trip", err)
	}
	for _, extra := range []string{`"allow_direct":false,`, `"exit_scope":null,`, `"local_egress_devices":[],`} {
		bad := append([]byte("{"+extra), body[1:]...)
		if DecodeCanonical(bad, &recovered, contractTestLimits) == nil {
			t.Fatal("accepted partial or null internet fields in LAN Policy")
		}
	}
	for _, change := range []func(*Service){
		func(s *Service) { s.Matchers = []ServiceMatcher{} },
		func(s *Service) { s.LocalNetwork.VirtualPrefix = "198.51.100.0/24" },
		func(s *Service) { s.LocalNetwork.LocalPrefix = "192.0.2.1/24" },
		func(s *Service) { s.LocalNetwork.LocalPrefix = "192.0.2.0/25" },
		func(s *Service) { s.LocalNetwork.AllocationAttempt = 4 },
	} {
		bad := localNetworkTestService(t, "demo-network", "demo-service", "demo-gateway")
		change(&bad)
		if _, err := CanonicalEncode(bad); err == nil {
			t.Fatal("accepted invalid LAN mapping")
		}
	}
}

func TestLocalNetworkAllocationExclusionAndExhaustion(t *testing.T) {
	first := localNetworkTestService(t, "demo-network", "demo-a", "demo-gateway-a")
	prefix := netip.MustParsePrefix(first.LocalNetwork.VirtualPrefix)
	for _, bits := range []int{24, 32} {
		local := netip.PrefixFrom(netip.MustParseAddr("192.0.2.0"), bits).String()
		a, err := AllocateLocalNetworkPrefix("demo-network", "demo-b", 0, local, []netip.Prefix{prefix})
		b, secondErr := AllocateLocalNetworkPrefix("demo-network", "demo-b", 0, local, []netip.Prefix{prefix, prefix})
		if err != nil || secondErr != nil || a != b || a.Bits() != bits || !a.Addr().IsPrivate() || a.Overlaps(prefix) {
			t.Fatal("allocation depends on duplicate exclusions or overlaps reserved space", err, secondErr)
		}
	}
	if _, err := AllocateLocalNetworkPrefix("demo-network", "demo-b", 3, "192.0.2.0/24", localNetworkPools); err == nil {
		t.Fatal("exhausted private address space was silently reused")
	}
	intent := EmptyNetworkIntent()
	other := first
	other.ID = "demo-b"
	other.LocalNetwork = new(*first.LocalNetwork)
	other.LocalNetwork.GatewayNodeID = "demo-gateway-b"
	intent.Services = []Service{first, other}
	if conflicts := LocalNetworkConflicts(intent); !conflicts[first.ID] || !conflicts[other.ID] {
		t.Fatal("concurrent overlapping mappings selected a winner")
	}
	allocated, err := AllocateLocalNetworkPrefix("demo-network", other.ID, 1, other.LocalNetwork.LocalPrefix, []netip.Prefix{prefix})
	if err != nil {
		t.Fatal(err)
	}
	other.LocalNetwork.VirtualPrefix, other.LocalNetwork.AllocationAttempt = allocated.String(), 1
	intent.Services[1] = other
	if len(LocalNetworkConflicts(intent)) != 0 {
		t.Fatal("equal local prefixes on distinct gateways were treated as virtual conflicts")
	}
}

func TestLocalNetworkAllocationPrefersSourceInsideTenPool(t *testing.T) {
	for _, tc := range []struct{ local, want string }{
		{"10.64.8.0/24", "10.64.8.0/24"},
		{"192.0.2.0/24", "10.0.2.0/24"},
		{"192.0.0.0/16", "10.0.0.0/16"},
		{"192.0.2.17/32", "10.0.2.17/32"},
		{"192.0.0.0/8", "10.0.0.0/8"},
	} {
		allocated, err := AllocateLocalNetworkPrefix("demo-network", "demo-lan", 0, tc.local, nil)
		if err != nil || allocated.String() != tc.want || ValidateLocalNetworkPrefixes(tc.local, tc.want) != nil {
			t.Fatal("source network bits or length changed", tc, allocated, err)
		}
	}
	preferred := netip.MustParsePrefix("10.64.8.0/24")
	for _, excluded := range [][]netip.Prefix{
		{preferred},
		{netip.MustParsePrefix("10.64.8.128/25")},
		{netip.MustParsePrefix("10.64.0.0/16")},
	} {
		allocated, err := AllocateLocalNetworkPrefix("demo-network", "demo-lan", 0, preferred.String(), excluded)
		duplicate, duplicateErr := AllocateLocalNetworkPrefix("demo-network", "demo-lan", 0, preferred.String(), append(excluded, excluded...))
		if err != nil || duplicateErr != nil || allocated != duplicate || !localNetworkPools[0].Contains(allocated.Addr()) || allocated.Overlaps(excluded[0]) || allocated == preferred {
			t.Fatal("preferred collision did not produce a deterministic disjoint 10 prefix", allocated, err)
		}
	}
	if _, err := AllocateLocalNetworkPrefix("demo-network", "demo-lan", 0, "192.0.2.0/24", localNetworkPools[:1]); err == nil {
		t.Fatal("exhausting 10/8 fell back to another private pool")
	}
	for _, invalid := range []netip.Prefix{{}, netip.MustParsePrefix("2001:db8::/64"), netip.MustParsePrefix("192.0.2.1/24")} {
		if _, err := AllocateLocalNetworkPrefix("demo-network", "demo-lan", 0, preferred.String(), []netip.Prefix{invalid}); err == nil {
			t.Fatal("preferred candidate bypassed invalid exclusion validation")
		}
	}
	for _, prefix := range []string{"172.16.8.0/24", "192.168.8.0/24"} {
		if ValidateLocalNetworkPrefixes("192.0.2.0/24", prefix) != nil || ValidateLocalNetworkPrefixes(prefix, prefix) == nil {
			t.Fatal("historical disjoint mappings changed or non-10 identity mapping was accepted")
		}
		original := []byte(`{"id":"demo-lan","kind":"local_network","local_network":{"allocation_attempt":0,"enabled":true,"gateway_node_id":"demo-gateway","local_prefix":"192.0.2.0/24","virtual_prefix":"` + prefix + `"},"name":"Demo LAN"}`)
		var service Service
		if err := DecodeCanonical(original, &service, contractTestLimits); err != nil {
			t.Fatal("historical private mapping no longer decodes", err)
		}
		if encoded, err := CanonicalEncode(service); err != nil || !bytes.Equal(encoded, original) {
			t.Fatal("historical private mapping bytes changed", err)
		}
	}
	service := localNetworkTestService(t, "demo-network", "demo-lan", "demo-gateway")
	service.LocalNetwork.LocalPrefix, service.LocalNetwork.VirtualPrefix = preferred.String(), preferred.String()
	intent := EmptyNetworkIntent()
	intent.Services = []Service{service}
	if len(LocalNetworkConflicts(intent)) != 0 {
		t.Fatal("gateway's own identical source was treated as an external conflict")
	}
	other := localNetworkTestService(t, "demo-network", "demo-other", "demo-other-gateway")
	other.LocalNetwork.VirtualPrefix = preferred.String()
	intent.Services = append(intent.Services, other)
	if conflicts := LocalNetworkConflicts(intent); !conflicts[service.ID] || !conflicts[other.ID] {
		t.Fatal("identity source exemption hid another Service's virtual overlap")
	}
}

func localNetworkProjectionFixture(t *testing.T) Projection {
	p := relayProjectionFixture(t)
	p.DeviceAuthorizations[1].Responsibilities = []string{"forward"}
	p.NetworkIntent.Services[0] = localNetworkTestService(t, p.NetworkID, p.NetworkIntent.Services[0].ID, "demo-exit")
	p.NetworkIntent.Policies[0].ExitScope, p.NetworkIntent.Policies[0].AllowDirect, p.NetworkIntent.Policies[0].LocalEgressDevices = nil, nil, nil
	service := p.NetworkIntent.Services[0]
	address := netip.MustParsePrefix(service.LocalNetwork.VirtualPrefix).Addr().Next()
	p.NetworkIntent.DNSRecords = []DNSRecord{{ID: "demo-lan-dns", Name: "demo-lan.loom", ServiceID: service.ID, Addresses: []string{address.String()}}}
	return p
}

func TestLocalNetworkFixedGatewayTranslationAndWithdrawal(t *testing.T) {
	p := localNetworkProjectionFixture(t)
	for _, id := range []string{"demo-access", "demo-entry", "demo-exit"} {
		view, err := ProjectDeviceView(p, id)
		if err != nil {
			t.Fatal(id, err)
		}
		body, err := CanonicalEncode(view)
		var recovered DeviceView
		if err != nil || DecodeCanonical(body, &recovered, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000}) != nil || !reflect.DeepEqual(view, recovered) {
			t.Fatal("LAN View failed original byte recovery", err)
		}
		if id == "demo-access" {
			if len(testDeviceExecution(view).Routes) != 2 || len(testDeviceExecution(view).BusinessProbeTargets) != 1 || len(testDeviceExecution(view).BusinessProbeTargets[0].Targets) != 0 {
				t.Fatal("LAN lost one-hop/relay alternatives or invented business evidence")
			}
			for _, route := range testDeviceExecution(view).Routes {
				if route.FinalExit != "demo-exit" || route.Scope != "local_network:"+route.ServiceID {
					t.Fatal("LAN acquired an arbitrary internet exit or shared internet scope")
				}
			}
		}
		var config struct {
			Outbounds []map[string]any `json:"outbounds"`
		}
		if err := json.Unmarshal([]byte(testDeviceExecution(view).RuntimeProfile.Config), &config); err != nil {
			t.Fatal(err)
		}
		mappings := 0
		for _, outbound := range config.Outbounds {
			if outbound["prefix_mapping"] != nil {
				mappings++
				if outbound["type"] != "direct" || outbound["detour"] != nil || id != "demo-exit" {
					t.Fatal("translation moved before the fixed final gateway")
				}
			}
		}
		if (id == "demo-exit") != (mappings == 1) {
			t.Fatal("gateway does not own exactly one mapping for the Service")
		}
	}
	for _, change := range []func(*Projection){
		func(p *Projection) { p.NetworkIntent.Services[0].LocalNetwork.Enabled = false },
		func(p *Projection) { p.NetworkIntent.Services = []Service{} },
		func(p *Projection) { p.NetworkIntent.Policies[0].Action = "deny" },
		func(p *Projection) { p.DeviceAuthorizations[0].PolicyIDs = []string{} },
		func(p *Projection) { p.DeviceAuthorizations[1].Responsibilities = []string{"internet_egress"} },
		func(p *Projection) {
			other := p.NetworkIntent.Services[0]
			other.ID = "demo-z-conflict"
			p.NetworkIntent.Services = append(p.NetworkIntent.Services, other)
		},
	} {
		copy := localNetworkProjectionFixture(t)
		change(&copy)
		noConsumers := len(copy.DeviceAuthorizations[0].PolicyIDs) == 0
		for _, id := range []string{"demo-access", "demo-entry", "demo-exit"} {
			view, err := ProjectDeviceView(copy, id)
			if noConsumers {
				if err != nil || len(testDeviceExecution(view).Routes) != 0 || len(testDeviceExecution(view).AccessGrants) != 0 {
					t.Fatal("withdrawn origin retained an access grant", id, err)
				}
				for _, permission := range view.TransportCredentials {
					if permission.SenderID == "demo-access" {
						t.Fatal("withdrawn origin retained access credentials")
					}
				}
				continue
			}
			if err != nil || len(testDeviceExecution(view).Routes) != 0 || testDeviceExecution(view).RuntimeProfile != nil && strings.Contains(testDeviceExecution(view).RuntimeProfile.Config, `"prefix_mapping"`) {
				t.Fatal("withdrawn LAN left a candidate, credential or translation", id, err)
			}
		}
	}
}
