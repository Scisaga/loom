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
	return Service{ID: id, Name: "Demo LAN", Kind: "local_network", LocalNetwork: &LocalNetwork{GatewayNodeID: gateway, LocalPrefix: "192.0.2.0/24", VirtualPrefix: prefix.String(), Enabled: true}}
}

func TestLocalNetworkContractPreservesInternetBytes(t *testing.T) {
	internet := Service{ID: "demo-service", Name: "Demo", Kind: "internet", Matchers: []ServiceMatcher{{Kind: "ip_prefix", Value: "192.0.2.0/24"}}}
	body, err := CanonicalEncode(internet)
	if err != nil || string(body) != `{"id":"demo-service","kind":"internet","matchers":[{"kind":"ip_prefix","value":"192.0.2.0/24"}],"name":"Demo"}` {
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
			if len(view.Routes) != 2 || len(view.BusinessProbeTargets) != 1 || len(view.BusinessProbeTargets[0].Targets) != 0 {
				t.Fatal("LAN lost one-hop/relay alternatives or invented business evidence")
			}
			for _, route := range view.Routes {
				if route.FinalExit != "demo-exit" || route.Scope != "local_network:"+route.ServiceID {
					t.Fatal("LAN acquired an arbitrary internet exit or shared internet scope")
				}
			}
		}
		var config struct {
			Outbounds []map[string]any `json:"outbounds"`
		}
		if err := json.Unmarshal([]byte(view.RuntimeProfile.Config), &config); err != nil {
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
		for _, id := range []string{"demo-access", "demo-entry", "demo-exit"} {
			view, err := ProjectDeviceView(copy, id)
			if err != nil || len(view.Routes) != 0 || len(view.InboundCredentials) != 0 || view.RuntimeProfile != nil && strings.Contains(view.RuntimeProfile.Config, `"prefix_mapping"`) {
				t.Fatal("withdrawn LAN left a candidate, credential or translation", id, err)
			}
		}
	}
}
