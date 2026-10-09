package control

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
)

// LocalNetworkPrefix is a signed readback value, never a sharing grant.
// LAN requires platform evidence of a physical directly connected subnet.
type LocalNetworkPrefix struct {
	Prefix string `json:"prefix"`
	LAN    bool   `json:"lan"`
}

// LocalNetwork is a value of its Service, not a separately identified mapping.
type LocalNetwork struct {
	GatewayNodeID     string `json:"gateway_node_id"`
	LocalPrefix       string `json:"local_prefix"`
	VirtualPrefix     string `json:"virtual_prefix"`
	AllocationAttempt int    `json:"allocation_attempt"`
	Enabled           bool   `json:"enabled"`
}

var localNetworkPools = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

var errNoLocalNetworkPrefix = errors.New("no nonconflicting private prefix can fit the local network")

func localNetworkPrefix(text string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(text)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix != prefix.Masked() || prefix.String() != text || !prefix.Addr().IsGlobalUnicast() {
		return netip.Prefix{}, errors.New("local network requires a canonical unicast IPv4 prefix of at least /8")
	}
	return prefix, nil
}

func (value LocalNetwork) Validate() error {
	if ValidateID(value.GatewayNodeID) != nil || value.GatewayNodeID == "direct" || value.AllocationAttempt < 0 || value.AllocationAttempt > 3 {
		return errors.New("local network mapping is invalid")
	}
	return ValidateLocalNetworkPrefixes(value.LocalPrefix, value.VirtualPrefix)
}

func ValidateLocalNetworkPrefixes(localText, virtualText string) error {
	local, localErr := localNetworkPrefix(localText)
	virtual, virtualErr := localNetworkPrefix(virtualText)
	if localErr != nil || virtualErr != nil || local.Bits() != virtual.Bits() || local.Overlaps(virtual) {
		return errors.New("local and virtual prefixes must be disjoint canonical IPv4 prefixes of equal length")
	}
	for _, pool := range localNetworkPools {
		if virtual.Bits() >= pool.Bits() && pool.Contains(virtual.Addr()) {
			return nil
		}
	}
	return errors.New("virtual network must fit wholly inside a private IPv4 pool")
}

func (service Service) Scope() string {
	if service.Kind == "local_network" {
		return "local_network:" + service.ID
	}
	return "service:" + service.ID
}

// TargetMatchers is a runtime projection. The LAN wire retains the complete
// mapping; callers cannot encode it as an internet Service with an IP matcher.
func (service Service) TargetMatchers(records ...DNSRecord) []ServiceMatcher {
	if service.LocalNetwork != nil {
		matchers := []ServiceMatcher{{Kind: "ip_prefix", Value: service.LocalNetwork.VirtualPrefix}}
		for _, record := range records {
			if dnsRecordForLocalNetwork(record, service) {
				matchers = append(matchers, ServiceMatcher{Kind: "dns_exact", Value: record.Name})
			}
		}
		sort.Slice(matchers, func(i, j int) bool { return serviceMatcherLess(matchers[i], matchers[j]) })
		return matchers
	}
	return append([]ServiceMatcher{}, service.Matchers...)
}

func ipv4Number(address netip.Addr) uint64 {
	value := address.As4()
	return uint64(binary.BigEndian.Uint32(value[:]))
}

func prefixLast(prefix netip.Prefix) uint64 {
	return ipv4Number(prefix.Masked().Addr()) + (uint64(1) << (32 - prefix.Bits())) - 1
}

// AllocateLocalNetworkPrefix is pure. It subtracts occupied slot intervals,
// rather than scanning millions of addresses when the requested prefix is /32.
func AllocateLocalNetworkPrefix(networkID, serviceID string, attempt int, localText string, excluded []netip.Prefix) (netip.Prefix, error) {
	local, err := localNetworkPrefix(localText)
	if err != nil || ValidateID(networkID) != nil || ValidateID(serviceID) != nil || attempt < 0 || attempt > 3 {
		return netip.Prefix{}, errors.New("local network allocation input is invalid")
	}
	type interval struct{ first, last uint64 }
	type poolSlots struct {
		base uint64
		free []interval
	}
	size := uint64(1) << (32 - local.Bits())
	blocks := append(append([]netip.Prefix{}, excluded...), local)
	for _, value := range []string{"172.19.0.0/30", "192.0.2.0/30", "198.18.0.0/15"} {
		blocks = append(blocks, netip.MustParsePrefix(value))
	}
	var pools []poolSlots
	var count uint64
	for _, pool := range localNetworkPools {
		if pool.Bits() > local.Bits() {
			continue
		}
		base, end := ipv4Number(pool.Addr()), prefixLast(pool)
		occupied := []interval{}
		for _, block := range blocks {
			if !block.IsValid() || !block.Addr().Is4() || block != block.Masked() {
				return netip.Prefix{}, errors.New("allocation exclusions must be masked IPv4 prefixes")
			}
			if !pool.Overlaps(block) {
				continue
			}
			first, last := max(base, ipv4Number(block.Addr())), min(end, prefixLast(block))
			occupied = append(occupied, interval{(first - base) / size, (last - base) / size})
		}
		sort.Slice(occupied, func(i, j int) bool { return occupied[i].first < occupied[j].first })
		slots := poolSlots{base: base, free: []interval{}}
		next, limit := uint64(0), (end-base+1)/size
		for _, block := range occupied {
			if next < block.first {
				slots.free = append(slots.free, interval{next, block.first - 1})
			}
			next = max(next, block.last+1)
		}
		if next < limit {
			slots.free = append(slots.free, interval{next, limit - 1})
		}
		for _, free := range slots.free {
			count += free.last - free.first + 1
		}
		pools = append(pools, slots)
	}
	if count == 0 {
		return netip.Prefix{}, errNoLocalNetworkPrefix
	}
	body, err := CanonicalEncode(map[string]any{"network_id": networkID, "service_id": serviceID, "allocation_attempt": attempt})
	if err != nil {
		return netip.Prefix{}, err
	}
	digest := sha256.Sum256(append([]byte("loom-local-network-prefix-v3\x00"), body...))
	choice := binary.BigEndian.Uint64(digest[:8]) % count
	for _, pool := range pools {
		for _, free := range pool.free {
			length := free.last - free.first + 1
			if choice >= length {
				choice -= length
				continue
			}
			var address [4]byte
			binary.BigEndian.PutUint32(address[:], uint32(pool.base+(free.first+choice)*size))
			return netip.PrefixFrom(netip.AddrFrom4(address), local.Bits()), nil
		}
	}
	panic("validated local network slot count disagrees with its intervals")
}

// LocalNetworkConflicts is a disposable index. Both sides of an overlap stop;
// disabled mappings retain their reserved prefix but never regain permission.
func LocalNetworkConflicts(intent NetworkIntent) map[string]bool {
	conflicts := map[string]bool{}
	overlay := []netip.Prefix{}
	for _, resource := range intent.Resources {
		if resource.Authentication.LocalAddresses != nil {
			for _, text := range *resource.Authentication.LocalAddresses {
				if prefix, err := netip.ParsePrefix(text); err == nil && prefix.Addr().Is4() {
					overlay = append(overlay, prefix.Masked())
				}
			}
		}
	}
	for _, service := range intent.Services {
		if service.LocalNetwork == nil {
			continue
		}
		virtual, err := netip.ParsePrefix(service.LocalNetwork.VirtualPrefix)
		if err != nil {
			conflicts[service.ID] = true
			continue
		}
		for _, prefix := range overlay {
			if virtual.Overlaps(prefix) {
				conflicts[service.ID] = true
			}
		}
		for _, other := range intent.Services {
			if other.LocalNetwork == nil {
				continue
			}
			local, _ := netip.ParsePrefix(other.LocalNetwork.LocalPrefix)
			if virtual.Overlaps(local) {
				conflicts[service.ID] = true
			}
			if other.ID != service.ID {
				prefix, _ := netip.ParsePrefix(other.LocalNetwork.VirtualPrefix)
				if virtual.Overlaps(prefix) {
					conflicts[service.ID], conflicts[other.ID] = true, true
				}
			}
		}
	}
	return conflicts
}

func executableServices(projection Projection) map[string]Service {
	conflicts := LocalNetworkConflicts(projection.NetworkIntent)
	services := map[string]Service{}
	for _, service := range projection.NetworkIntent.Services {
		if value := service.LocalNetwork; value != nil {
			gateway, found := authorizationFor(projection, value.GatewayNodeID)
			if !value.Enabled || conflicts[service.ID] || !found || !containsString(gateway.Responsibilities, "forward") {
				continue
			}
		}
		services[service.ID] = service
	}
	return services
}

func validateServiceGateway(material Material, view Projection, service Service) error {
	if service.LocalNetwork == nil {
		return nil
	}
	node := service.LocalNetwork.GatewayNodeID
	gateway, found := authorizationFor(view, node)
	if !found || !containsString(gateway.Responsibilities, "forward") {
		return errors.New("local network gateway requires a current forward authorization")
	}
	return requireTargetDependency(material, view, "device", node, true)
}

func validateLocalNetworkTransition(services []Service, next Service) error {
	value := next.LocalNetwork
	for _, service := range services {
		if service.ID != next.ID || service.LocalNetwork == nil {
			continue
		}
		prior := service.LocalNetwork
		if *prior == *value {
			return nil
		}
		disabled := *prior
		disabled.Enabled = false
		if *value == disabled {
			return nil
		}
		if value.Enabled && value.AllocationAttempt == 0 {
			return nil
		} // Explicit administrator allocation round.
		if prior.Enabled && value.Enabled && prior.GatewayNodeID == value.GatewayNodeID && prior.LocalPrefix == value.LocalPrefix && value.AllocationAttempt == prior.AllocationAttempt+1 {
			return nil
		}
		return errors.New("LAN transition must preserve its mapping, allocate the next attempt, or explicitly start a new round")
	}
	if !value.Enabled || value.AllocationAttempt != 0 {
		return errors.New("new LAN Service requires an enabled initial allocation")
	}
	return nil
}
