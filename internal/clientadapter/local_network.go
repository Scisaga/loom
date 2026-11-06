package clientadapter

import (
	"encoding/json"
	"errors"
	"loom/internal/control"
	"loom/internal/netx"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
)

// ConnectedIPv4Prefixes reads the local underlay. Including other VPNs is
// deliberate for conflict detection: their addresses must not enter Loom.
// The platform's own fixed capture subnet is reserved by the allocator.
func ConnectedIPv4Prefixes() (*[]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	addresses := []string{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		local, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, address := range local {
			addresses = append(addresses, address.String())
		}
	}
	return InterfaceIPv4Prefixes(addresses)
}

// InterfaceIPv4Prefixes consumes a platform's UP, non-loopback interface
// addresses. A nil slice means unavailable readback; an empty slice is known.
// Resource addresses are remote coordinates and never identify owned local
// interfaces. Only the platform capture addresses below are omitted.
func InterfaceIPv4Prefixes(addresses []string) (*[]string, error) {
	if addresses == nil {
		return nil, nil
	}
	ignored := map[netip.Addr]bool{netip.MustParseAddr("172.19.0.1"): true, netip.MustParseAddr("192.0.2.1"): true}

	values := map[string]bool{}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			return nil, errors.New("invalid platform interface address")
		}
		if !ignored[prefix.Addr()] && prefix.Addr().Is4() && prefix.Addr().IsGlobalUnicast() && prefix.Bits() >= 8 {
			values[prefix.Masked().String()] = true
		}
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return &result, nil
}

// UnderlayNetworkReport carries conflict evidence only. Generic interface
// enumeration cannot certify a physical LAN and its connected route.
func UnderlayNetworkReport(prefixes *[]string) *[]control.LocalNetworkPrefix {
	if prefixes == nil {
		return nil
	}
	values := make([]control.LocalNetworkPrefix, 0, len(*prefixes))
	for _, prefix := range *prefixes {
		values = append(values, control.LocalNetworkPrefix{Prefix: prefix})
	}
	return &values
}

// WithLocalNetworkBoundary is a one-way local restriction. Missing underlay
// readback blocks LAN scopes; it never disables unrelated Internet services.
// It only changes process configuration, never host routes or signed input.
func WithLocalNetworkBoundary(config string, connected *[]string, localNetworks ...control.LocalNetworkPrefix) (string, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	route, ok := document["route"].(map[string]any)
	if !ok {
		return "", errors.New("LAN boundary requires runtime routes")
	}
	rules, _ := route["rules"].([]any)
	prefixes, _ := localRuntimePrefixes(document)
	if len(prefixes) == 0 {
		if err := applyTUNCapture(document); err != nil {
			return "", err
		}
		body, err := json.Marshal(document)
		return string(body), err
	}
	underlay := []netip.Prefix{}
	if connected != nil {
		for _, text := range *connected {
			prefix, err := netip.ParsePrefix(text)
			if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
				return "", errors.New("invalid connected prefix")
			}
			underlay = append(underlay, prefix)
		}
	}
	// Only a gateway's final, range-checked dialer can use its own identical
	// physical LAN. Local access selectors and capture remain restricted.
	gatewayLocal := map[string]bool{}
	for _, raw := range array(document["outbounds"]) {
		outbound, _ := raw.(map[string]any)
		mapping, _ := outbound["prefix_mapping"].(map[string]any)
		virtual, _ := mapping["virtual_prefix"].(string)
		if outbound["type"] != "direct" || virtual == "" || mapping["local_prefix"] != virtual || connected == nil {
			continue
		}
		physical, nonPhysical := false, false
		for _, network := range localNetworks {
			if network.Prefix == virtual {
				physical = physical || network.LAN
				nonPhysical = nonPhysical || !network.LAN
			}
		}
		prefix, err := netip.ParsePrefix(virtual)
		if err != nil || !physical || nonPhysical {
			continue
		}
		exact, otherOverlap := false, false
		for _, local := range underlay {
			exact = exact || prefix == local
			otherOverlap = otherOverlap || prefix.Overlaps(local) && prefix != local
		}
		gatewayLocal[virtual] = exact && !otherOverlap
	}
	blocked := []string{}
	for _, text := range prefixes {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return "", err
		}
		conflict := connected == nil
		for _, local := range underlay {
			conflict = conflict || prefix.Overlaps(local)
		}
		if conflict {
			blocked = append(blocked, text)
		}
	}
	if len(blocked) > 0 {
		globalBlocked, localBlocked := []string{}, []string{}
		for _, prefix := range blocked {
			if gatewayLocal[prefix] {
				localBlocked = append(localBlocked, prefix)
			} else {
				globalBlocked = append(globalBlocked, prefix)
			}
		}
		blockedTags := map[string]bool{}
		for _, raw := range array(document["outbounds"]) {
			outbound, _ := raw.(map[string]any)
			mapping, _ := outbound["prefix_mapping"].(map[string]any)
			prefix, _ := mapping["virtual_prefix"].(string)
			if slices.Contains(globalBlocked, prefix) {
				tag, _ := outbound["tag"].(string)
				blockedTags[tag] = true
			}
		}
		var intersects func(map[string]any) bool
		intersects = func(rule map[string]any) bool {
			for _, prefix := range stringArray(rule["ip_cidr"]) {
				if slices.Contains(blocked, prefix) {
					return true
				}
			}
			for _, raw := range array(rule["rules"]) {
				child, _ := raw.(map[string]any)
				if intersects(child) {
					return true
				}
			}
			return false
		}
		for _, raw := range rules {
			rule, _ := raw.(map[string]any)
			tag, _ := rule["outbound"].(string)
			if strings.HasPrefix(tag, "local_network:") && intersects(rule) {
				blockedTags[tag] = true
			}
		}
		// Deny the whole affected Service, including its names. An IP-only
		// guard cannot stop a proxy request whose destination is still a name.
		guardedRules := make([]any, 0, len(rules))
		for _, raw := range rules {
			rule, _ := raw.(map[string]any)
			tag, _ := rule["outbound"].(string)
			if blockedTags[tag] {
				deny := maps.Clone(rule)
				deny["outbound"] = "reject"
				guardedRules = append(guardedRules, deny)
			}
			guardedRules = append(guardedRules, raw)
		}
		rules = guardedRules
		// Do not return a virtual address that now names an underlay host.
		if dns, ok := document["dns"].(map[string]any); ok {
			for _, raw := range array(dns["servers"]) {
				server, _ := raw.(map[string]any)
				if server["tag"] != "loom-overlay-dns" {
					continue
				}
				records, _ := server["static_records"].(map[string]any)
				for name, addresses := range records {
					for _, text := range stringArray(addresses) {
						address, _ := netip.ParseAddr(text)
						for _, prefix := range globalBlocked {
							if netip.MustParsePrefix(prefix).Contains(address) {
								delete(records, name)
							}
						}
					}
				}
				if len(records) == 0 {
					server["address"] = "rcode://name_error"
					delete(server, "static_records")
				}
			}
		}
		index := len(rules)
		for i, raw := range rules {
			rule, _ := raw.(map[string]any)
			outbound, _ := rule["outbound"].(string)
			if strings.HasPrefix(outbound, "service:") || strings.HasPrefix(outbound, "local_network:") || strings.HasPrefix(outbound, "local-network-egress:") {
				index = i
				break
			}
		}
		// If a server ACL embeds the egress in a nested rule, restriction must
		// precede it as well. Server profiles have no local capture prefix.
		if index == len(rules) {
			index = 0
		}
		guards := []any{}
		if len(globalBlocked) > 0 {
			guards = append(guards, map[string]any{"ip_cidr": globalBlocked, "outbound": "reject"})
		}
		if len(localBlocked) > 0 {
			inbounds := []string{}
			for _, raw := range array(document["inbounds"]) {
				inbound, _ := raw.(map[string]any)
				switch inbound["type"] {
				case "tun", "mixed", "socks", "http":
					if tag, _ := inbound["tag"].(string); tag != "" {
						inbounds = append(inbounds, tag)
					}
				}
			}
			if len(inbounds) > 0 {
				guards = append(guards, map[string]any{"inbound": inbounds, "ip_cidr": localBlocked, "outbound": "reject"})
			}
		}
		rules = append(rules[:index], append(guards, rules[index:]...)...)
		route["rules"] = rules
	}
	if err := applyTUNCapture(document); err != nil {
		return "", err
	}
	body, err := json.Marshal(document)
	return string(body), err
}

func array(value any) []any { result, _ := value.([]any); return result }
func stringArray(value any) []string {
	if values, ok := value.([]string); ok {
		return append([]string(nil), values...)
	}
	result := []string{}
	for _, raw := range array(value) {
		if text, ok := raw.(string); ok {
			result = append(result, text)
		}
	}
	return result
}
func localRuntimePrefixes(document map[string]any) ([]string, bool) {
	values := map[string]bool{}
	internet := false
	for _, raw := range array(document["outbounds"]) {
		outbound, _ := raw.(map[string]any)
		if mapping, ok := outbound["prefix_mapping"].(map[string]any); ok {
			if prefix, ok := mapping["virtual_prefix"].(string); ok {
				values[prefix] = true
			}
		}
	}
	var visit func(map[string]any, bool)
	visit = func(rule map[string]any, lan bool) {
		tag, _ := rule["outbound"].(string)
		lan = lan || strings.HasPrefix(tag, "local_network:")
		if lan {
			for _, value := range stringArray(rule["ip_cidr"]) {
				values[value] = true
			}
		}
		for _, raw := range array(rule["rules"]) {
			if child, ok := raw.(map[string]any); ok {
				visit(child, lan)
			}
		}
	}
	if route, ok := document["route"].(map[string]any); ok {
		for _, raw := range array(route["rules"]) {
			if rule, ok := raw.(map[string]any); ok {
				internet = internet || rule["outbound"] == control.AccessSelectorScope && hasPublicInternetMatcher(rule)
				visit(rule, false)
			}
		}
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, internet
}

func hasPublicInternetMatcher(rule map[string]any) bool {
	if rule["invert"] == true {
		return false
	}
	if rule["public_internet"] == true {
		return true
	}
	for _, raw := range array(rule["rules"]) {
		if child, ok := raw.(map[string]any); ok && hasPublicInternetMatcher(child) {
			return true
		}
	}
	return false
}

// WithTUNCapture projects the existing access rules into positive capture
// ranges. Local conflict guards, when present, only narrow those ranges.
func WithTUNCapture(config string) (string, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	if err := applyTUNCapture(document); err != nil {
		return "", err
	}
	body, err := json.Marshal(document)
	return string(body), err
}

func applyTUNCapture(document map[string]any) error {
	for _, raw := range array(document["inbounds"]) {
		inbound, _ := raw.(map[string]any)
		if inbound["type"] != "tun" {
			continue
		}
		capture, exclusions, err := accessCapturePrefixes(document, stringArray(inbound["address"]), stringArray(inbound["route_exclude_address"]))
		if err != nil {
			return err
		}
		inbound["route_address"] = capture
		if len(exclusions) > 0 {
			inbound["route_exclude_address"] = exclusions
		}
	}
	return nil
}

func accessCapturePrefixes(document map[string]any, addresses, exclusions []string) ([]string, []string, error) {
	prefixes, internet := localRuntimePrefixes(document)
	blocked := map[string]bool{}
	route, _ := document["route"].(map[string]any)
	for _, raw := range array(route["rules"]) {
		rule, _ := raw.(map[string]any)
		if rule["outbound"] == "reject" {
			for _, prefix := range stringArray(rule["ip_cidr"]) {
				if slices.Contains(prefixes, prefix) {
					blocked[prefix] = true
				}
			}
		}
	}
	var capture []string
	if internet {
		capture = netx.PublicInternetPrefixes()
	}
	exclusions = append([]string(nil), exclusions...)
	for _, prefix := range prefixes {
		if blocked[prefix] {
			exclusions = append(exclusions, prefix)
		} else {
			capture = append(capture, prefix)
		}
	}
	for _, text := range addresses {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return nil, nil, err
		}
		capture = append(capture, prefix.Masked().String())
	}
	if dns, ok := document["dns"].(map[string]any); ok {
		for _, raw := range array(dns["servers"]) {
			server, _ := raw.(map[string]any)
			if server["tag"] != "loom-tun-domain" || server["address"] != "fakeip" {
				continue
			}
			pool, _ := dns["fakeip"].(map[string]any)
			if pool["enabled"] != true {
				return nil, nil, errors.New("TUN domain DNS capture has no enabled address pool")
			}
			for _, key := range []string{"inet4_range", "inet6_range"} {
				text, _ := pool[key].(string)
				prefix, err := netip.ParsePrefix(text)
				if err != nil || prefix != prefix.Masked() {
					return nil, nil, errors.New("TUN domain DNS capture has an invalid address pool")
				}
				capture = append(capture, text)
			}
		}
	}
	if len(capture) == 0 {
		return nil, nil, errors.New("TUN capture has no positive address boundary")
	}
	sort.Strings(capture)
	capture = slices.Compact(capture)
	sort.Strings(exclusions)
	return capture, slices.Compact(exclusions), nil
}
