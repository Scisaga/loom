package clientadapter

import (
	"encoding/json"
	"errors"
	"loom/internal/control"
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
func ConnectedIPv4Prefixes(resources ...control.TransportResource) (*[]string, error) {
	ignored := map[netip.Addr]bool{netip.MustParseAddr("172.19.0.1"): true, netip.MustParseAddr("192.0.2.1"): true}
	for _, resource := range resources {
		if resource.Authentication.LocalAddresses != nil {
			for _, text := range *resource.Authentication.LocalAddresses {
				if prefix, err := netip.ParsePrefix(text); err == nil {
					ignored[prefix.Addr()] = true
				}
			}
		}
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	values := map[string]bool{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && !ignored[prefix.Addr()] && prefix.Addr().Is4() && prefix.Addr().IsGlobalUnicast() && prefix.Bits() >= 8 {
				values[prefix.Masked().String()] = true
			}
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
func WithLocalNetworkBoundary(config string, connected *[]string) (string, error) {
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
		return config, nil
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
		blockedTags := map[string]bool{}
		for _, raw := range array(document["outbounds"]) {
			outbound, _ := raw.(map[string]any)
			mapping, _ := outbound["prefix_mapping"].(map[string]any)
			prefix, _ := mapping["virtual_prefix"].(string)
			if slices.Contains(blocked, prefix) {
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
						for _, prefix := range blocked {
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
		guard := map[string]any{"ip_cidr": blocked, "outbound": "reject"}
		rules = append(rules[:index], append([]any{guard}, rules[index:]...)...)
		route["rules"] = rules
	}
	guarded, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	for _, raw := range array(document["inbounds"]) {
		inbound, _ := raw.(map[string]any)
		if inbound["type"] != "tun" {
			continue
		}
		capture, exclusions, err := LocalNetworkCapture(string(guarded), stringArray(inbound["address"]), stringArray(inbound["route_exclude_address"]))
		if err != nil {
			return "", err
		}
		if len(capture) > 0 {
			inbound["route_address"] = capture
		}
		if len(exclusions) > 0 {
			inbound["route_exclude_address"] = exclusions
		}
	}
	body, err := json.Marshal(document)
	return string(body), err
}

func array(value any) []any { result, _ := value.([]any); return result }
func stringArray(value any) []string {
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
		tag, _ := outbound["tag"].(string)
		internet = internet || strings.HasPrefix(tag, "service:")
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

// LocalNetworkCapture derives exact capture values from the existing scopes
// and deny rules. The validator uses the same pure projection.
func LocalNetworkCapture(config string, addresses, exclusions []string) ([]string, []string, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return nil, nil, err
	}
	prefixes, internet := localRuntimePrefixes(document)
	if len(prefixes) == 0 {
		return nil, exclusions, nil
	}
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
	exclusions = append([]string(nil), exclusions...)
	for _, prefix := range prefixes {
		if blocked[prefix] {
			exclusions = append(exclusions, prefix)
		} else if !internet {
			capture = append(capture, prefix)
		}
	}
	if !internet {
		for _, text := range addresses {
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				return nil, nil, err
			}
			capture = append(capture, prefix.Masked().String())
		}
		if len(capture) == 0 {
			return nil, nil, errors.New("LAN capture has no explicit address boundary")
		}
		sort.Strings(capture)
		capture = slices.Compact(capture)
	}
	sort.Strings(exclusions)
	return capture, slices.Compact(exclusions), nil
}
