package clientadapter

import (
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
)

// TUNDNSCache is disposable data-plane DNS state, never device authority.
// The host must resolve this relative name inside its protected runtime root.
const TUNDNSCache = "tun-dns.db"

// WithTUNDomainDNS restores a TUN application's DNS target before transport
// routing. It cannot infer a domain from an arbitrary literal-IP connection.
// The source is an already validated access runtime, not another wire decoder.
func WithTUNDomainDNS(config string) (string, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	var route struct {
		Rules []tunDNSMatcher `json:"rules"`
	}
	if err := json.Unmarshal(document["route"], &route); err != nil {
		return "", err
	}
	domains, suffixes := map[string]bool{}, map[string]bool{}
	var visit func(tunDNSMatcher)
	visit = func(rule tunDNSMatcher) {
		for _, value := range rule.Domain {
			domains[value] = true
		}
		for _, value := range rule.DomainSuffix {
			suffixes[value] = true
		}
		for _, child := range rule.Rules {
			visit(child)
		}
	}
	for _, rule := range route.Rules {
		visit(rule)
	}
	if len(domains)+len(suffixes) == 0 {
		return config, nil
	}
	var dns map[string]json.RawMessage
	if document["dns"] == nil {
		// Missing infrastructure cannot be invented by capture. An explicit
		// proxy or literal-IP request can still use its certified permission.
		return config, nil
	}
	if json.Unmarshal(document["dns"], &dns) != nil || dns == nil {
		return "", errors.New("TUN domain services require authenticated DNS")
	}
	for _, field := range []string{"fakeip", "rules"} {
		if _, found := dns[field]; found {
			return "", errors.New("TUN DNS source already owns domain capture")
		}
	}
	var servers []json.RawMessage
	if json.Unmarshal(dns["servers"], &servers) != nil || len(servers) == 0 {
		return "", errors.New("TUN domain services require authenticated DNS")
	}
	servers = append(servers, json.RawMessage(`{"tag":"loom-tun-domain","address":"fakeip"}`))
	dns["servers"], _ = json.Marshal(servers)
	dns["independent_cache"] = json.RawMessage(`true`)
	delete(dns, "reverse_mapping")
	matcher := map[string]any{"inbound": []string{"tun-in"}, "query_type": []string{"A", "AAAA"}, "server": "loom-tun-domain"}
	if len(domains) > 0 {
		matcher["domain"] = sortedDNSNames(domains)
	}
	if len(suffixes) > 0 {
		matcher["domain_suffix"] = sortedDNSNames(suffixes)
	}
	dns["rules"], _ = json.Marshal([]any{matcher})
	dns["fakeip"] = json.RawMessage(`{"enabled":true,"inet4_range":"198.18.0.0/15","inet6_range":"2001:db8:8000::/49"}`)
	document["dns"], _ = json.Marshal(dns)
	var experimental map[string]json.RawMessage
	if json.Unmarshal(document["experimental"], &experimental) != nil || experimental == nil || experimental["cache_file"] != nil {
		return "", errors.New("TUN DNS requires a unique local runtime cache")
	}
	experimental["cache_file"], _ = json.Marshal(map[string]any{"enabled": true, "path": TUNDNSCache, "store_fakeip": true})
	document["experimental"], _ = json.Marshal(experimental)
	// A concrete service inside the synthetic pool is ambiguous. A default
	// prefix does not claim that pool as a real network; matching still occurs
	// on the restored FQDN, just as it does for an explicit proxy request.
	var check func(tunDNSMatcher) error
	check = func(rule tunDNSMatcher) error {
		for _, value := range rule.IPCIDR {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return err
			}
			for _, pool := range []string{"198.18.0.0/15", "2001:db8:8000::/49"} {
				reserved := netip.MustParsePrefix(pool)
				if reserved.Contains(prefix.Addr()) && prefix.Bits() >= reserved.Bits() {
					return errors.New("Service target overlaps the TUN DNS address pool")
				}
			}
		}
		for _, child := range rule.Rules {
			if err := check(child); err != nil {
				return err
			}
		}
		return nil
	}
	for _, rule := range route.Rules {
		if err := check(rule); err != nil {
			return "", err
		}
	}
	body, err := json.Marshal(document)
	return string(body), err
}

type tunDNSMatcher struct {
	Domain       []string        `json:"domain"`
	DomainSuffix []string        `json:"domain_suffix"`
	IPCIDR       []string        `json:"ip_cidr"`
	Rules        []tunDNSMatcher `json:"rules"`
}

func sortedDNSNames(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
