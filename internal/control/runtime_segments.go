package control

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
)

const LinkProbeInbound = "loom-link-probe"
const ExecutionDNSIPv6Range = "2001:db8:8000::/49"

func ResourceInboundTag(resourceID string) string { return "resource:" + resourceID }
func WireGuardBaseTag(resourceID string) string   { return "wg-base." + resourceID }

// This builder is a disposable pure projection. It owns no accepted state,
// phase, cache or independent permission; the one signed View is its input.
type segmentedRuntime struct {
	view        DeviceView
	credentials map[string]string
	resources   map[string]TransportResource
	outbounds   []any
	rules       []any
	dnsRules    []any
	sources     map[string]map[string]bool
	tags        map[string]bool
}

func (r *segmentedRuntime) addOutbound(value map[string]any) error {
	tag, _ := value["tag"].(string)
	if tag == "" || r.tags[tag] {
		return errors.New("runtime outbound identity is duplicated")
	}
	r.tags[tag] = true
	r.outbounds = append(r.outbounds, value)
	return nil
}

func (r *segmentedRuntime) useSender(resourceID string) error {
	if r.sources[resourceID] != nil {
		return nil
	}
	resource := r.resources[resourceID]
	if resource.Kind != "wireguard" || resource.OwnerNodeID == r.view.DeviceID {
		return errors.New("WG sender has no distinct receiving resource")
	}
	if _, err := wireGuardAccessPrivate(r.credentials[WireGuardSenderTag(resourceID)]); err != nil {
		return err
	}
	r.sources[resourceID] = map[string]bool{}
	return nil
}

func (r *segmentedRuntime) addWG(permission InboundCredential, tag string) error {
	if permission.SenderID != r.view.DeviceID {
		return errors.New("runtime cannot send as another device")
	}
	if err := r.useSender(permission.ResourceID); err != nil {
		return err
	}
	private, _ := wireGuardAccessPrivate(r.credentials[WireGuardSenderTag(permission.ResourceID)])
	address, err := WireGuardPacketSource(r.view.NetworkID, permission, base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()))
	if err != nil {
		return err
	}
	r.sources[permission.ResourceID][address.String()+"/128"] = true
	if err := r.addOutbound(map[string]any{"type": "direct", "tag": tag, "detour": WireGuardSenderTag(permission.ResourceID), "inet6_bind_address": address.String()}); err != nil {
		return err
	}
	r.dnsRules = append(r.dnsRules, map[string]any{"outbound": []string{tag}, "server": "wg-dns." + permission.ResourceID})
	return nil
}

func (r *segmentedRuntime) incoming() ([]any, error) {
	dnsRules := []any{}
	for _, resource := range r.view.Resources {
		if resource.OwnerNodeID != r.view.DeviceID {
			continue
		}
		tag := ResourceInboundTag(resource.ID)
		if resource.Kind == "wireguard" {
			dns, err := WireGuardAccessAddress(resource, "")
			if err != nil {
				return nil, err
			}
			allowed := []string{}
			for _, peer := range r.view.WireGuardPeers {
				if peer.ResourceID != resource.ID {
					continue
				}
				base, err := WireGuardAccessAddress(resource, peer.PublicKey)
				if err != nil {
					return nil, err
				}
				allowed = append(allowed, base.String()+"/128")
				for _, permission := range r.view.InboundCredentials {
					if permission.ResourceID != resource.ID || permission.SenderID != peer.DeviceID {
						continue
					}
					source, err := WireGuardPacketSource(r.view.NetworkID, permission, peer.PublicKey)
					if err != nil {
						return nil, err
					}
					allowed = append(allowed, source.String()+"/128")
				}
			}
			sort.Strings(allowed)
			if len(allowed) > 0 {
				r.rules = append(r.rules, map[string]any{"inbound": []string{tag}, "source_ip_cidr": allowed, "ip_cidr": []string{dns.String() + "/128"}, "port": []int{53}, "action": "hijack-dns"})
			}
			dnsRules = append(dnsRules, map[string]any{"inbound": []string{tag}, "query_type": []string{"AAAA"}, "server": "wg-execution-dns"}, map[string]any{"inbound": []string{tag}, "server": "loom-runtime-deny-dns"})
		}
		for _, permission := range r.view.InboundCredentials {
			if permission.ResourceID != resource.ID {
				continue
			}
			path, index, err := permissionPath(r.view, permission)
			if err != nil {
				return nil, err
			}
			scope := map[string]any{"inbound": []string{tag}}
			if resource.Kind == "hysteria2" {
				user, err := InboundCredentialUser(permission)
				if err != nil {
					return nil, err
				}
				scope["auth_user"] = []string{user}
			} else {
				public := ""
				for _, peer := range r.view.WireGuardPeers {
					if peer.ResourceID == resource.ID && peer.DeviceID == permission.SenderID {
						public = peer.PublicKey
					}
				}
				source, err := WireGuardPacketSource(r.view.NetworkID, permission, public)
				if err != nil {
					return nil, err
				}
				scope["source_ip_cidr"] = []string{source.String() + "/128"}
			}
			outbound := "resource-egress"
			if index+1 < len(path.hops) {
				next := permission
				next.ResourceID, next.ReceiverNodeID, next.SenderID, next.Credential = path.hops[index+1].ID, path.hops[index+1].OwnerNodeID, r.view.DeviceID, ""
				user, err := InboundCredentialUser(next)
				if err != nil {
					return nil, err
				}
				outbound = "segment:" + user
				if err := r.addWG(next, outbound); err != nil {
					return nil, err
				}
			} else if !r.tags[outbound] {
				if err := r.addOutbound(map[string]any{"type": "direct", "tag": outbound}); err != nil {
					return nil, err
				}
			}
			for _, set := range []struct {
				matchers []ServiceMatcher
				outbound string
			}{{permission.ExcludedTargets, "reject"}, {permission.AllowedTargets, outbound}} {
				for _, matcher := range set.matchers {
					r.rules = append(r.rules, map[string]any{"type": "logical", "mode": "and", "rules": []any{scope, matcherRule(matcher)}, "outbound": set.outbound})
				}
			}
		}
		r.rules = append(r.rules, map[string]any{"inbound": []string{tag}, "outbound": "reject"})
	}
	for _, link := range r.view.Links {
		if link.FromNodeID != r.view.DeviceID {
			continue
		}
		if err := r.useSender(link.ResourceID); err != nil {
			return nil, err
		}
	}
	return dnsRules, nil
}

func (r *segmentedRuntime) access(services map[string]Service, policies map[string]NetworkPolicy) error {
	ids := []string{}
	for id := range policies {
		if _, found := services[id]; found {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for left := range ids {
		for right := left + 1; right < len(ids); right++ {
			r.rules = append(r.rules, map[string]any{"type": "logical", "mode": "and", "rules": []any{serviceRule(services[ids[left]]), serviceRule(services[ids[right]])}, "outbound": "reject"})
		}
	}
	byService := map[string][]string{}
	for index, candidate := range r.view.Routes {
		service, exists := services[candidate.ServiceID]
		policy, assigned := policies[candidate.ServiceID]
		if candidate.Validate() != nil || !exists || !assigned || policy.Action != "allow" || index > 0 && r.view.Routes[index-1].ID >= candidate.ID {
			return errors.New("certified candidates are invalid, duplicated or unassigned")
		}
		if candidate.FirstResourceID == "" {
			allowed := candidate.FinalExit == "direct" && policy.AllowDirect || candidate.FinalExit == r.view.DeviceID && containsString(r.view.Responsibilities, "internet_egress") && containsString(policy.LocalEgressDevices, r.view.DeviceID) && policy.ExitScope.Allows(r.view.DeviceID)
			want, err := localCandidate(service, policy, candidate.FinalExit, r.view.DNSRecords...)
			if !allowed || err != nil || !sameContractValue(want, candidate) {
				return errors.New("local candidate has no current permission")
			}
			if err := r.addOutbound(map[string]any{"type": "direct", "tag": candidate.ID}); err != nil {
				return err
			}
		} else {
			path, err := candidateTransportPath(r.view, r.view.DeviceID, service, policy, candidate)
			if err != nil {
				return err
			}
			if path.local && !containsString(r.view.Responsibilities, "forward") {
				return errors.New("local Link origin has no forwarding responsibility")
			}
			first := path.hops[0]
			if first.Kind == "hysteria2" {
				outbound, err := hy2Outbound(candidate, first, r.credentials[candidate.ID])
				if err != nil {
					return err
				}
				if err := r.addOutbound(outbound); err != nil {
					return err
				}
			} else {
				permission := pathPermission(path, 0, r.view.DeviceID, policy, service, []ServiceMatcher{})
				if err := r.addWG(permission, candidate.ID); err != nil {
					return err
				}
			}
		}
		byService[service.ID] = append(byService[service.ID], candidate.ID)
	}
	for _, id := range ids {
		members := byService[id]
		if len(members) == 0 {
			continue
		}
		scope := "service:" + id
		if err := r.addOutbound(map[string]any{"type": "selector", "tag": scope, "outbounds": members, "default": members[0]}); err != nil {
			return err
		}
		rule := serviceRule(services[id])
		rule["outbound"] = scope
		r.rules = append(r.rules, rule)
	}
	return nil
}

func (r *segmentedRuntime) finish(incomingDNS []any) (map[string]any, error) {
	document := map[string]any{"outbounds": r.outbounds, "route": map[string]any{"rules": r.rules, "final": "reject"}}
	if len(r.sources) == 0 && len(incomingDNS) == 0 {
		return document, nil
	}
	servers := []any{map[string]any{"tag": "loom-runtime-deny-dns", "address": "rcode://refused"}}
	final := "loom-runtime-deny-dns"
	if len(r.view.DNSServers) > 0 {
		if err := r.addOutbound(map[string]any{"type": "direct", "tag": "loom-underlay-dns"}); err != nil {
			return nil, err
		}
		for i, address := range r.view.DNSServers {
			servers = append(servers, map[string]any{"tag": fmt.Sprintf("loom-resolver-%d", i), "address": "udp://" + net.JoinHostPort(address, "53"), "detour": "loom-underlay-dns"})
		}
		final = "loom-resolver-0"
	}
	physical := []string{}
	for _, raw := range r.outbounds {
		outbound := raw.(map[string]any)
		if outbound["type"] == "direct" && outbound["detour"] == nil {
			physical = append(physical, outbound["tag"].(string))
		}
	}
	if len(physical) > 0 {
		r.dnsRules = append(r.dnsRules, map[string]any{"outbound": physical, "server": final})
	}
	ids := []string{}
	for id := range r.sources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	endpoints := []any{}
	probeRules := []any{}
	for _, id := range ids {
		addresses := []string{}
		for source := range r.sources[id] {
			addresses = append(addresses, source)
		}
		resource := r.resources[id]
		endpoint, err := wireGuardSenderEndpoint(r.view.NetworkID, resource, r.credentials[WireGuardSenderTag(id)], addresses)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
		private, _ := wireGuardAccessPrivate(r.credentials[WireGuardSenderTag(id)])
		base, err := WireGuardAccessAddress(resource, base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()))
		if err != nil {
			return nil, err
		}
		if err := r.addOutbound(map[string]any{"type": "direct", "tag": WireGuardBaseTag(id), "detour": WireGuardSenderTag(id), "inet6_bind_address": base.String()}); err != nil {
			return nil, err
		}
		dns, err := WireGuardAccessAddress(resource, "")
		if err != nil {
			return nil, err
		}
		probeRules = append(probeRules, map[string]any{"inbound": []string{LinkProbeInbound}, "auth_user": []string{id}, "ip_cidr": []string{dns.String() + "/128"}, "port": []int{53}, "outbound": WireGuardBaseTag(id)})
		servers = append(servers, map[string]any{"tag": "wg-dns." + id, "address": "udp://" + net.JoinHostPort(dns.String(), "53"), "detour": WireGuardBaseTag(id), "strategy": "ipv6_only"})
	}
	probeRules = append(probeRules, map[string]any{"inbound": []string{LinkProbeInbound}, "outbound": "reject"})
	document["route"].(map[string]any)["rules"] = append(probeRules, r.rules...)
	dns := map[string]any{"servers": servers, "rules": append(r.dnsRules, incomingDNS...), "final": final, "independent_cache": true}
	if len(incomingDNS) > 0 {
		servers = append(servers, map[string]any{"tag": "wg-execution-dns", "address": "fakeip"})
		dns["servers"] = servers
		dns["fakeip"] = map[string]any{"enabled": true, "inet4_range": "198.18.0.0/15", "inet6_range": ExecutionDNSIPv6Range}
		pool := netip.MustParsePrefix(ExecutionDNSIPv6Range)
		for _, service := range r.view.Services {
			for _, matcher := range service.Matchers {
				if matcher.Kind == "ip_prefix" {
					prefix, _ := netip.ParsePrefix(matcher.Value)
					if pool.Contains(prefix.Addr()) && prefix.Bits() >= pool.Bits() {
						return nil, errors.New("Service target overlaps execution DNS addresses")
					}
				}
			}
		}
	}
	document["outbounds"], document["endpoints"], document["dns"] = r.outbounds, endpoints, dns
	return document, nil
}

func renderSegmentedRuntime(view DeviceView, credentials map[string]string) ([]RouteCandidate, *RuntimeProfile, error) {
	services, policies, err := servicePermissionValues(view)
	if err != nil {
		return nil, nil, err
	}
	if err := validateViewResources(view); err != nil {
		return nil, nil, err
	}
	access := containsString(view.Responsibilities, "access")
	if !access && (len(view.PolicyIDs) != 0 || len(view.Routes) != 0) {
		return nil, nil, errors.New("non-access node has access permissions")
	}
	if !access && len(view.Resources) == 0 {
		return []RouteCandidate{}, nil, nil
	}
	r := &segmentedRuntime{view: view, credentials: credentials, resources: map[string]TransportResource{}, outbounds: []any{}, rules: []any{}, dnsRules: []any{}, sources: map[string]map[string]bool{}, tags: map[string]bool{}}
	for _, resource := range view.Resources {
		r.resources[resource.ID] = resource
	}
	if err := r.addOutbound(map[string]any{"type": "block", "tag": "reject"}); err != nil {
		return nil, nil, err
	}
	incomingDNS, err := r.incoming()
	if err != nil {
		return nil, nil, err
	}
	if access {
		if err := r.access(services, policies); err != nil {
			return nil, nil, err
		}
	}
	document, err := r.finish(incomingDNS)
	if err != nil {
		return nil, nil, err
	}
	body, err := CanonicalEncode(document)
	if err != nil {
		return nil, nil, err
	}
	return append([]RouteCandidate{}, view.Routes...), &RuntimeProfile{Kind: "sing_box", Config: string(body)}, nil
}
