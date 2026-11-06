package control

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"loom/internal/netx"
	"loom/protocol"
)

const LinkProbeInbound = "loom-link-probe"
const AccessSelectorScope = "access"
const InternetEgressOutboundTag = "loom-internet-egress"

func serviceEgressOutboundTag(service Service) string {
	if service.Kind == "internet" {
		return InternetEgressOutboundTag
	}
	return "egress:" + service.ID
}

// ManagedResolverRules uses existing DNS Lookup response rules to try the
// configured encrypted alternatives. The address limits accept both families;
// they are DNS response conditions, never business routes or permissions.
func ManagedResolverRules(servers, outbounds []string) []map[string]any {
	rules := []map[string]any{}
	for i := range servers {
		rule := map[string]any{"outbound": outbounds, "server": fmt.Sprintf("loom-resolver-%d", i)}
		if i+1 < len(servers) {
			rule["ip_cidr"] = []string{"0.0.0.0/0", "::/0"}
		}
		rules = append(rules, rule)
	}
	return rules
}

func ResourceInboundTag(resourceID string) string { return "resource:" + resourceID }

// This builder is a disposable pure projection. It owns no accepted state,
// phase, cache or independent permission; the one signed View is its input.
type segmentedRuntime struct {
	view        DeviceExecution
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

func (r *segmentedRuntime) addInternetEgress() error {
	if r.tags[InternetEgressOutboundTag] {
		return nil
	}
	return r.addOutbound(map[string]any{"type": "direct", "tag": InternetEgressOutboundTag, "public_internet": true})
}

func (r *segmentedRuntime) addServiceEgress(service Service) error {
	if service.Kind == "internet" {
		return r.addInternetEgress()
	}
	tag := serviceEgressOutboundTag(service)
	if r.tags[tag] {
		return nil
	}
	value := map[string]any{"type": "direct", "tag": tag}
	if mapping := service.LocalNetwork; mapping != nil {
		if !mapping.Enabled || mapping.GatewayNodeID != r.view.DeviceID {
			return errors.New("local network translation requires its enabled fixed gateway")
		}
		value["prefix_mapping"] = map[string]any{"virtual_prefix": mapping.VirtualPrefix, "local_prefix": mapping.LocalPrefix}
	}
	return r.addOutbound(value)
}

func (r *segmentedRuntime) useSender(resourceID string) error {
	if r.sources[resourceID] != nil {
		return nil
	}
	resource := r.resources[resourceID]
	if resource.Kind != "wireguard" || resource.OwnerNodeID == r.view.DeviceID {
		return errors.New("WG sender has no distinct receiving resource")
	}
	if _, _, err := sharedWireGuardIdentity(r.view.DeviceView, r.credentials); err != nil {
		return err
	}
	r.sources[resourceID] = map[string]bool{}
	return nil
}

func ForwardSelectorTag(policyID string) string { return "forward:" + policyID }
func ForwardSegmentTag(resourceID string) (string, error) {
	if ValidateID(resourceID) != nil {
		return "", errors.New("invalid transport resource")
	}
	id, err := digestContractValue("loom-transport-outbound-v3\x00", map[string]any{"resource_id": resourceID})
	return "transport:" + id, err
}
func (r *segmentedRuntime) ensureTransport(resourceID string) (string, error) {
	resource, ok := r.resources[resourceID]
	if !ok || resource.OwnerNodeID == r.view.DeviceID {
		return "", errors.New("resource has no remote transport")
	}
	tag, err := ForwardSegmentTag(resourceID)
	if err != nil {
		return "", err
	}
	if r.tags[tag] {
		return tag, nil
	}
	authentication, err := senderAuthenticationDigest(r.view.DeviceView, resource, r.credentials[resource.ID])
	if err != nil {
		return "", err
	}
	if resource.Kind == "hysteria2" {
		credential := r.credentials[resource.ID]
		if credential == "" {
			return "", errors.New("resource has no authenticated sender credential")
		}
		value, err := hy2Outbound(RouteCandidate{ID: tag}, resource, credential)
		if err != nil {
			return "", err
		}
		value["execution"] = map[string]any{"policy_id": "", "authentication_digest": authentication}
		return tag, r.addOutbound(value)
	}
	if resource.Kind != "wireguard" {
		return "", errors.New("unsupported transport")
	}
	if err = r.useSender(resourceID); err != nil {
		return "", err
	}
	endpoint, public, err := sharedWireGuardIdentity(r.view.DeviceView, r.credentials)
	if err != nil {
		return "", err
	}
	address, err := WireGuardAccessAddress(resource, public)
	if err != nil {
		return "", err
	}
	r.sources[resourceID][address.String()+"/128"] = true
	value := map[string]any{"type": "direct", "tag": tag, "detour": endpoint, "inet6_bind_address": address.String(), "execution": map[string]any{"policy_id": "", "authentication_digest": authentication}}
	return tag, r.addOutbound(value)
}
func (r *segmentedRuntime) forwarding() error {
	for _, policy := range r.view.Policies {
		if policy.Action != "allow" {
			continue
		}
		for _, exit := range policyExitNodes(r.view, policy.ID) {
			if exit == r.view.DeviceID {
				for _, service := range r.view.Services {
					if service.ID == policy.ServiceID {
						if err := r.addServiceEgress(service); err != nil {
							return err
						}
					}
				}
			}
		}
		if !containsString(r.view.Responsibilities, "forward") {
			continue
		}
		hop, err := HopPolicyProjection(r.view, policy)
		if err != nil {
			return err
		}
		hop.Origins = []string{}
		// This selector orders subsequent hops after receiver admission. The
		// complete source and receiver projections retain the actual entry
		// permission; this required but unused traversal field grants nothing.
		hop.EntryScope = protocol.PolicyScope{Mode: "any", NodeIDs: []string{}}
		members := []string{"reject"}
		nodes := map[string]string{}
		bindings := map[string]string{}
		for _, link := range ForwardingLinks(r.view, policy) {
			tag, err := r.ensureTransport(link.ResourceID)
			if err != nil {
				return err
			}

			members = append(members, tag)
			nodes[tag] = link.ToNodeID
			bindings[tag] = policy.ID
		}
		sort.Strings(members[1:])
		choices := map[string][]string{}
		for _, exit := range policyExitNodes(r.view, policy.ID) {
			distances := relayDistances(r.view.Links, policy, exit)
			tags := []string{}
			for tag, node := range nodes {
				if _, exists := distances[node]; exists && (node == exit || policy.RelayScope.Allows(node)) {
					tags = append(tags, tag)
				}
			}
			sort.Slice(tags, func(i, j int) bool {
				a, b := distances[nodes[tags[i]]], distances[nodes[tags[j]]]
				return a < b || a == b && tags[i] < tags[j]
			})
			choices[exit] = tags
		}
		if err = r.addOutbound(map[string]any{"type": "selector", "tag": ForwardSelectorTag(policy.ID), "outbounds": members, "default": "reject", "candidate_policies": bindings, "hop": map[string]any{"policy": hop, "node_id": r.view.DeviceID, "nodes": nodes, "exit_choices": choices}}); err != nil {
			return err
		}
	}
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
			tag = WireGuardEndpointTag
		}

		// Business execution is admitted by the native receiver, not target-only
		// ACL rows for expanded complete paths. Raw incoming business is rejected.
		r.rules = append(r.rules, map[string]any{"inbound": []string{tag}, "outbound": "reject"})
	}
	for _, link := range r.view.Links {
		if link.FromNodeID == r.view.DeviceID && r.resources[link.ResourceID].Kind == "wireguard" {
			if _, err := r.ensureTransport(link.ResourceID); err != nil {
				return nil, err
			}
		}
	}
	return dnsRules, nil
}
func (r *segmentedRuntime) access(services map[string]Service, policies map[string]NetworkPolicy) error {
	entries := map[string]any{}
	nodes := viewNodes(r.view.DeviceView)
	self := nodes[r.view.DeviceID]
	for _, resource := range r.view.Resources {
		if resource.OwnerNodeID == r.view.DeviceID || !senderMayAuthenticate(r.view, self, resource) {
			continue
		}
		tag, err := r.ensureTransport(resource.ID)
		if err != nil {
			return err
		}
		node := nodes[resource.OwnerNodeID]
		authentication, err := senderAuthenticationDigest(r.view.DeviceView, resource, r.credentials[resource.ID])
		if err != nil {
			return err
		}
		entries[resource.ID] = map[string]any{"node_id": node.ID, "outbound": tag, "authentication_digest": authentication, "access_enabled": resource.Kind == "wireguard" && resource.AccessEnabled || resource.Kind == "hysteria2" && !resource.LinkOnly, "forward": containsString(node.Responsibilities, "forward"), "internet_egress": containsString(node.Responsibilities, "internet_egress")}
	}
	groups := map[string][]NetworkPolicy{AccessSelectorScope: {}}
	for _, policy := range policies {
		if policy.Action != "allow" {
			continue
		}
		service := services[policy.ServiceID]
		scope := AccessSelectorScope
		if service.Kind == "local_network" {
			scope = service.Scope()
		}
		groups[scope] = append(groups[scope], policy)
	}
	scopes := []string{}
	for scope := range groups {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	for _, scope := range scopes {
		values := []any{}
		egress := map[string]string{}
		forward := map[string]string{}
		members := map[string]bool{"reject": true}
		graphNodes := []string{}
		graphEdges := []protocol.DirectedHop{}
		serviceID, kind := "", "internet"
		sort.Slice(groups[scope], func(i, j int) bool { return groups[scope][i].ID < groups[scope][j].ID })
		for _, policy := range groups[scope] {
			service := services[policy.ServiceID]
			if service.Kind == "local_network" {
				serviceID, kind = service.ID, service.Kind
			}
			value, err := executionPolicyProjection(r.view, policy)
			if err != nil {
				return err
			}
			hop := value["policy"].(protocol.HopPolicy)
			graphNodes, graphEdges = hop.Nodes, hop.Edges
			// Source permissions carry one graph, not one copy per Policy.
			raw := map[string]any{"policy_id": hop.PolicyID, "service_id": hop.ServiceID, "kind": hop.Kind, "origins": []string{r.view.DeviceID}, "exits": hop.Exits, "entry_scope": hop.EntryScope, "relay_scope": hop.RelayScope, "max_hops": hop.MaxHops}
			value["policy"] = raw
			values = append(values, value)
			if value["allow_direct"] == true || value["local_egress"] == true {
				tag := serviceEgressOutboundTag(service)
				if err = r.addServiceEgress(service); err != nil {
					return err
				}
				egress[service.ID] = tag
				members[tag] = true
			}
			tag := ForwardSelectorTag(policy.ID)
			if r.tags[tag] {
				forward[policy.ID] = tag
				members[tag] = true
			}
		}
		for _, raw := range entries {
			entry := raw.(map[string]any)
			members[entry["outbound"].(string)] = true
		}
		tags := []string{}
		for tag := range members {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		access := map[string]any{"node_id": r.view.DeviceID, "forward": containsString(r.view.Responsibilities, "forward"), "kind": kind, "service_id": serviceID, "policies": values, "nodes": graphNodes, "edges": graphEdges, "entries": entries, "egress_outbounds": egress, "forward_outbounds": forward}
		if err := r.addOutbound(map[string]any{"type": "selector", "tag": scope, "outbounds": tags, "default": "reject", "access": access}); err != nil {
			return err
		}
	}
	// LAN is independently authorized and routed before the Internet default.
	ids := []string{}
	for id := range services {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		service := services[id]
		if service.Kind != "local_network" || groups[service.Scope()] == nil {
			continue
		}
		rule := captureServiceRule(service, r.view.DNSRecords...)
		rule["outbound"] = service.Scope()
		r.rules = append(r.rules, rule)
	}
	r.rules = append(r.rules, map[string]any{"public_internet": true, "outbound": AccessSelectorScope})
	return nil
}
func (r *segmentedRuntime) finish(incomingDNS []any) (map[string]any, error) {
	document := map[string]any{"outbounds": r.outbounds, "route": map[string]any{"rules": r.rules, "final": "reject"}}
	owned, receiving, ownedErr := ownedWireGuard(r.view.Resources, r.view.DeviceID)
	if ownedErr != nil {
		return nil, ownedErr
	}
	// Business DNS belongs to the node's actual sockets, including Hy2-only
	// receivers. It cannot depend on the presence of a measurement SOCKS rule.
	servers := []any{map[string]any{"tag": "loom-runtime-deny-dns", "address": "rcode://refused"}}
	final := "loom-runtime-deny-dns"
	if len(r.view.DNSServers) > 0 {
		if err := r.addOutbound(map[string]any{"type": "direct", "tag": "loom-underlay-dns"}); err != nil {
			return nil, err
		}
		for i, address := range r.view.DNSServers {
			resolver, err := netx.ParseDNSResolver(address)
			if err != nil {
				return nil, err
			}
			servers = append(servers, map[string]any{"tag": fmt.Sprintf("loom-resolver-%d", i), "address": resolver.RuntimeAddress(), "detour": "loom-underlay-dns"})
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
		if len(r.view.DNSServers) > 1 && strings.HasPrefix(r.view.DNSServers[0], "https://") {
			for _, rule := range ManagedResolverRules(r.view.DNSServers, physical) {
				r.dnsRules = append(r.dnsRules, rule)
			}
		} else {
			r.dnsRules = append(r.dnsRules, map[string]any{"outbound": physical, "server": final})
		}
	}
	endpoints := []any{}
	if len(r.sources) > 0 || receiving {
		shared, err := sharedWireGuardEndpoint(r.view, r.credentials, r.sources)
		if err != nil {
			return nil, err
		}
		if receiving {
			execution, err := WireGuardAccessAddress(owned, "")
			if err != nil {
				return nil, err
			}
			projection, err := ReceiverExecutionOptions(r.view.DeviceView, owned.ID)
			if err != nil {
				return nil, err
			}
			shared["execution_address"], shared["execution"] = execution.String(), projection
		}
		endpoints = append(endpoints, shared)
	}
	dns := map[string]any{"servers": servers, "rules": append(r.dnsRules, incomingDNS...), "final": final, "independent_cache": true}
	if receiving {
		pool, err := WireGuardTargetPrefix(r.view.NetworkID, owned)
		if err != nil {
			return nil, err
		}
		dns["fakeip"] = map[string]any{"enabled": true, "inet6_range": pool.String()}
		for _, service := range r.view.Services {
			for _, matcher := range service.TargetMatchers() {
				if matcher.Kind == "ip_prefix" {
					prefix, _ := netip.ParsePrefix(matcher.Value)
					if pool.Contains(prefix.Addr()) && prefix.Bits() >= pool.Bits() {
						return nil, errors.New("Service target overlaps execution registration addresses")
					}
				}
			}
		}
	}
	document["outbounds"], document["endpoints"], document["dns"] = r.outbounds, endpoints, dns
	return document, nil
}

func renderSegmentedRuntime(view DeviceExecution, credentials map[string]string) ([]RouteCandidate, *RuntimeProfile, error) {
	services, policies, err := servicePermissionValues(view.DeviceView)
	if err != nil {
		return nil, nil, err
	}
	if err := validateStableView(view.DeviceView); err != nil {
		return nil, nil, err
	}
	access := containsString(view.Responsibilities, "access")
	if !access && (len(view.SelectedPolicyIDs) != 0 || len(view.Routes) != 0) {
		return nil, nil, errors.New("non-access node has access permissions")
	}
	probeDuty := hasEgressProbeDuty(view.DeviceView)
	if !access && len(view.Resources) == 0 && !probeDuty {
		return []RouteCandidate{}, nil, nil
	}
	r := &segmentedRuntime{view: view, credentials: credentials, resources: map[string]TransportResource{}, outbounds: []any{}, rules: []any{}, dnsRules: []any{}, sources: map[string]map[string]bool{}, tags: map[string]bool{}}
	for _, resource := range view.Resources {
		r.resources[resource.ID] = resource
	}
	if err := r.addOutbound(map[string]any{"type": "block", "tag": "reject"}); err != nil {
		return nil, nil, err
	}
	if probeDuty {
		if err := r.addInternetEgress(); err != nil {
			return nil, nil, err
		}
	}
	if err := r.forwarding(); err != nil {
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

func mustTransportTag(resource string) string { tag, _ := ForwardSegmentTag(resource); return tag }
