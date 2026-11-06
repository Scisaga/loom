package control

import (
	"errors"
	"net/netip"
	"sort"

	"loom/protocol"
)

func WGResourceAddress(resource TransportResource) (netip.Addr, error) {
	if resource.Validate() != nil || resource.Kind != "wireguard" || len(*resource.Authentication.LocalAddresses) != 1 {
		return netip.Addr{}, errors.New("WireGuard resource requires one exact interface address")
	}
	prefix, err := netip.ParsePrefix((*resource.Authentication.LocalAddresses)[0])
	if err != nil || prefix.Bits() != prefix.Addr().BitLen() || !prefix.Addr().IsGlobalUnicast() {
		return netip.Addr{}, errors.New("WireGuard address must be an exact unicast address")
	}
	return prefix.Addr(), nil
}
func linkResources(link NetworkLink, resources map[string]TransportResource) (TransportResource, TransportResource, TransportResource, error) {
	from, to := resources[link.FromResourceID], resources[link.ResourceID]
	if link.Validate() != nil || to.ID == "" || to.OwnerNodeID != link.ToNodeID || to.Validate() != nil || link.ProbeTarget.ResourceID != to.ID || link.FromResourceID != "" && (from.ID == "" || from.OwnerNodeID != link.FromNodeID) {
		return from, to, to, errors.New("directed link lacks its native receiving resource")
	}
	if to.Kind == "wireguard" {
		address, err := WireGuardAccessAddress(to, "")
		if err != nil || link.ProbeTarget.Action != "wireguard_echo" || link.ProbeTarget.Host != address.String() || link.ProbeTarget.Port != 53 {
			return from, to, to, errors.New("WG link lacks its exact execution entry")
		}
	} else if to.Kind != "hysteria2" || link.ProbeTarget.Action != "hysteria2_echo" || link.ProbeTarget.Host != to.DialHost || link.ProbeTarget.Port != to.DialPort {
		return from, to, to, errors.New("Hy2 link lacks its exact native receiver")
	}
	return from, to, to, nil
}
func candidateForEntry(service Service, policy NetworkPolicy, entry string, resource TransportResource, exit string, records ...DNSRecord) (RouteCandidate, error) {
	identity := map[string]any{"service_id": service.ID, "policy_id": policy.ID, "entry_node_id": entry, "first_resource_id": resource.ID, "final_exit": exit}
	id, err := protocol.CandidateID(service.ID, policy.ID, protocol.RouteChoice{EntryNodeID: entry, FirstResourceID: resource.ID, FinalExit: exit})
	if err != nil {
		return RouteCandidate{}, err
	}
	values := []TransportResource{}
	if resource.ID != "" {
		values = append(values, resource)
	}
	specification := map[string]any{"identity": identity, "service_boundary": service.TargetMatchers(records...), "policy": policy, "resources": values}
	if service.LocalNetwork != nil {
		specification["local_network"] = *service.LocalNetwork
	}
	spec, err := digestContractValue("loom-candidate-spec-v3\x00", specification)
	return RouteCandidate{ID: id, SpecDigest: spec, Scope: service.Scope(), ServiceID: service.ID, PolicyID: policy.ID, EntryNodeID: entry, FirstResourceID: resource.ID, FinalExit: exit}, err
}
func policyExitNodes(view DeviceExecution, id string) []string {
	for _, value := range view.PolicyExits {
		if value.PolicyID == id {
			return value.NodeIDs
		}
	}
	return nil
}
func hasAccessGrant(view DeviceExecution, device, policy string) bool {
	index := sort.Search(len(view.AccessGrants), func(i int) bool {
		return view.AccessGrants[i].DeviceID > device || view.AccessGrants[i].DeviceID == device && view.AccessGrants[i].PolicyID >= policy
	})
	return index < len(view.AccessGrants) && view.AccessGrants[index] == (AccessGrant{DeviceID: device, PolicyID: policy})
}

// HopPolicyProjection is a pure receiving/graph value from the one signed View.
// It creates no node type, route registry or independently editable relation.
func HopPolicyProjection(view DeviceExecution, policy NetworkPolicy) (protocol.HopPolicy, error) {
	var service Service
	for _, value := range view.Services {
		if value.ID == policy.ServiceID {
			service = value
		}
	}
	if policy.Action != "allow" || policy.ValidateForService(service) != nil {
		return protocol.HopPolicy{}, errors.New("Policy has no executable Service")
	}
	nodes := map[string]bool{}
	for id, node := range viewNodes(view.DeviceView) {
		if containsString(node.Responsibilities, "forward") || containsString(node.Responsibilities, "internet_egress") {
			nodes[id] = true
		}
	}
	value := protocol.HopPolicy{PolicyID: policy.ID, ServiceID: policy.ServiceID, Kind: service.Kind, Origins: []string{}, Exits: append([]string{}, policyExitNodes(view, policy.ID)...), Nodes: []string{}, EntryScope: policy.EntryScope, RelayScope: policy.RelayScope, MaxHops: policy.MaxHops, Edges: []protocol.DirectedHop{}}
	for _, grant := range view.AccessGrants {
		if grant.PolicyID == policy.ID {
			value.Origins = append(value.Origins, grant.DeviceID)
		}
	}
	for node := range nodes {
		value.Nodes = append(value.Nodes, node)
	}
	sort.Strings(value.Nodes)
	sort.Strings(value.Origins)
	edges := map[protocol.DirectedHop]bool{}
	for _, link := range view.Links {
		edge := protocol.DirectedHop{From: link.FromNodeID, To: link.ToNodeID}
		if !edges[edge] {
			value.Edges = append(value.Edges, edge)
			edges[edge] = true
		}
	}
	sort.Slice(value.Edges, func(i, j int) bool {
		a, b := value.Edges[i], value.Edges[j]
		return a.From < b.From || a.From == b.From && a.To < b.To
	})
	if len(value.Nodes) == 0 {
		return value, nil
	}
	return value, value.Validate()
}

// Reverse topology is shared by every entry for an exit. It proves only that
// an allowed sequence can be generated, never reachability or measured cost.
func relayDistances(links []NetworkLink, policy NetworkPolicy, exit string) map[string]int {
	reverse := map[string][]string{}
	for _, link := range links {
		if link.ToNodeID == exit || policy.RelayScope.Allows(link.ToNodeID) {
			reverse[link.ToNodeID] = append(reverse[link.ToNodeID], link.FromNodeID)
		}
	}
	distances := map[string]int{exit: 0}
	queue := []string{exit}
	for head := 0; head < len(queue); head++ {
		node := queue[head]
		for _, from := range reverse[node] {
			if _, seen := distances[from]; !seen {
				distances[from] = distances[node] + 1
				queue = append(queue, from)
			}
		}
	}
	return distances
}
func candidateEntries(view DeviceExecution, service Service, policy NetworkPolicy) ([]RouteCandidate, error) {
	result := []RouteCandidate{}
	if !hasAccessGrant(view, view.DeviceID, policy.ID) {
		return result, nil
	}
	add := func(entry string, resource TransportResource, exit string) error {
		value, err := candidateForEntry(service, policy, entry, resource, exit, view.DNSRecords...)
		if err == nil {
			result = append(result, value)
		}
		return err
	}
	if service.Kind == "internet" && policy.permitsDirect() {
		if err := add("", TransportResource{}, "direct"); err != nil {
			return nil, err
		}
	}
	for _, exit := range policyExitNodes(view, policy.ID) {
		if exit == view.DeviceID {
			local := service.Kind == "internet" && containsString(view.Responsibilities, "internet_egress") && policy.permitsLocalEgress(view.DeviceID) || service.Kind == "local_network" && containsString(view.Responsibilities, "forward") && policy.EntryScope.Allows(view.DeviceID)
			if local {
				if err := add(view.DeviceID, TransportResource{}, exit); err != nil {
					return nil, err
				}
			}
		}
		distances := relayDistances(view.Links, policy, exit)
		allowed := func(entry string) bool {
			distance, found := distances[entry]
			return found && policy.EntryScope.Allows(entry) && (policy.MaxHops == 0 || distance+1 <= policy.MaxHops)
		}
		if exit != view.DeviceID && containsString(view.Responsibilities, "forward") && allowed(view.DeviceID) {
			if err := add(view.DeviceID, TransportResource{}, exit); err != nil {
				return nil, err
			}
		}
		for _, resource := range view.Resources {
			if resource.OwnerNodeID == view.DeviceID || !allowed(resource.OwnerNodeID) || resource.AccessHY2ResourceID != "" {
				continue
			}
			if resource.Kind == "wireguard" && !resource.AccessEnabled || resource.Kind == "hysteria2" && resource.LinkOnly || resource.Kind != "wireguard" && resource.Kind != "hysteria2" {
				continue
			}
			if resource.Kind == "wireguard" && view.WireGuardPublicKey == "" {
				continue
			}
			if err := add(resource.OwnerNodeID, resource, exit); err != nil {
				return nil, err
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

// CandidateTopologyEstimate is a display/cold-start witness. It is not an
// authorization chain, a measured fastest path or a command to downstream hops.
func CandidateTopologyEstimate(view DeviceExecution, candidate RouteCandidate) ([]string, []string, error) {
	if candidate.FinalExit == "direct" {
		return []string{}, []string{}, nil
	}
	var policy NetworkPolicy
	for _, value := range view.Policies {
		if value.ID == candidate.PolicyID {
			policy = value
		}
	}
	distances := relayDistances(view.Links, policy, candidate.FinalExit)
	if _, exists := distances[candidate.EntryNodeID]; !exists {
		return nil, nil, errors.New("candidate entry has no permitted topology to its exit")
	}
	nodes := []string{candidate.EntryNodeID}
	links := []string{}
	for nodes[len(nodes)-1] != candidate.FinalExit {
		current := nodes[len(nodes)-1]
		var selected NetworkLink
		for _, link := range view.Links {
			distance, exists := distances[link.ToNodeID]
			if link.FromNodeID == current && exists && distance+1 == distances[current] && (link.ToNodeID == candidate.FinalExit || policy.RelayScope.Allows(link.ToNodeID)) && (selected.ID == "" || link.ID < selected.ID) {
				selected = link
			}
		}
		if selected.ID == "" {
			return nil, nil, errors.New("candidate topology witness is incomplete")
		}
		nodes = append(nodes, selected.ToNodeID)
		links = append(links, selected.ID)
	}
	return nodes, links, nil
}

// policyDistances shares a reverse topology traversal across all entries or
// receiving neighbors. It never uses a measured result as an authorization.
func policyDistances(view DeviceExecution, policy NetworkPolicy, forbidden string) map[string]int {
	seeds := map[string]bool{}
	distances := map[string]int{}
	queue := []string{}
	for _, exit := range policyExitNodes(view, policy.ID) {
		if exit != forbidden {
			seeds[exit] = true
			distances[exit] = 0
			queue = append(queue, exit)
		}
	}
	reverse := map[string][]string{}
	for _, link := range view.Links {
		if link.FromNodeID != forbidden && link.ToNodeID != forbidden {
			reverse[link.ToNodeID] = append(reverse[link.ToNodeID], link.FromNodeID)
		}
	}
	for head := 0; head < len(queue); head++ {
		node := queue[head]
		if !seeds[node] && !policy.RelayScope.Allows(node) {
			continue
		}
		for _, from := range reverse[node] {
			if _, seen := distances[from]; !seen {
				distances[from] = distances[node] + 1
				queue = append(queue, from)
			}
		}
	}
	return distances
}
func policyCanReceive(view DeviceExecution, policy NetworkPolicy, node string) bool {
	distance, found := policyDistances(view, policy, "")[node]
	return found && (policy.MaxHops == 0 || distance+1 <= policy.MaxHops)
}

// Compiled only for this pure continuation projection. Retaining a transport
// facility is not entry/relay admission; source and receivers check the full
// current connection path before using it.
func segmentEligibility(view DeviceExecution) func(NetworkPolicy, NetworkLink) bool {
	cached := map[string]map[string]int{}
	return func(policy NetworkPolicy, link NetworkLink) bool {
		key := policy.ID + "\x00" + link.FromNodeID
		distances, found := cached[key]
		if !found {
			distances = policyDistances(view, policy, link.FromNodeID)
			cached[key] = distances
		}
		if link.ToNodeID == link.FromNodeID {
			return false
		}
		if !containsString(policyExitNodes(view, policy.ID), link.ToNodeID) && !policy.RelayScope.Allows(link.ToNodeID) {
			return false
		}
		distance, found := distances[link.ToNodeID]
		return found && (policy.MaxHops == 0 || distance+2 <= policy.MaxHops)
	}
}

// ForwardingLinks is the shared pure projection of this node's next hops.
// Rendering and performance decisions consume it without decoding runtime JSON.
func ForwardingLinks(view DeviceExecution, policy NetworkPolicy) []NetworkLink {
	result := []NetworkLink{}
	if policy.Action != "allow" || !containsString(view.Responsibilities, "forward") {
		return result
	}
	eligible := segmentEligibility(view)
	for _, link := range view.Links {
		if link.FromNodeID == view.DeviceID && eligible(policy, link) {
			result = append(result, link)
		}
	}
	return result
}
