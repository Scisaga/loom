package control

import (
	"errors"
	"net/netip"
	"sort"
)

// Each hop terminates its transport and receives business TCP/UDP. A local
// hybrid starts at its next WG receiver without dialing its own listener.
type transportPath struct {
	candidate RouteCandidate
	hops      []TransportResource
	links     []NetworkLink
	local     bool
}

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
	a, ea := WGResourceAddress(from)
	b, eb := WGResourceAddress(to)
	dns, ed := WireGuardAccessAddress(to, "")
	if link.Validate() != nil || link.ProbeTarget.Action != "wireguard_dns" || ea != nil || eb != nil || ed != nil || a == b || a.BitLen() != b.BitLen() ||
		from.AccessHY2ResourceID != "" || from.OwnerNodeID != link.FromNodeID || to.OwnerNodeID != link.ToNodeID || link.ProbeTarget.ResourceID != to.ID || link.ProbeTarget.Host != dns.String() {
		return from, to, to, errors.New("Link does not bind two independent WG resources and execution DNS")
	}
	return from, to, to, nil
}

func pathCandidate(service Service, policy NetworkPolicy, chain []string, hops []TransportResource, links []NetworkLink, local bool, resources map[string]TransportResource, records []DNSRecord) (RouteCandidate, error) {
	if len(chain) == 1 && !local {
		return oneHopCandidate(service, policy, hops[0], records...)
	}
	first := hops[0].ID
	ids := []string{}
	used := map[string]TransportResource{}
	for _, resource := range hops {
		used[resource.ID] = resource
	}
	for _, link := range links {
		ids = append(ids, link.ID)
		for _, id := range []string{link.FromResourceID, link.ResourceID} {
			used[id] = resources[id]
		}
	}
	values := []TransportResource{}
	for _, resource := range used {
		values = append(values, resource)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	identity := map[string]any{"service_id": service.ID, "first_resource_id": first, "node_chain": chain, "link_ids": ids, "final_exit": chain[len(chain)-1]}
	id, err := digestContractValue("loom-candidate-id-v3\x00", identity)
	if err != nil {
		return RouteCandidate{}, err
	}
	spec, err := digestContractValue("loom-candidate-spec-v3\x00", dnsCandidateSpec(map[string]any{"identity": identity, "service": service, "policy": policy, "resources": values, "links": links}, service, records))
	return RouteCandidate{ID: id, SpecDigest: spec, Scope: service.Scope(), ServiceID: service.ID, FirstResourceID: first, NodeChain: append([]string{}, chain...), LinkIDs: ids, FinalExit: chain[len(chain)-1]}, err
}

func transportPaths(source string, localForward bool, service Service, policy NetworkPolicy, values []TransportResource, links []NetworkLink, records ...DNSRecord) ([]transportPath, error) {
	resources := map[string]TransportResource{}
	for _, resource := range values {
		resources[resource.ID] = resource
	}
	ordered := append([]TransportResource{}, values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	edges := append([]NetworkLink{}, links...)
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
	result := []transportPath{}
	var walk func([]string, []TransportResource, []NetworkLink, bool) error
	walk = func(chain []string, hops []TransportResource, pathLinks []NetworkLink, local bool) error {
		last := chain[len(chain)-1]
		if len(hops) > 0 && policy.permitsEndpoint(service, last) {
			candidate, err := pathCandidate(service, policy, chain, hops, pathLinks, local, resources, records)
			if err != nil {
				return err
			}
			result = append(result, transportPath{candidate: candidate, hops: append([]TransportResource{}, hops...), links: append([]NetworkLink{}, pathLinks...), local: local})
		}
		if policy.MaxHops > 0 && len(chain) >= policy.MaxHops || len(chain) > 1 && !policy.RelayScope.Allows(last) {
			return nil
		}
		for _, link := range edges {
			if link.FromNodeID != last || containsString(chain, link.ToNodeID) || link.ToNodeID == source {
				continue
			}
			_, _, target, err := linkResources(link, resources)
			if err != nil {
				continue
			}
			if err = walk(append(append([]string{}, chain...), link.ToNodeID), append(append([]TransportResource{}, hops...), target), append(append([]NetworkLink{}, pathLinks...), link), local); err != nil {
				return err
			}
		}
		return nil
	}
	for _, resource := range ordered {
		if resource.OwnerNodeID == source || !policy.EntryScope.Allows(resource.OwnerNodeID) || resource.AccessHY2ResourceID != "" {
			continue
		}
		if resource.Kind == "wireguard" {
			if !resource.AccessEnabled {
				continue
			}
			if _, err := WireGuardAccessAddress(resource, ""); err != nil {
				return nil, err
			}
		} else if resource.Kind != "hysteria2" || resource.LinkOnly {
			continue
		}
		if err := walk([]string{resource.OwnerNodeID}, []TransportResource{resource}, []NetworkLink{}, false); err != nil {
			return nil, err
		}
	}
	if localForward && policy.EntryScope.Allows(source) {
		if err := walk([]string{source}, []TransportResource{}, []NetworkLink{}, true); err != nil {
			return nil, err
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].candidate.ID < result[j].candidate.ID })
	for i := 1; i < len(result); i++ {
		if result[i-1].candidate.ID == result[i].candidate.ID {
			return nil, errors.New("transport candidate identities are ambiguous")
		}
	}
	return result, nil
}

func candidateTransportPath(view DeviceView, origin string, service Service, policy NetworkPolicy, candidate RouteCandidate) (transportPath, error) {
	reject := errors.New("candidate does not match its authorized transport path")
	chain := candidate.NodeChain
	if candidate.Validate() != nil || len(chain) == 0 || !policy.EntryScope.Allows(chain[0]) || !policy.permitsEndpoint(service, candidate.FinalExit) || policy.MaxHops > 0 && len(chain) > policy.MaxHops {
		return transportPath{}, reject
	}
	resources := map[string]TransportResource{}
	for _, resource := range view.Resources {
		resources[resource.ID] = resource
	}
	links := map[string]NetworkLink{}
	for _, link := range view.Links {
		links[link.ID] = link
	}
	path := transportPath{local: chain[0] == origin, hops: []TransportResource{}, links: []NetworkLink{}}
	if !path.local {
		first, found := resources[candidate.FirstResourceID]
		if !found || first.OwnerNodeID != chain[0] || first.Validate() != nil || first.AccessHY2ResourceID != "" {
			return transportPath{}, reject
		}
		if first.Kind == "wireguard" {
			if !first.AccessEnabled {
				return transportPath{}, reject
			}
		} else if first.Kind != "hysteria2" || first.LinkOnly {
			return transportPath{}, reject
		}
		path.hops = append(path.hops, first)
	}
	// The supplied candidate already names its entire path. Verify those exact
	// edges, then recompute its complete identity/spec. Enumerating every other
	// path for each permission turns ordinary View validation into a graph scan
	// repeated once per candidate and does not strengthen authorization.
	for i, id := range candidate.LinkIDs {
		link, found := links[id]
		if !found || link.FromNodeID != chain[i] || link.ToNodeID != chain[i+1] || chain[i+1] == origin || i > 0 && !policy.RelayScope.Allows(chain[i]) {
			return transportPath{}, reject
		}
		_, _, target, err := linkResources(link, resources)
		if err != nil {
			return transportPath{}, err
		}
		path.hops = append(path.hops, target)
		path.links = append(path.links, link)
	}
	if len(path.hops) == 0 {
		return transportPath{}, reject
	}
	want, err := pathCandidate(service, policy, chain, path.hops, path.links, path.local, resources, view.DNSRecords)
	if err != nil || !sameContractValue(want, candidate) {
		return transportPath{}, reject
	}
	path.candidate = want
	return path, nil
}

func pathPermission(path transportPath, index int, origin string, policy NetworkPolicy, service Service, excluded []ServiceMatcher, records ...DNSRecord) InboundCredential {
	position := index
	if path.local {
		position++
	}
	sender := origin
	if position > 0 {
		sender = path.candidate.NodeChain[position-1]
	}
	resource := path.hops[index]
	return InboundCredential{DeviceID: origin, ServiceID: service.ID, PolicyID: policy.ID, Candidate: path.candidate, SenderID: sender,
		ResourceID: resource.ID, ReceiverNodeID: resource.OwnerNodeID, AllowedTargets: append([]ServiceMatcher{}, service.TargetMatchers(records...)...), ExcludedTargets: append([]ServiceMatcher{}, excluded...)}
}
