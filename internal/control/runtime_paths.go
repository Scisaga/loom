package control

import (
	"errors"
	"net/netip"
	"sort"
	"strconv"
)

// transportPath is a disposable traversal result, never another authority.
// Links identify kernel underlay; hops identify the authenticated Hy2 stream
// endpoints carried over it. A local hybrid omits its own Hy2 hop.
type transportPath struct {
	candidate RouteCandidate
	hops      []TransportResource
	links     []NetworkLink
	local     bool
	accessWG  *TransportResource
}

func WGResourceAddress(resource TransportResource) (netip.Addr, error) {
	if resource.Validate() != nil || resource.Kind != "wireguard" || len(*resource.Authentication.LocalAddresses) != 1 {
		return netip.Addr{}, errors.New("WireGuard relay requires one exact interface address")
	}
	prefix, err := netip.ParsePrefix((*resource.Authentication.LocalAddresses)[0])
	if err != nil || prefix.Bits() != prefix.Addr().BitLen() || !prefix.Addr().IsGlobalUnicast() {
		return netip.Addr{}, errors.New("WireGuard relay address must be a unicast /32 or /128")
	}
	return prefix.Addr(), nil
}

func linkResources(link NetworkLink, resources map[string]TransportResource) (TransportResource, TransportResource, TransportResource, error) {
	from, to, target := resources[link.FromResourceID], resources[link.ResourceID], resources[link.ProbeTarget.ResourceID]
	a, ea := WGResourceAddress(from)
	b, eb := WGResourceAddress(to)
	if link.Validate() != nil || ea != nil || eb != nil || a == b || a.BitLen() != b.BitLen() ||
		from.OwnerNodeID != link.FromNodeID || to.OwnerNodeID != link.ToNodeID ||
		target.Kind != "hysteria2" || target.Validate() != nil || target.OwnerNodeID != link.ToNodeID ||
		link.ProbeTarget.Host != b.String() || link.ProbeTarget.Port != target.DialPort {
		return from, to, target, errors.New("Link does not bind its two WireGuard identities and exact target resource")
	}
	return from, to, target, nil
}

func RelayDialTarget(view DeviceView, target RelayTarget, receiver string) (string, int, error) {
	resources := map[string]TransportResource{}
	for _, resource := range view.Resources {
		resources[resource.ID] = resource
	}
	for _, link := range view.Links {
		if link.ID != target.LinkID {
			continue
		}
		_, _, next, err := linkResources(link, resources)
		if err != nil || link.FromNodeID != receiver || next.ID != target.ResourceID {
			break
		}
		return link.ProbeTarget.Host, link.ProbeTarget.Port, nil
	}
	return "", 0, errors.New("relay credential has no exact authorized next hop")
}

func pathHopTag(path transportPath, index int) string {
	if index == len(path.hops)-1 {
		return path.candidate.ID
	}
	return path.candidate.ID + ".hop." + strconv.Itoa(index)
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
	var walk func([]string, []TransportResource, []NetworkLink, bool, *TransportResource) error
	walk = func(chain []string, hops []TransportResource, pathLinks []NetworkLink, local bool, accessWG *TransportResource) error {
		last := chain[len(chain)-1]
		if len(hops) > 0 && policy.ExitScope.Allows(last) {
			var candidate RouteCandidate
			var err error
			if !local && len(chain) == 1 && accessWG == nil {
				candidate, err = oneHopCandidate(service, policy, hops[0], records...)
			} else {
				first := hops[0].ID
				if local {
					first = pathLinks[0].ResourceID
				}
				ids := []string{}
				used := map[string]TransportResource{}
				if accessWG != nil {
					first = accessWG.ID
					used[accessWG.ID] = *accessWG
				}
				for _, hop := range hops {
					used[hop.ID] = hop
				}
				for _, link := range pathLinks {
					ids = append(ids, link.ID)
					for _, id := range []string{link.FromResourceID, link.ResourceID, link.ProbeTarget.ResourceID} {
						used[id] = resources[id]
					}
				}
				specResources := []TransportResource{}
				for _, resource := range used {
					specResources = append(specResources, resource)
				}
				sort.Slice(specResources, func(i, j int) bool { return specResources[i].ID < specResources[j].ID })
				identity := map[string]any{"service_id": service.ID, "first_resource_id": first, "node_chain": chain, "link_ids": ids, "final_exit": last}
				id, e := digestContractValue("loom-candidate-id-v3\x00", identity)
				if e != nil {
					return e
				}
				spec, e := digestContractValue("loom-candidate-spec-v3\x00", dnsCandidateSpec(map[string]any{"identity": identity, "service": service, "policy": policy, "resources": specResources, "links": pathLinks}, service, records))
				if e != nil {
					return e
				}
				candidate = RouteCandidate{ID: id, SpecDigest: spec, Scope: "service:" + service.ID, ServiceID: service.ID, FirstResourceID: first, NodeChain: append([]string{}, chain...), LinkIDs: ids, FinalExit: last}
			}
			if err != nil {
				return err
			}
			result = append(result, transportPath{candidate: candidate, hops: append([]TransportResource{}, hops...), links: append([]NetworkLink{}, pathLinks...), local: local, accessWG: accessWG})
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
			if err := walk(append(append([]string{}, chain...), link.ToNodeID), append(append([]TransportResource{}, hops...), target), append(append([]NetworkLink{}, pathLinks...), link), local, accessWG); err != nil {
				return err
			}
		}
		return nil
	}
	for _, resource := range ordered {
		if resource.OwnerNodeID == source || !policy.EntryScope.Allows(resource.OwnerNodeID) {
			continue
		}
		first := resource
		var accessWG *TransportResource
		if resource.Kind == "wireguard" {
			target, err := WireGuardAccessTarget(resource, resources)
			if err != nil {
				continue
			}
			first, accessWG = target, &resource
		} else if resource.Kind != "hysteria2" || resource.LinkOnly {
			continue
		}
		if err := walk([]string{resource.OwnerNodeID}, []TransportResource{first}, []NetworkLink{}, false, accessWG); err != nil {
			return nil, err
		}
	}
	if localForward && policy.EntryScope.Allows(source) {
		if err := walk([]string{source}, []TransportResource{}, []NetworkLink{}, true, nil); err != nil {
			return nil, err
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].candidate.ID < result[j].candidate.ID })
	for i := 1; i < len(result); i++ {
		if result[i-1].candidate.ID == result[i].candidate.ID {
			return nil, errors.New("transport candidates have ambiguous stable identities")
		}
	}
	return result, nil
}

func renderTransportPath(path transportPath, resources []TransportResource, credentials map[string]string) ([]any, error) {
	byID := map[string]TransportResource{}
	for _, resource := range resources {
		byID[resource.ID] = resource
	}
	result := []any{}
	for index, hop := range path.hops {
		tag := pathHopTag(path, index)
		outbound, err := hy2Outbound(RouteCandidate{ID: tag}, hop, credentials[tag])
		if err != nil {
			return nil, err
		}
		linkIndex := index - 1
		if path.local {
			linkIndex++
		}
		if linkIndex >= 0 {
			link := path.links[linkIndex]
			outbound["server"], outbound["server_port"] = link.ProbeTarget.Host, link.ProbeTarget.Port
			if index == 0 {
				outbound["bind_interface"] = byID[link.FromResourceID].ListenerID
			}
		}
		if index > 0 {
			outbound["detour"] = pathHopTag(path, index-1)
		} else if path.accessWG != nil {
			address, err := WireGuardAccessAddress(*path.accessWG, "")
			if err != nil {
				return nil, err
			}
			outbound["detour"] = wireGuardAccessTag(path.accessWG.ID)
			outbound["server"], outbound["server_port"] = address.String(), hop.DialPort
		}
		result = append(result, outbound)
	}
	return result, nil
}
