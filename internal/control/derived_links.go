package control

import (
	"errors"
	"sort"
)

// DerivedNetworkLinks projects possible native relay segments from authenticated
// node responsibilities and resources. It does not consult measurements or the
// historical manually configured Link facts, and grants no Service permission.
func DerivedNetworkLinks(projection Projection) ([]NetworkLink, error) {
	resources, nodes, err := projectedNativeTopology(projection)
	if err != nil {
		return nil, err
	}
	return nodeNetworkLinks(projection.NetworkID, nodes, resources)
}
func projectedNativeTopology(projection Projection) ([]TransportResource, map[string]ViewNode, error) {
	resources := []TransportResource{}
	seenResources, wgOwners, wgAddresses := map[string]bool{}, map[string]bool{}, map[string]bool{}
	devices := map[string]DeviceAuthorization{}
	for _, device := range projection.DeviceAuthorizations {
		devices[device.ID] = device
	}
	for _, resource := range projection.NetworkIntent.Resources {
		owner, ok := devices[resource.OwnerNodeID]
		if !ok || !containsString(owner.Responsibilities, "forward") && !containsString(owner.Responsibilities, "internet_egress") {
			continue
		}
		if resource.Validate() != nil || validateCurrentTransportPayload(resource) != nil {
			return nil, nil, errors.New("invalid native resource")
		}
		if resource.Kind == "wireguard" && owner.WireGuardPublicKey != *resource.Authentication.PublicKey {
			return nil, nil, errors.New("WG resource requires its registered owner identity")
		}
		if seenResources[resource.ID] {
			return nil, nil, errors.New("native resource identity is duplicated")
		}
		seenResources[resource.ID] = true
		if resource.Kind == "wireguard" {
			address, err := WGResourceAddress(resource)
			if err != nil || wgOwners[owner.ID] || wgAddresses[address.String()] {
				return nil, nil, errors.New("WG receiving identity or host address is ambiguous")
			}
			wgOwners[owner.ID], wgAddresses[address.String()] = true, true
		}
		resources = append(resources, resource)
	}
	nodes := map[string]ViewNode{}
	for _, device := range projection.DeviceAuthorizations {
		node := ViewNode{WireGuardPublicKey: device.WireGuardPublicKey, DNSServers: append([]string(nil), device.DNSServers...), ID: device.ID, Responsibilities: device.Responsibilities, PolicyIDs: device.PolicyIDs}
		nodes[node.ID] = node
	}
	return resources, nodes, nil
}
func DerivedViewLinks(view DeviceView) ([]NetworkLink, error) { return viewNetworkLinks(view) }
func viewNetworkLinks(view DeviceView) ([]NetworkLink, error) {
	return nodeNetworkLinks(view.NetworkID, viewNodes(view), view.Resources)
}
func nodeNetworkLinks(network string, nodes map[string]ViewNode, resources []TransportResource) ([]NetworkLink, error) {
	result := []NetworkLink{}
	owned := map[string]string{}
	for _, r := range resources {
		if r.Kind == "wireguard" {
			owned[r.OwnerNodeID] = r.ID
		}
	}
	for _, source := range nodes {
		for _, to := range resources {
			link, allowed, err := nodeNetworkLink(network, source, nodes[to.OwnerNodeID], to, owned[source.ID])
			if err != nil {
				return nil, err
			}
			if allowed {
				result = append(result, link)
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

// This single-segment projection is identical to the whole topology writer.
// Bounded measurement readers do not need its source/resource product.
func nodeNetworkLink(network string, source, receiver ViewNode, to TransportResource, owned string) (NetworkLink, bool, error) {
	if !containsString(source.Responsibilities, "forward") || receiver.ID == "" || source.ID == to.OwnerNodeID ||
		!containsString(receiver.Responsibilities, "forward") && !containsString(receiver.Responsibilities, "internet_egress") ||
		to.Kind == "wireguard" && source.WireGuardPublicKey == "" {
		return NetworkLink{}, false, nil
	}
	id, err := digestContractValue("loom-relay-link-id-v3\x00", map[string]any{"network_id": network, "from_node_id": source.ID, "resource_id": to.ID, "purpose": "relay"})
	if err != nil {
		return NetworkLink{}, false, err
	}
	initiator := source.ID
	if to.OwnerNodeID < initiator {
		initiator = to.OwnerNodeID
	}
	probe := LinkProbeTarget{ResourceID: to.ID, Host: to.DialHost, Port: to.DialPort, Action: "hysteria2_echo"}
	fromResource := ""
	if to.Kind == "wireguard" {
		address, err := WireGuardAccessAddress(to, "")
		if err != nil {
			return NetworkLink{}, false, err
		}
		probe.Host, probe.Port, probe.Action = address.String(), 53, "wireguard_echo"
		fromResource = owned
	}
	link := NetworkLink{ID: id, FromNodeID: source.ID, ToNodeID: to.OwnerNodeID, FromResourceID: fromResource, ResourceID: to.ID, InitiatorNodeID: initiator, Purpose: "relay", ProbeTarget: probe}
	if err := link.Validate(); err != nil {
		return NetworkLink{}, false, err
	}
	return link, true, nil
}

// Exact former resource-pair projection is used only to verify protected old
// originals during explicit migration. It is never a current graph writer.
func derivedNetworkLink(network string, from, to TransportResource) (NetworkLink, error) {
	id, err := digestContractValue("loom-relay-link-id-v3\x00", map[string]any{"network_id": network, "from_resource_id": from.ID, "resource_id": to.ID, "purpose": "relay"})
	if err != nil {
		return NetworkLink{}, err
	}
	dns, err := WireGuardAccessAddress(to, "")
	if err != nil {
		return NetworkLink{}, err
	}
	initiator := from.OwnerNodeID
	if to.OwnerNodeID < initiator {
		initiator = to.OwnerNodeID
	}
	link := NetworkLink{ID: id, FromNodeID: from.OwnerNodeID, ToNodeID: to.OwnerNodeID,
		FromResourceID: from.ID, ResourceID: to.ID, InitiatorNodeID: initiator, Purpose: "relay",
		ProbeTarget: LinkProbeTarget{ResourceID: to.ID, Host: dns.String(), Port: 53, Action: "wireguard_echo"}}
	return link, link.Validate()
}
