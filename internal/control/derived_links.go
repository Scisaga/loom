package control

import (
	"errors"
	"sort"
)

// DerivedNetworkLinks projects possible native relay segments from authenticated
// node responsibilities and resources. It does not consult measurements or the
// historical manually configured Link facts, and grants no Service permission.
func DerivedNetworkLinks(projection Projection) ([]NetworkLink, error) {
	if ValidateID(projection.NetworkID) != nil {
		return nil, errors.New("relay projection requires a network identity")
	}
	roles := map[string][]string{}
	for _, device := range projection.DeviceAuthorizations {
		if _, exists := roles[device.ID]; exists {
			return nil, errors.New("relay node identity is ambiguous")
		}
		roles[device.ID] = device.Responsibilities
	}
	resources := []TransportResource{}
	ids, owners, keys, addresses := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, resource := range projection.NetworkIntent.Resources {
		if resource.Kind != "wireguard" || !containsString(roles[resource.OwnerNodeID], "forward") && !containsString(roles[resource.OwnerNodeID], "internet_egress") {
			continue
		}
		address, err := WGResourceAddress(resource)
		if err != nil || validateCurrentTransportPayload(resource) != nil || validateWireGuardPublicKey(*resource.Authentication.PublicKey) != nil {
			return nil, errors.New("relay resource has no current native identity")
		}
		if ids[resource.ID] || owners[resource.OwnerNodeID] || keys[*resource.Authentication.PublicKey] || addresses[address.String()] {
			return nil, errors.New("relay resources have ambiguous owners, keys or addresses")
		}
		ids[resource.ID], owners[resource.OwnerNodeID], keys[*resource.Authentication.PublicKey], addresses[address.String()] = true, true, true, true
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	result := []NetworkLink{}
	for _, from := range resources {
		if !containsString(roles[from.OwnerNodeID], "forward") {
			continue
		}
		for _, to := range resources {
			if from.OwnerNodeID == to.OwnerNodeID {
				continue
			}
			fromAddress, _ := WGResourceAddress(from)
			toAddress, _ := WGResourceAddress(to)
			if fromAddress.BitLen() != toAddress.BitLen() {
				continue
			}
			link, err := derivedNetworkLink(projection.NetworkID, from, to)
			if err != nil {
				return nil, err
			}
			result = append(result, link)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

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
		ProbeTarget: LinkProbeTarget{ResourceID: to.ID, Host: dns.String(), Port: 53, Action: "wireguard_dns"}}
	return link, link.Validate()
}
