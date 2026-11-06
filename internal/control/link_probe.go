package control

import (
	"errors"
	"net"
	"sort"
	"strconv"
)

// LinkSpecifications computes current directed transport specifications once.
// Policy, Service and consumer multiplicity do not multiply measurements.
func LinkSpecifications(view DeviceView) (map[string]string, error) {
	links, err := DerivedViewLinks(view)
	if err != nil {
		return nil, err
	}
	resources := map[string]TransportResource{}
	for _, value := range view.Resources {
		resources[value.ID] = value
	}
	nodes := viewNodes(view)
	result := make(map[string]string, len(links))
	for _, link := range links {
		_, to, _, err := linkResources(link, resources)
		if err != nil {
			return nil, err
		}
		source := nodes[link.FromNodeID]
		// Public WG identity belongs to the sender even if it owns no listener.
		spec, err := directedLinkSpec(view.NetworkID, link, source, to)
		if err != nil {
			return nil, err
		}
		result[link.ID] = spec
	}
	return result, nil
}

func directedLinkSpec(network string, link NetworkLink, source ViewNode, to TransportResource) (string, error) {
	return digestContractValue("loom-directed-link-spec-v3\x00", map[string]any{"network_id": network, "link": link, "receiver_resource": to, "source_node_id": source.ID, "source_wireguard_public_key": source.WireGuardPublicKey, "dns_servers": append([]string{}, source.DNSServers...)})
}

// The control already owns the authenticated facts needed for shared specs.
// Computing them does not require a private View, credentials or native JSON.
func projectionLinkSpecs(projection Projection) (map[string]string, error) {
	resources, nodes, err := projectedNativeTopology(projection)
	if err != nil {
		return nil, err
	}
	links, err := nodeNetworkLinks(projection.NetworkID, nodes, resources)
	if err != nil {
		return nil, err
	}
	byID := map[string]TransportResource{}
	for _, resource := range resources {
		byID[resource.ID] = resource
	}
	result := make(map[string]string, len(links))
	for _, link := range links {
		value, err := directedLinkSpec(projection.NetworkID, link, nodes[link.FromNodeID], byID[link.ResourceID])
		if err != nil {
			return nil, err
		}
		result[link.ID] = value
	}
	return result, nil
}

func LinkSpecDigest(view DeviceView, linkID string) (string, error) {
	values, err := LinkSpecifications(view)
	if err != nil {
		return "", err
	}
	if value, ok := values[linkID]; ok {
		return value, nil
	}
	return "", errors.New("Link observation has no current directed Link")
}

// Historical resource-pair specification: used only to verify original signed
// recovery evidence. It never creates a current observation specification.
func nativeLinkSpecDigest(link NetworkLink, from, to TransportResource) (string, error) {
	values := []TransportResource{from, to}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return digestContractValue("loom-link-spec-v3\x00", map[string]any{"link": link, "resources": values})
}

func verifyLinkObservation(value Observation, view DeviceView) error {
	links, err := DerivedViewLinks(view)
	if err != nil {
		return err
	}
	for _, link := range links {
		if link.ID != value.LinkID || link.FromNodeID != view.DeviceID {
			continue
		}
		digest, err := LinkSpecDigest(view, link.ID)
		if err == nil && matchesNativeLinkObservation(value, link, digest) {
			return nil
		}
	}
	return errors.New("Link observation is outside the source's current native probe specification")
}

func matchesNativeLinkObservation(value Observation, link NetworkLink, digest string) bool {
	return value.LinkID == link.ID && value.ResourceID == link.ResourceID && value.SpecDigest == digest &&
		value.Target == net.JoinHostPort(link.ProbeTarget.Host, strconv.Itoa(link.ProbeTarget.Port)) && value.Action == link.ProbeTarget.Action
}
