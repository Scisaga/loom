package control

import "errors"

// The same schema retains exact signed historical bytes for signature and
// causal verification. This does not admit their execution to a new View or
// allow any writer to issue the retired transport semantics again.
func validateCurrentTransportPayload(payload MaterialPayload) error {
	switch value := payload.(type) {
	case TransportResource:
		if value.AccessHY2ResourceID != "" {
			return errors.New("WireGuard access cannot depend on a Hy2 resource")
		}
	case NetworkLink:
		if value.ProbeTarget.Action != "wireguard_dns" {
			return errors.New("new Links require independent WireGuard execution")
		}
	}
	return nil
}

func historicalAccessTarget(resource TransportResource, resources map[string]TransportResource) error {
	target := resources[resource.AccessHY2ResourceID]
	if resource.Validate() != nil || resource.Kind != "wireguard" || resource.AccessHY2ResourceID == "" ||
		target.Validate() != nil || target.Kind != "hysteria2" || target.LinkOnly || target.OwnerNodeID != resource.OwnerNodeID {
		return errors.New("historical access fact has no exact same-node resource dependency")
	}
	_, err := WGResourceAddress(resource)
	return err
}

func historicalLinkResources(link NetworkLink, resources map[string]TransportResource) error {
	if link.ProbeTarget.Action != "hysteria2_tls" {
		_, _, _, err := linkResources(link, resources)
		return err
	}
	from, to, target := resources[link.FromResourceID], resources[link.ResourceID], resources[link.ProbeTarget.ResourceID]
	a, ea := WGResourceAddress(from)
	b, eb := WGResourceAddress(to)
	if link.Validate() != nil || ea != nil || eb != nil || a == b || a.BitLen() != b.BitLen() ||
		from.OwnerNodeID != link.FromNodeID || to.OwnerNodeID != link.ToNodeID || target.Kind != "hysteria2" ||
		target.Validate() != nil || target.OwnerNodeID != link.ToNodeID || link.ProbeTarget.Host != b.String() || link.ProbeTarget.Port != target.DialPort {
		return errors.New("historical Link has inconsistent signed resource relationships")
	}
	return nil
}
