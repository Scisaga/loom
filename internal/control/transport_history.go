package control

import (
	"errors"
	"net/url"
)

// The same schema retains exact signed historical bytes for signature and
// causal verification. This does not admit their execution to a new View or
// allow any writer to issue the retired transport semantics again.
func validateCurrentTransportPayload(payload MaterialPayload) error {
	switch value := payload.(type) {
	case Genesis:
		if len(value.NetworkIntent.BusinessProbeTargets) != 0 {
			return errors.New("new genesis cannot contain a retired probe pool")
		}
		for _, service := range value.NetworkIntent.Services {
			if err := service.ValidateCurrent(); err != nil {
				return err
			}
		}
	case Service:
		return value.ValidateCurrent()
	case BusinessProbeTarget:
		return errors.New("probe URLs belong to Service; independent probe targets cannot be signed")
	case ConflictResolution:
		if value.Value != nil {
			return validateCurrentTransportPayload(value.Value)
		}
	case TransportResource:
		if value.AccessHY2ResourceID != "" {
			return errors.New("WireGuard access cannot depend on a Hy2 resource")
		}
	case NetworkLink:
		return errors.New("relay Links are derived from authenticated nodes and resources; manual Link writes are retired")
	}
	return nil
}

// Recognize the exact retired Service shape only while validating immutable
// Material originals and their causal dependencies. It is never executable.
func validateHistoricalService(service Service) error {
	if service.RestrictToProbeTargets != nil || ValidateID(service.ID) != nil || ValidateText(service.Name) != nil {
		return errors.New("invalid historical Service identity")
	}
	if service.Kind == "local_network" {
		if service.LocalNetwork == nil || service.LocalNetwork.Validate() != nil || service.Matchers != nil || service.AccessScope != "" {
			return errors.New("invalid historical LAN Service")
		}
	} else {
		if service.Kind != "internet" || service.LocalNetwork != nil || service.AccessScope != "" && service.AccessScope != "public_internet" {
			return errors.New("invalid historical internet Service")
		}
		if service.AccessScope == "public_internet" {
			if service.Matchers != nil {
				return errors.New("historical ordinary internet has destinations")
			}
		} else if len(service.Matchers) == 0 {
			return errors.New("historical specified Service has no matchers")
		}
		for index, matcher := range service.Matchers {
			if matcher.Kind == "public_internet" || matcher.Port != 0 || matcher.Validate() != nil || index > 0 && !serviceMatcherLess(service.Matchers[index-1], matcher) {
				return errors.New("invalid historical Service matchers")
			}
		}
	}
	if service.ProbeURLs != nil && len(service.ProbeURLs) == 0 {
		return errors.New("empty historical probe URLs")
	}
	for index, target := range service.ProbeURLs {
		if ValidateHTTPSURL(target) != nil || index > 0 && service.ProbeURLs[index-1] >= target {
			return errors.New("invalid historical probe URL")
		}
		parsed, _ := url.Parse(target)
		matched := false
		for _, matcher := range historicalServiceMatchers(service) {
			matched = matched || matcher.Matches(parsed.Hostname())
		}
		if !matched {
			return errors.New("historical probe is outside its original permission")
		}
	}
	return nil
}

func historicalServiceMatchers(service Service) []ServiceMatcher {
	if service.LocalNetwork != nil {
		return []ServiceMatcher{{Kind: "ip_prefix", Value: service.LocalNetwork.VirtualPrefix}}
	}
	if service.AccessScope == "public_internet" {
		return []ServiceMatcher{{Kind: "public_internet"}}
	}
	return service.Matchers
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
	if link.ProbeTarget.Action == "wireguard_dns" {
		from, to := resources[link.FromResourceID], resources[link.ResourceID]
		a, ea := WGResourceAddress(from)
		b, eb := WGResourceAddress(to)
		execution, ee := WireGuardAccessAddress(to, "")
		if link.Validate() != nil || ea != nil || eb != nil || ee != nil || a == b || a.BitLen() != b.BitLen() || from.OwnerNodeID != link.FromNodeID || to.OwnerNodeID != link.ToNodeID || link.ProbeTarget.ResourceID != to.ID || link.ProbeTarget.Host != execution.String() {
			return errors.New("historical native Link is inconsistent")
		}
		return nil
	}
	if link.ProbeTarget.Action != "hysteria2_tls" {
		return errors.New("unrecognized historical Link action")
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
