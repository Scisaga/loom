package localconfig

import (
	"errors"
	"net/netip"
)

// IngressAddress resolves only an explicitly supplied infrastructure mapping.
// It cannot create a listener, a node responsibility or network permission.
func IngressAddress(nodes []NodeNetwork, owner, protocol, publicHost string, publicPort int) (netip.AddrPort, error) {
	if publicPort < 1 || publicPort > 65535 || protocol != "udp" && protocol != "tcp" {
		return netip.AddrPort{}, errors.New("invalid infrastructure mapping query")
	}
	var result netip.AddrPort
	for _, node := range nodes {
		if node.ID != owner {
			continue
		}
		for _, mapping := range node.Ingress {
			if mapping.Protocol != protocol || mapping.PublicHost != publicHost || publicPort < mapping.PublicPorts.First || publicPort > mapping.PublicPorts.Last {
				continue
			}
			address, err := netip.ParseAddr(mapping.HostAddress)
			port := mapping.HostPorts.First + publicPort - mapping.PublicPorts.First
			if err != nil || address.String() != mapping.HostAddress || address.Zone() != "" || address.Is4In6() || port < 1 || port > 65535 || result.IsValid() || mapping.HostPorts.Last-mapping.HostPorts.First != mapping.PublicPorts.Last-mapping.PublicPorts.First {
				return netip.AddrPort{}, errors.New("infrastructure mapping is invalid or ambiguous")
			}
			result = netip.AddrPortFrom(address, uint16(port))
		}
	}
	if !result.IsValid() {
		return result, errors.New("explicit infrastructure mapping is missing")
	}
	return result, nil
}
