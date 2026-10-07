package control

import (
	"errors"
	"net"
	"sort"
	"strconv"
)

// ResourceProbe is a disposable private execution projection, not another
// identity or wire object. Never log it: Credential is an existing permission.
type ResourceProbe struct {
	Resource   TransportResource
	Credential string
	SpecDigest string
}

func (probe ResourceProbe) Target() string {
	return net.JoinHostPort(probe.Resource.DialHost, strconv.Itoa(probe.Resource.DialPort))
}

// FirstHopProbes chooses one already authorized login per public first hop.
// Stable candidate order makes the choice identical on client and receiver.
// Local hybrid Link execution is deliberately excluded from this projection.
func FirstHopProbes(view DeviceView) ([]ResourceProbe, error) {
	if err := view.Validate(); err != nil {
		return nil, err
	}
	credentials, err := profileCredentials(view)
	if err != nil {
		return nil, err
	}
	resources := map[string]TransportResource{}
	for _, resource := range view.Resources {
		resources[resource.ID] = resource
	}
	seen := map[string]bool{}
	result := []ResourceProbe{}
	for _, route := range view.Routes {
		resource, found := resources[route.FirstResourceID]
		if !found || resource.Kind != "hysteria2" || resource.OwnerNodeID == view.DeviceID || resource.LinkOnly || seen[resource.ID] {
			continue
		}
		if len(route.NodeChain) == 0 || route.NodeChain[0] != resource.OwnerNodeID {
			return nil, errors.New("public first hop does not match the certified path")
		}
		tag := route.ID
		if len(route.LinkIDs) > 0 {
			tag += ".hop.0"
		}
		credential := credentials[tag]
		if ValidatePublicKey(credential) != nil {
			return nil, errors.New("public first hop has no authorized credential")
		}
		binding, err := digestContractValue("loom-resource-probe-credential-v3\x00", credential)
		if err != nil {
			return nil, err
		}
		digest, err := digestContractValue("loom-resource-probe-spec-v3\x00", map[string]any{
			"device_id": view.DeviceID, "resource": resource, "dns_servers": append([]string{}, view.DNSServers...), "credential_digest": binding,
		})
		if err != nil {
			return nil, err
		}
		seen[resource.ID] = true
		result = append(result, ResourceProbe{Resource: resource, Credential: credential, SpecDigest: digest})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Resource.ID < result[j].Resource.ID })
	return result, nil
}

func verifyResourceObservation(value Observation, probes []ResourceProbe) error {
	for _, probe := range probes {
		if value.ResourceID == probe.Resource.ID && value.Target == probe.Target() && value.SpecDigest == probe.SpecDigest && value.Action == "hysteria2_tls" {
			return nil
		}
	}
	return errors.New("resource observation is outside the device's current first-hop authorization")
}
