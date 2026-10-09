package control

import (
	"errors"
	"net"
	"sort"
	"strconv"
)

// ResourceProbe is a disposable private execution projection, not another
// identity or wire object. Never log it: Hy2 Credential grants permission.
// For WG, Credential contains only the running shared identity public key.
type ResourceProbe struct {
	NetworkID  string
	Resource   TransportResource
	Credential string
	SpecDigest string
}

func (probe ResourceProbe) Action() string {
	if probe.Resource.Kind == "wireguard" {
		return "wireguard_dns"
	}
	return "hysteria2_tls"
}

func (probe ResourceProbe) Target() string {
	return net.JoinHostPort(probe.Resource.DialHost, strconv.Itoa(probe.Resource.DialPort))
}

// FirstHopProbes chooses one already authorized login per public first hop.
// Stable candidate order makes the choice identical on client and receiver.
// Local hybrid Link execution is deliberately excluded from this projection.
func FirstHopProbes(view DeviceView) ([]ResourceProbe, error) {
	byCandidate, err := CandidateFirstHopProbes(view)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	result := []ResourceProbe{}
	for _, route := range view.Routes {
		probe, found := byCandidate[route.ID]
		if !found || seen[probe.Resource.ID] {
			continue
		}
		seen[probe.Resource.ID] = true
		result = append(result, probe)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Resource.ID < result[j].Resource.ID })
	return result, nil
}

// CandidateFirstHopProbes binds paths using the currently sampled first login.
// These are private execution projections, not additional sampling requests.
// In particular, a resource sample made with another path's Hy2 credential
// cannot be used as evidence about this path's authentication: it has no entry.
func CandidateFirstHopProbes(view DeviceView) (map[string]ResourceProbe, error) {
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
	result := map[string]ResourceProbe{}
	executions := map[string]ResourceProbe{}
	var wireGuardPublic string
	for _, route := range view.Routes {
		resource, found := resources[route.FirstResourceID]
		if !found || (resource.Kind != "hysteria2" && resource.Kind != "wireguard") || resource.OwnerNodeID == view.DeviceID || resource.LinkOnly {
			continue
		}
		if len(route.NodeChain) > 0 && route.NodeChain[0] == view.DeviceID {
			continue
		}
		if len(route.NodeChain) == 0 || route.NodeChain[0] != resource.OwnerNodeID {
			return nil, errors.New("public first hop does not match the certified path")
		}
		credential := credentials[route.ID]
		valid := ValidatePublicKey(credential) == nil
		if resource.Kind == "wireguard" {
			if !resource.AccessEnabled {
				continue
			}
			if wireGuardPublic == "" {
				_, wireGuardPublic, err = sharedWireGuardIdentity(view, credentials)
				if err != nil {
					return nil, err
				}
			}
			credential = wireGuardPublic
			valid = validateWireGuardPublicKey(credential) == nil
		}
		if !valid {
			return nil, errors.New("public first hop has no authorized credential")
		}
		if probe, found := executions[resource.ID]; found {
			if probe.Credential == credential {
				result[route.ID] = probe
			}
			continue
		}
		binding, err := digestContractValue("loom-resource-probe-credential-v3\x00", credential)
		if err != nil {
			return nil, err
		}
		spec := map[string]any{"device_id": view.DeviceID, "resource": resource, "dns_servers": append([]string{}, view.DNSServers...), "credential_digest": binding}
		if resource.Kind == "wireguard" {
			spec["network_id"] = view.NetworkID
		}
		digest, err := digestContractValue("loom-resource-probe-spec-v3\x00", spec)
		if err != nil {
			return nil, err
		}
		probe := ResourceProbe{NetworkID: view.NetworkID, Resource: resource, Credential: credential, SpecDigest: digest}
		executions[resource.ID], result[route.ID] = probe, probe
	}
	return result, nil
}

func verifyResourceObservation(value Observation, probes []ResourceProbe) error {
	for _, probe := range probes {
		if value.ResourceID == probe.Resource.ID && value.Target == probe.Target() && value.SpecDigest == probe.SpecDigest && value.Action == probe.Action() {
			return nil
		}
	}
	return errors.New("resource observation is outside the device's current first-hop authorization")
}
