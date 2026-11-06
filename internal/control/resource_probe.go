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
	PolicyID     string
	DiagnosticID string
	NetworkID    string
	Resource     TransportResource
	Credential   string
	SpecDigest   string
}

func (probe ResourceProbe) Action() string {
	if probe.Resource.Kind == "wireguard" {
		return "wireguard_echo"
	}
	return "hysteria2_echo"
}

func (probe ResourceProbe) Target() string {
	return net.JoinHostPort(probe.Resource.DialHost, strconv.Itoa(probe.Resource.DialPort))
}

// FirstHopProbes chooses one already authorized login per public first hop.
// Stable candidate order makes the choice identical on client and receiver.
// Local hybrid Link execution is deliberately excluded from this projection.
func FirstHopProbes(view DeviceExecution) ([]ResourceProbe, error) {
	byCandidate, err := CandidateFirstHopProbes(view)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	result := []ResourceProbe{}
	for _, route := range view.Routes {
		probe, found := byCandidate[route.ID]
		if !found || seen[probe.Resource.ID+"\x00"+probe.PolicyID] {
			continue
		}
		seen[probe.Resource.ID+"\x00"+probe.PolicyID] = true
		result = append(result, probe)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Resource.ID < result[j].Resource.ID || result[i].Resource.ID == result[j].Resource.ID && result[i].SpecDigest < result[j].SpecDigest
	})
	return result, nil
}

// CandidateFirstHopProbes binds paths using the currently sampled first login.
// These are private execution projections, not additional sampling requests.
// In particular, a resource sample made with another path's Hy2 credential
// cannot be used as evidence about this path's authentication: it has no entry.
func CandidateFirstHopProbes(view DeviceExecution) (map[string]ResourceProbe, error) {
	if err := view.Validate(); err != nil {
		return nil, err
	}
	credentials, err := executionCredentials(view.DeviceView)
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
		if route.EntryNodeID != resource.OwnerNodeID {
			return nil, errors.New("public entry differs from its resource owner")
		}

		credential := credentials[resource.ID]
		valid := TransportCredential{ResourceID: resource.ID, SenderID: view.DeviceID, Credential: credential}.Validate() == nil
		if resource.Kind == "wireguard" {
			if !resource.AccessEnabled {
				continue
			}
			if wireGuardPublic == "" {
				_, wireGuardPublic, err = sharedWireGuardIdentity(view.DeviceView, credentials)
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
		if probe, found := executions[resource.ID+"\x00"+route.PolicyID]; found {
			if probe.Credential == credential {
				result[route.ID] = probe
			}
			continue
		}
		binding, err := digestContractValue("loom-resource-probe-credential-v3\x00", credential)
		if err != nil {
			return nil, err
		}
		diagnostic, err := TransportPrincipalID(view.NetworkID, resource.ID, view.DeviceID)
		if err != nil {
			return nil, err
		}
		spec := map[string]any{"policy_id": route.PolicyID, "device_id": view.DeviceID, "resource": resource, "dns_servers": append([]string{}, view.DNSServers...), "credential_digest": binding, "request": map[string]any{"operation": "admission_echo", "policy_id": route.PolicyID}}
		if resource.Kind == "wireguard" {
			spec["network_id"] = view.NetworkID
			source, err := WireGuardPacketSource(resource, wireGuardPublic)
			if err != nil {
				return nil, err
			}
			spec["source_address"] = source.String()
		}
		digest, err := digestContractValue("loom-resource-probe-spec-v3\x00", spec)
		if err != nil {
			return nil, err
		}
		probe := ResourceProbe{PolicyID: route.PolicyID, DiagnosticID: "entry:" + diagnostic, NetworkID: view.NetworkID, Resource: resource, Credential: credential, SpecDigest: digest}
		executions[resource.ID+"\x00"+route.PolicyID], result[route.ID] = probe, probe
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
