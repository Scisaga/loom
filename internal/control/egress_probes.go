package control

import (
	"sort"
)

// EgressProbe is a disposable measurement specification. Service consumers are
// deliberately absent from its identity; transport permissions remain separate.
type EgressProbe struct {
	Target         string `json:"target"`
	SpecDigest     string `json:"spec_digest"`
	PublicInternet bool   `json:"public_internet"`
}

func finalInternetServices(view DeviceView) []Service {
	if !containsString(view.Responsibilities, "internet_egress") {
		return []Service{}
	}
	allowed := map[string]bool{}
	for _, policy := range view.Policies {
		if policy.Action == "allow" && policy.ExitScope != nil && policy.ExitScope.Allows(view.DeviceID) {
			allowed[policy.ServiceID] = true
		}
	}
	result := []Service{}
	for _, service := range view.Services {
		if service.Kind == "internet" && allowed[service.ID] {
			result = append(result, service)
		}
	}
	return result
}

func hasEgressProbeDuty(view DeviceView) bool {
	for _, service := range finalInternetServices(view) {
		if len(service.ProbeURLs) > 0 {
			return true
		}
	}
	return false
}

func EgressProbes(view DeviceView) ([]EgressProbe, error) {
	bySpec := map[string]EgressProbe{}
	targetSpecs := map[string]string{}
	for _, service := range finalInternetServices(view) {
		for _, target := range service.ProbeURLs {
			// Exact request and resolver parameters form the measurement identity.
			// HTTPS duration is kept distinct from segment RTT.
			spec, measured := targetSpecs[target]
			if !measured {
				var err error
				spec, err = egressProbeSpec(view.NetworkID, view.DeviceID, target, view.DNSServers, service.IsPublicInternet())
				if err != nil {
					return nil, err
				}
				targetSpecs[target] = spec
			}

			bySpec[spec] = EgressProbe{Target: target, SpecDigest: spec, PublicInternet: service.IsPublicInternet()}
		}
	}
	result := make([]EgressProbe, 0, len(bySpec))
	for _, value := range bySpec {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SpecDigest < result[j].SpecDigest })
	return result, nil
}

// Kept byte-identical to EgressProbes; a query page projects one target only.
func egressProbeSpec(network, source, target string, dns []string, public bool) (string, error) {
	return digestContractValue("loom-egress-probe-v3\x00", map[string]any{"network_id": network, "source": source, "target": target, "action": "https_request", "method": "GET", "redirect": "none", "body_limit": 4096, "tls_minimum": "TLS1.2", "timeout_ms": 8000, "dns_servers": dns, "public_internet": public})
}
