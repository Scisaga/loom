package control

// RuntimeExecutionDigest compares already authenticated Views. It excludes
// measurement configuration, device labels and expected release coordinates;
// every permission, transport and capture dependency remains in the digest.
// This is a deletable local comparison, never a signed authorization frontier.
func RuntimeExecutionDigest(view DeviceView) (string, error) {
	services := make([]Service, len(view.Services))
	for index, service := range view.Services {
		services[index] = executionService(service)
	}
	inputs := map[string]any{
		"schema": view.Schema, "network_id": view.NetworkID, "device_id": view.DeviceID,
		"runtime_required":  HasRuntime(view),
		"device_public_key": view.DevicePublicKey, "platform": view.Platform,
		"responsibilities": view.Responsibilities, "policy_ids": view.PolicyIDs,
		"services": services, "policies": view.Policies, "resources": view.Resources,
		"nodes": executionNodes(view), "endpoints": view.Endpoints,
		"web_endpoints": append([]EndpointGeneration{}, view.WebEndpoints...),
		"public_trust":  append([]PublicTrust{}, view.PublicTrust...),
		"dns_records":   append([]DNSRecord{}, view.DNSRecords...), "dns_servers": view.DNSServers,
		"transport_credentials": view.TransportCredentials,
		"wireguard_private_key": view.WireGuardPrivateKey,
		"wireguard_public_key":  view.WireGuardPublicKey,
	}
	return digestContractValue("loom-runtime-execution-v3\x00", inputs)
}

func executionNodes(view DeviceView) []ViewNode {
	values := append([]ViewNode{}, view.Nodes...)
	for i := range values {
		values[i].DNSServers = nil
	}
	return values
}
