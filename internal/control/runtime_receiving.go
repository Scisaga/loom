package control

import (
	"errors"
	"net/netip"
)

// ReceiverExecutionOptions is the sole native receiving projection shared by
// WG and Hy2. It is rebuilt from the accepted View, never separately persisted.
func ReceiverExecutionOptions(view DeviceView, resourceID string) (map[string]any, error) {
	var resource TransportResource
	for _, value := range view.Resources {
		if value.ID == resourceID {
			resource = value
		}
	}
	if resource.OwnerNodeID != view.DeviceID {
		return nil, errors.New("receiving resource is not owned by this node")
	}
	facts, err := executionFacts(view)
	if err != nil {
		return nil, err
	}
	credentials, err := executionCredentials(view)
	if err != nil {
		return nil, err
	}
	senderDigests, err := senderAuthenticationDigests(facts, credentials)
	if err != nil {
		return nil, err
	}
	policies := []any{}
	bindings := []any{}
	for _, policy := range view.Policies {
		if policy.Action != "allow" {
			continue
		}
		value, err := executionPolicyProjection(facts, policy)
		if err != nil {
			return nil, err
		}
		policies = append(policies, value)
	}
	if resource.Kind == "hysteria2" {
		for _, credential := range view.TransportCredentials {
			if credential.ResourceID != resourceID {
				continue
			}
			key, err := TransportCredentialUser(view.NetworkID, credential)
			if err != nil {
				return nil, err
			}
			bindings = append(bindings, map[string]any{"key": key, "sender_id": credential.SenderID})
		}
	} else {
		for _, peer := range facts.WireGuardPeers {
			if peer.ResourceID != resourceID {
				continue
			}
			source, err := WireGuardAccessAddress(resource, peer.PublicKey)
			if err != nil {
				return nil, err
			}
			bindings = append(bindings, map[string]any{"key": source.String(), "sender_id": peer.DeviceID})
		}
	}
	return map[string]any{"node_id": view.DeviceID, "responsibilities": view.Responsibilities, "sender_authentication_digests": senderDigests, "access_enabled": resource.Kind == "wireguard" && resource.AccessEnabled || resource.Kind == "hysteria2" && !resource.LinkOnly, "policies": policies, "bindings": bindings}, nil
}

func executionPolicyProjection(view DeviceExecution, policy NetworkPolicy) (map[string]any, error) {
	hop, err := HopPolicyProjection(view, policy)
	if err != nil {
		return nil, err
	}
	var service Service
	for _, value := range view.Services {
		if value.ID == policy.ServiceID {
			service = value
		}
	}
	forward, egress := "", ""
	if containsString(view.Responsibilities, "forward") {
		forward = ForwardSelectorTag(policy.ID)
	}
	if containsString(policyExitNodes(view, policy.ID), view.DeviceID) {
		egress = serviceEgressOutboundTag(service)
	}
	local := containsString(policyExitNodes(view, policy.ID), view.DeviceID) && (service.Kind == "internet" && containsString(view.Responsibilities, "internet_egress") && policy.permitsLocalEgress(view.DeviceID) || service.Kind == "local_network" && containsString(view.Responsibilities, "forward") && policy.EntryScope.Allows(view.DeviceID))
	value := map[string]any{"policy": hop, "forward_outbound": forward, "egress_outbound": egress, "public_internet": service.Kind == "internet", "allow_direct": service.Kind == "internet" && policy.AllowDirect != nil && *policy.AllowDirect, "local_egress": local}
	if service.LocalNetwork != nil {
		value["lan_prefix"] = service.LocalNetwork.VirtualPrefix
		records := map[string][]string{}
		for _, record := range view.DNSRecords {
			if record.ServiceID == service.ID {
				records[record.Name] = append([]string{}, record.Addresses...)
			}
		}
		if len(records) > 0 {
			value["lan_records"] = records
		}
	}
	if service.RestrictToProbeTargets != nil && *service.RestrictToProbeTargets {
		targets := []map[string]any{}
		for _, matcher := range service.TargetMatchers(view.DNSRecords...) {
			host := matcher.Value
			if matcher.Kind == "ip_prefix" {
				prefix, err := netip.ParsePrefix(host)
				if err != nil || prefix.Bits() != prefix.Addr().BitLen() {
					return nil, errors.New("restricted target must be exact")
				}
				host = prefix.Addr().String()
			}
			targets = append(targets, map[string]any{"host": host, "port": matcher.Port})
		}
		value["allowed_targets"] = targets
	}
	return value, nil
}
