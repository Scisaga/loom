package control

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"sort"
)

func sameContractValue(left, right any) bool {
	a, err := CanonicalEncode(left)
	if err != nil {
		return false
	}
	b, err := CanonicalEncode(right)
	return err == nil && bytes.Equal(a, b)
}

func HY2TrustPEM(resource TransportResource) ([]string, error) {
	if resource.Validate() != nil || resource.Kind != "hysteria2" {
		return nil, errors.New("resource has no valid Hy2 trust")
	}
	certificates := make([]string, 0, len(*resource.Authentication.CACertificates))
	for _, encoded := range *resource.Authentication.CACertificates {
		der, _ := base64.RawURLEncoding.DecodeString(encoded)
		certificates = append(certificates, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	}
	return certificates, nil
}

func hy2Outbound(candidate RouteCandidate, resource TransportResource, credential string) (map[string]any, error) {
	if ValidatePublicKey(credential) != nil {
		return nil, errors.New("Hy2 outbound has no canonical projected credential")
	}
	certificates, err := HY2TrustPEM(resource)
	if err != nil {
		return nil, err
	}
	return map[string]any{"type": "hysteria2", "tag": candidate.ID, "server": resource.DialHost, "server_port": resource.DialPort,
		"password": credential, "tls": map[string]any{"enabled": true, "server_name": *resource.Authentication.ServerName,
			"certificate": certificates}}, nil
}

// InboundACLDigest binds stable permissions, not transient recommendations or
// unrestricted probe URLs. It is a runtime readback, never another authority.
func InboundACLDigest(view DeviceView, resourceID string) (string, error) {
	credentials := []TransportCredential{}
	for _, value := range view.TransportCredentials {
		if value.ResourceID == resourceID {
			credentials = append(credentials, value)
		}
	}
	services := []Service{}
	for _, service := range view.Services {
		services = append(services, executionService(service))
	}
	return digestContractValue("loom-inbound-acl-v3\x00", map[string]any{"resource_id": resourceID, "nodes": executionNodes(view), "self_responsibilities": view.Responsibilities, "self_policy_ids": view.PolicyIDs, "services": services, "policies": view.Policies, "credentials": credentials})
}
func projectViewResources(projection Projection, view *DeviceView) error {
	devices := map[string]DeviceAuthorization{}
	for _, device := range projection.DeviceAuthorizations {
		devices[device.ID] = device
	}
	services := executableServices(projection)
	resources := []TransportResource{}
	for _, resource := range projection.NetworkIntent.Resources {
		if validateCurrentTransportPayload(resource) != nil {
			return errors.New("resource requires explicit forward replacement")
		}
		owner, found := devices[resource.OwnerNodeID]
		if !found || !containsString(owner.Responsibilities, "forward") && !containsString(owner.Responsibilities, "internet_egress") {
			continue
		}
		if resource.Validate() != nil {
			return errors.New("invalid current resource")
		}
		if resource.Kind == "wireguard" && owner.WireGuardPublicKey != *resource.Authentication.PublicKey {
			return errors.New("WG resource requires its registered owner identity")
		}
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	serving := containsString(view.Responsibilities, "forward") || containsString(view.Responsibilities, "internet_egress")
	relevant := map[string]bool{}
	usedServices := map[string]bool{}
	// Qualification comes from current device responsibilities, never names.
	for _, policy := range projection.NetworkIntent.Policies {
		service, found := services[policy.ServiceID]
		if !found || policy.ValidateForService(service) != nil {
			continue
		}
		final := policy.Action == "allow" && (service.Kind == "internet" && containsString(view.Responsibilities, "internet_egress") || service.Kind == "local_network" && containsString(view.Responsibilities, "forward")) && policy.permitsEndpoint(service, view.DeviceID)
		if containsString(view.PolicyIDs, policy.ID) || serving && policy.Action == "allow" && (final || containsString(view.Responsibilities, "forward") && (policy.EntryScope.Allows(view.DeviceID) || policy.RelayScope.Allows(view.DeviceID))) {
			relevant[policy.ID] = true
			usedServices[service.ID] = true
		}
	}
	view.Services = []Service{}
	view.Policies = []NetworkPolicy{}
	view.Resources = []TransportResource{}
	view.Nodes = []ViewNode{}
	view.TransportCredentials = []TransportCredential{}
	for _, service := range projection.NetworkIntent.Services {
		if usedServices[service.ID] {
			view.Services = append(view.Services, service)
		}
	}
	for _, policy := range projection.NetworkIntent.Policies {
		if relevant[policy.ID] {
			view.Policies = append(view.Policies, policy)
		}
	}
	sort.Slice(view.Services, func(i, j int) bool { return view.Services[i].ID < view.Services[j].ID })
	sort.Slice(view.Policies, func(i, j int) bool { return view.Policies[i].ID < view.Policies[j].ID })
	if containsString(view.Responsibilities, "access") || serving {
		view.Resources = resources
	}
	var wg *TransportResource
	for i := range view.Resources {
		if view.Resources[i].Kind == "wireguard" {
			wg = &view.Resources[i]
			break
		}
	}
	for _, device := range projection.DeviceAuthorizations {
		ids := []string{}
		for _, id := range device.PolicyIDs {
			if relevant[id] {
				ids = append(ids, id)
			}
		}
		visible := device.ID == view.DeviceID || containsString(device.Responsibilities, "forward") || containsString(device.Responsibilities, "internet_egress") || serving && containsString(device.Responsibilities, "access") && len(ids) > 0
		if !visible {
			continue
		}
		node := ViewNode{WireGuardPublicKey: device.WireGuardPublicKey, DNSServers: append([]string(nil), device.DNSServers...), ID: device.ID, Responsibilities: append([]string{}, device.Responsibilities...), PolicyIDs: ids}
		for _, member := range projection.Config.Members {
			if member.NodeID == device.ID && !containsString(node.Responsibilities, "control") {
				node.Responsibilities = append(node.Responsibilities, "control")
			}
		}
		sort.Strings(node.Responsibilities)
		if wg != nil && device.ID == view.DeviceID && device.WireGuardPublicKey != "" {
			private, _, err := deriveWireGuardAccess(view.NetworkID, device, *wg)
			if err != nil {
				return err
			}
			view.WireGuardPrivateKey = private
		}
		if device.ID != view.DeviceID {
			view.Nodes = append(view.Nodes, node)
		}
	}
	sort.Slice(view.Nodes, func(i, j int) bool { return view.Nodes[i].ID < view.Nodes[j].ID })
	facts, err := executionFacts(*view)
	if err != nil {
		return err
	}
	for _, resource := range view.Resources {
		if resource.Kind != "hysteria2" {
			continue
		}
		auth, err := digestContractValue("loom-resource-auth-v3\x00", resource.Authentication)
		if err != nil {
			return err
		}
		for id, node := range viewNodes(*view) {
			if id != view.DeviceID && resource.OwnerNodeID != view.DeviceID || !senderMayAuthenticate(facts, node, resource) {
				continue
			}
			source, found := devices[id]
			if !found {
				return errors.New("transport sender lacks its current identity material")
			}
			key, err := base64.RawURLEncoding.DecodeString(source.RuntimeKey)
			if err != nil {
				return err
			}
			credential, err := DeriveTransportCredential(key, TransportCredentialBinding{NetworkID: view.NetworkID, SenderID: id, ResourceID: resource.ID, ResourceAuthDigest: auth, ReceiverNodeID: resource.OwnerNodeID, Purpose: "transport-auth"})
			clear(key)
			if err != nil {
				return err
			}
			view.TransportCredentials = append(view.TransportCredentials, TransportCredential{ResourceID: resource.ID, SenderID: id, Credential: credential})
		}
	}
	sort.Slice(view.TransportCredentials, func(i, j int) bool {
		return transportCredentialOrder(view.TransportCredentials[i]) < transportCredentialOrder(view.TransportCredentials[j])
	})
	return nil
}
