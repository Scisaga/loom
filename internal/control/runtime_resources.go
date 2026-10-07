package control

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sort"
	"strings"
)

func oneHopCandidate(service Service, policy NetworkPolicy, resource TransportResource, records ...DNSRecord) (RouteCandidate, error) {
	identity := map[string]any{"service_id": service.ID, "first_resource_id": resource.ID, "node_chain": []string{resource.OwnerNodeID}, "link_ids": []string{}, "final_exit": resource.OwnerNodeID}
	id, err := digestContractValue("loom-candidate-id-v3\x00", identity)
	if err != nil {
		return RouteCandidate{}, err
	}
	spec, err := digestContractValue("loom-candidate-spec-v3\x00", dnsCandidateSpec(map[string]any{"identity": identity, "service": service, "policy": policy, "resources": []TransportResource{resource}, "links": []NetworkLink{}}, service, records))
	return RouteCandidate{ID: id, SpecDigest: spec, Scope: "service:" + service.ID, ServiceID: service.ID, FirstResourceID: resource.ID,
		NodeChain: []string{resource.OwnerNodeID}, LinkIDs: []string{}, FinalExit: resource.OwnerNodeID}, err
}

func inboundCredentialOrder(value InboundCredential) string {
	key := strings.Join([]string{value.DeviceID, value.ServiceID, value.PolicyID, value.ResourceID, value.ReceiverNodeID}, "\x00")
	if value.RelayTarget != nil {
		key += "\x00" + value.RelayTarget.LinkID + "\x00" + value.RelayTarget.ResourceID
	}
	return key
}

// InboundCredentialUser is a disposable transport username, never an identity
// authority. Hash the closed binding rather than joining user-controlled IDs.
func InboundCredentialUser(value InboundCredential) (string, error) {
	if err := value.Validate(); err != nil {
		return "", err
	}
	binding := map[string]any{"device_id": value.DeviceID, "service_id": value.ServiceID, "policy_id": value.PolicyID, "resource_id": value.ResourceID, "receiver_node_id": value.ReceiverNodeID}
	if value.RelayTarget != nil {
		binding["relay_target"] = *value.RelayTarget
	}
	return digestContractValue("loom-inbound-user-v3\x00", binding)
}

func InboundACLDigest(view DeviceView, resourceID string) (string, error) {
	values := []any{}
	for _, value := range view.InboundCredentials {
		if value.ResourceID == resourceID {
			values = append(values, value)
		}
	}
	for _, value := range view.LinkProbeCredentials {
		for _, link := range view.Links {
			if link.ID == value.LinkID && link.ToNodeID == view.DeviceID && link.ProbeTarget.ResourceID == resourceID {
				values = append(values, value)
			}
		}
	}
	return digestContractValue("loom-inbound-acl-v3\x00", values)
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
			"certificate": certificates, "insecure": false, "disable_sni": false}}, nil
}

// Only private passwords are recovered from the certified execution value.
// Its full structure is subsequently compared with the unique authorization
// projection; no addresses, ACLs or route identities flow back from this input.
func profileCredentials(view DeviceView) (map[string]string, error) {
	result := map[string]string{}
	if view.RuntimeProfile == nil {
		return result, nil
	}
	var document struct {
		Outbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Password   string `json:"password"`
			PrivateKey string `json:"private_key"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(view.RuntimeProfile.Config), &document); err != nil {
		return nil, errors.New("runtime credential projection is invalid")
	}
	for _, outbound := range document.Outbounds {
		if outbound.Type == "hysteria2" {
			if _, duplicate := result[outbound.Tag]; duplicate || ValidatePublicKey(outbound.Password) != nil {
				return nil, errors.New("runtime credentials are duplicated or invalid")
			}
			result[outbound.Tag] = outbound.Password
		} else if outbound.Type == "wireguard" {
			if _, duplicate := result[outbound.Tag]; duplicate {
				return nil, errors.New("runtime credentials are duplicated")
			}
			if _, err := wireGuardAccessPrivate(outbound.PrivateKey); err != nil {
				return nil, err
			}
			result[outbound.Tag] = outbound.PrivateKey
		}
	}
	return result, nil
}

func sameContractValue(left, right any) bool {
	a, err := CanonicalEncode(left)
	if err != nil {
		return false
	}
	b, err := CanonicalEncode(right)
	return err == nil && bytes.Equal(a, b)
}

func validateViewResources(view DeviceView) error {
	resources := map[string]TransportResource{}
	for index, resource := range view.Resources {
		if resource.Validate() != nil || (resource.Kind != "hysteria2" && resource.Kind != "wireguard") || index > 0 && view.Resources[index-1].ID >= resource.ID {
			return errors.New("view resources are unsupported, invalid or not uniquely sorted")
		}
		if resource.OwnerNodeID == view.DeviceID && !containsString(view.Responsibilities, "internet_egress") && !containsString(view.Responsibilities, "forward") {
			return errors.New("local Hy2 resource has no egress responsibility")
		}
		if resource.OwnerNodeID != view.DeviceID && !containsString(view.Responsibilities, "access") && !containsString(view.Responsibilities, "forward") && !containsString(view.Responsibilities, "internet_egress") {
			return errors.New("remote resource has no access consumer")
		}
		resources[resource.ID] = resource
	}
	for index, link := range view.Links {
		if index > 0 && view.Links[index-1].ID >= link.ID {
			return errors.New("view Links are not uniquely sorted")
		}
		if _, _, _, err := linkResources(link, resources); err != nil {
			return err
		}
	}
	policies := map[string]NetworkPolicy{}
	services := map[string]Service{}
	for _, value := range view.Policies {
		policies[value.ID] = value
	}
	for _, value := range view.Services {
		services[value.ID] = value
	}
	passwords := map[string]bool{}
	for index, value := range view.InboundCredentials {
		resource, exists := resources[value.ResourceID]
		policy := policies[value.PolicyID]
		service := services[value.ServiceID]
		if value.Validate() != nil || index > 0 && inboundCredentialOrder(view.InboundCredentials[index-1]) >= inboundCredentialOrder(value) ||
			!exists || value.ReceiverNodeID != view.DeviceID || resource.OwnerNodeID != view.DeviceID || policy.ServiceID != value.ServiceID ||
			policy.Action != "allow" || !sameContractValue(service.Matchers, value.AllowedTargets) {
			return errors.New("inbound permission does not match its resource, Service or Policy")
		}
		if value.RelayTarget == nil {
			if !policy.ExitScope.Allows(view.DeviceID) || !containsString(view.Responsibilities, "internet_egress") {
				return errors.New("inbound permission has no final egress grant")
			}
		} else if _, _, err := RelayDialTarget(view, *value.RelayTarget, view.DeviceID); err != nil || !containsString(view.Responsibilities, "forward") {
			return errors.New("inbound relay permission has no forwarding transport")
		}
		key := value.ResourceID + "\x00" + value.Credential
		if passwords[key] {
			return errors.New("Hy2 resource has duplicate authentication passwords")
		}
		passwords[key] = true
	}
	if err := validateWireGuardAccessPeers(view, resources, policies); err != nil {
		return err
	}
	return validateLinkProbeCredentials(view, passwords)
}

// projectViewResources shares the exact allow projection between each access
// outbound and its receiver. It consumes roots only inside the control process.
func projectViewResources(projection Projection, view *DeviceView) (map[string]string, error) {
	services := map[string]Service{}
	policies := map[string]NetworkPolicy{}
	devices := map[string]DeviceAuthorization{}
	for _, value := range projection.NetworkIntent.Services {
		services[value.ID] = value
	}
	for _, value := range projection.NetworkIntent.Policies {
		policies[value.ID] = value
	}
	for _, value := range projection.DeviceAuthorizations {
		devices[value.ID] = value
	}
	allResources := []TransportResource{}
	resources := map[string]TransportResource{}
	for _, resource := range projection.NetworkIntent.Resources {
		owner, found := devices[resource.OwnerNodeID]
		if !found || resource.Kind == "hysteria2" && !containsString(owner.Responsibilities, "internet_egress") || resource.Kind == "wireguard" && !containsString(owner.Responsibilities, "forward") {
			continue
		}
		if resource.Kind != "hysteria2" && resource.Kind != "wireguard" {
			continue
		}
		if err := resource.Validate(); err != nil {
			return nil, err
		}
		resources[resource.ID] = resource
		allResources = append(allResources, resource)
	}
	links := []NetworkLink{}
	for _, link := range projection.NetworkIntent.Links {
		if !containsString(devices[link.FromNodeID].Responsibilities, "forward") || !containsString(devices[link.ToNodeID].Responsibilities, "forward") {
			continue
		}
		if _, _, _, err := linkResources(link, resources); err != nil {
			continue
		}
		links = append(links, link)
	}
	visibleResources := map[string]TransportResource{}
	visibleLinks := map[string]NetworkLink{}
	visibleServices := map[string]Service{}
	visiblePolicies := map[string]NetworkPolicy{}
	permissions := map[string]InboundCredential{}
	wireGuardPeers := map[string]WireGuardAccessPeer{}
	for _, value := range view.Services {
		visibleServices[value.ID] = value
	}
	for _, value := range view.Policies {
		visiblePolicies[value.ID] = value
	}
	addLink := func(link NetworkLink) {
		visibleLinks[link.ID] = link
		for _, id := range []string{link.FromResourceID, link.ResourceID, link.ProbeTarget.ResourceID} {
			visibleResources[id] = resources[id]
		}
	}
	for _, resource := range allResources {
		if resource.OwnerNodeID == view.DeviceID && resource.Kind == "hysteria2" {
			visibleResources[resource.ID] = resource
		}
	}
	// Existing relay resources also carry authenticated management traffic.
	// Their node ownership is independent of access Service assignment.
	view.LinkProbeCredentials = nil
	for _, link := range links {
		if link.FromNodeID == view.DeviceID || link.ToNodeID == view.DeviceID {
			addLink(link)
			value, err := deriveLinkProbeCredential(projection.NetworkID, devices[link.FromNodeID], link, resources[link.ProbeTarget.ResourceID])
			if err != nil {
				return nil, err
			}
			view.LinkProbeCredentials = append(view.LinkProbeCredentials, value)
		}
	}
	sort.Slice(view.LinkProbeCredentials, func(i, j int) bool { return view.LinkProbeCredentials[i].LinkID < view.LinkProbeCredentials[j].LinkID })
	credentials := map[string]string{}
	for _, source := range projection.DeviceAuthorizations {
		if !containsString(source.Responsibilities, "access") {
			continue
		}
		for _, policyID := range source.PolicyIDs {
			policy, assigned := policies[policyID]
			service, present := services[policy.ServiceID]
			if !assigned || !present || policy.Action != "allow" {
				continue
			}
			paths, err := transportPaths(source.ID, containsString(source.Responsibilities, "forward"), service, policy, allResources, links, projectDNSRecords(projection.NetworkIntent.DNSRecords)...)
			if err != nil {
				return nil, err
			}
			excluded := []ServiceMatcher{}
			for _, otherID := range source.PolicyIDs {
				otherPolicy, exists := policies[otherID]
				otherService, effective := services[otherPolicy.ServiceID]
				if exists && effective && otherService.ID != service.ID {
					excluded = append(excluded, otherService.Matchers...)
				}
			}
			sort.Slice(excluded, func(i, j int) bool { return serviceMatcherLess(excluded[i], excluded[j]) })
			unique := excluded[:0]
			for _, matcher := range excluded {
				if len(unique) == 0 || unique[len(unique)-1] != matcher {
					unique = append(unique, matcher)
				}
			}
			for _, path := range paths {
				visible := source.ID == view.DeviceID
				for _, hop := range path.hops {
					visible = visible || hop.OwnerNodeID == view.DeviceID
				}
				if !visible {
					continue
				}
				if path.accessWG != nil {
					visibleResources[path.accessWG.ID] = *path.accessWG
					if source.ID == view.DeviceID || path.accessWG.OwnerNodeID == view.DeviceID {
						private, peer, err := deriveWireGuardAccess(projection.NetworkID, source, *path.accessWG)
						if err != nil {
							return nil, err
						}
						if source.ID == view.DeviceID {
							credentials[wireGuardAccessTag(path.accessWG.ID)] = private
						}
						if path.accessWG.OwnerNodeID == view.DeviceID {
							wireGuardPeers[wireGuardPeerOrder(peer)] = peer
						}
					}
				}
				for _, hop := range path.hops {
					visibleResources[hop.ID] = hop
				}
				for _, link := range path.links {
					addLink(link)
				}
				for index, resource := range path.hops {
					if source.ID != view.DeviceID && resource.OwnerNodeID != view.DeviceID {
						continue
					}
					authDigest, err := digestContractValue("loom-resource-auth-v3\x00", resource.Authentication)
					if err != nil {
						return nil, err
					}
					binding := ServiceCredentialBinding{NetworkID: projection.NetworkID, DeviceID: source.ID, ServiceID: service.ID, PolicyID: policy.ID, ResourceID: resource.ID, ResourceAuthDigest: authDigest, ReceiverNodeID: resource.OwnerNodeID, Purpose: "service-auth"}
					if index < len(path.hops)-1 {
						linkIndex := index
						if path.local {
							linkIndex++
						}
						binding.Purpose = "relay-auth"
						binding.RelayTarget = &RelayTarget{LinkID: path.links[linkIndex].ID, ResourceID: path.hops[index+1].ID}
					}
					root, err := base64.RawURLEncoding.DecodeString(source.RuntimeKey)
					if err != nil {
						return nil, errors.New("device credential root is invalid")
					}
					credential, err := DeriveServiceCredential(root, binding)
					clear(root)
					if err != nil {
						return nil, err
					}
					if source.ID == view.DeviceID {
						credentials[pathHopTag(path, index)] = credential
					}
					if resource.OwnerNodeID == view.DeviceID {
						value := InboundCredential{DeviceID: source.ID, ServiceID: service.ID, PolicyID: policy.ID, ResourceID: resource.ID, ReceiverNodeID: resource.OwnerNodeID, Credential: credential, AllowedTargets: append([]ServiceMatcher{}, service.Matchers...), ExcludedTargets: unique, RelayTarget: binding.RelayTarget}
						permissions[inboundCredentialOrder(value)] = value
						visibleServices[service.ID], visiblePolicies[policy.ID] = service, policy
					}
				}
			}
		}
	}
	view.Resources, view.Links, view.Services, view.Policies, view.InboundCredentials = []TransportResource{}, []NetworkLink{}, []Service{}, []NetworkPolicy{}, []InboundCredential{}
	view.WireGuardPeers = nil
	for _, peer := range wireGuardPeers {
		view.WireGuardPeers = append(view.WireGuardPeers, peer)
	}
	sort.Slice(view.WireGuardPeers, func(i, j int) bool {
		return wireGuardPeerOrder(view.WireGuardPeers[i]) < wireGuardPeerOrder(view.WireGuardPeers[j])
	})
	for _, value := range visibleResources {
		view.Resources = append(view.Resources, value)
	}
	for _, value := range visibleLinks {
		view.Links = append(view.Links, value)
	}
	for _, value := range visibleServices {
		view.Services = append(view.Services, value)
	}
	for _, value := range visiblePolicies {
		view.Policies = append(view.Policies, value)
	}
	for _, value := range permissions {
		view.InboundCredentials = append(view.InboundCredentials, value)
	}
	sort.Slice(view.Resources, func(i, j int) bool { return view.Resources[i].ID < view.Resources[j].ID })
	sort.Slice(view.Links, func(i, j int) bool { return view.Links[i].ID < view.Links[j].ID })
	sort.Slice(view.Services, func(i, j int) bool { return view.Services[i].ID < view.Services[j].ID })
	sort.Slice(view.Policies, func(i, j int) bool { return view.Policies[i].ID < view.Policies[j].ID })
	sort.Slice(view.InboundCredentials, func(i, j int) bool {
		return inboundCredentialOrder(view.InboundCredentials[i]) < inboundCredentialOrder(view.InboundCredentials[j])
	})
	return credentials, nil
}
