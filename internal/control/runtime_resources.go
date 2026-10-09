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
	return RouteCandidate{ID: id, SpecDigest: spec, Scope: service.Scope(), ServiceID: service.ID, FirstResourceID: resource.ID, NodeChain: []string{resource.OwnerNodeID}, LinkIDs: []string{}, FinalExit: resource.OwnerNodeID}, err
}

func inboundCredentialOrder(value InboundCredential) string {
	return strings.Join([]string{value.DeviceID, value.ServiceID, value.PolicyID, value.Candidate.ID, value.ResourceID, value.ReceiverNodeID, value.SenderID}, "\x00")
}

func InboundCredentialUser(value InboundCredential) (string, error) {
	if err := value.Validate(); err != nil {
		return "", err
	}
	return digestContractValue("loom-inbound-user-v3\x00", map[string]any{"device_id": value.DeviceID, "service_id": value.ServiceID, "policy_id": value.PolicyID, "candidate_id": value.Candidate.ID, "resource_id": value.ResourceID, "receiver_node_id": value.ReceiverNodeID, "sender_id": value.SenderID})
}

func InboundACLDigest(view DeviceView, resourceID string) (string, error) {
	values := []any{}
	for _, value := range view.InboundCredentials {
		if value.ResourceID == resourceID {
			values = append(values, value)
		}
	}
	for _, value := range view.WireGuardPeers {
		if value.ResourceID == resourceID {
			values = append(values, value)
		}
	}
	return digestContractValue("loom-inbound-acl-v3\x00", values)
}

// Private transport keys are the only inputs recovered from the signed
// profile. Every nonsecret execution field is rebuilt from the certified View.
func profileCredentials(view DeviceView) (map[string]string, error) {
	result := map[string]string{}
	if view.RuntimeProfile == nil {
		return result, nil
	}
	var document struct {
		Outbounds []struct {
			Type     string `json:"type"`
			Tag      string `json:"tag"`
			Password string `json:"password"`
		} `json:"outbounds"`
		Endpoints []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			PrivateKey string `json:"private_key"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(view.RuntimeProfile.Config), &document); err != nil {
		return nil, errors.New("runtime credential projection is invalid")
	}
	for _, outbound := range document.Outbounds {
		if outbound.Type != "hysteria2" {
			continue
		}
		if _, duplicate := result[outbound.Tag]; duplicate || ValidatePublicKey(outbound.Password) != nil {
			return nil, errors.New("runtime credentials are duplicated or invalid")
		}
		result[outbound.Tag] = outbound.Password
	}
	for _, endpoint := range document.Endpoints {
		if endpoint.Type != "wireguard" {
			return nil, errors.New("runtime endpoint is unsupported")
		}
		if _, duplicate := result[endpoint.Tag]; duplicate {
			return nil, errors.New("runtime sender keys are duplicated")
		}

		owned, hasOwned, err := ownedWireGuard(view.Resources, view.DeviceID)
		if err != nil {
			return nil, err
		}
		expectedTag := wireGuardSharedCredential
		if hasOwned {
			expectedTag = ResourceInboundTag(owned.ID)
		}
		if endpoint.Tag != expectedTag {
			return nil, errors.New("runtime WG endpoint is not shared")
		}
		if _, duplicate := result[wireGuardSharedCredential]; duplicate {
			return nil, errors.New("duplicate shared WG identity")
		}
		if hasOwned {
			if endpoint.PrivateKey != "" {
				return nil, errors.New("fixed WG private key must remain local")
			}
		} else {
			if _, err := wireGuardAccessPrivate(endpoint.PrivateKey); err != nil {
				return nil, err
			}
		}
		result[wireGuardSharedCredential] = endpoint.PrivateKey
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

func permissionPath(view DeviceView, permission InboundCredential) (transportPath, int, error) {
	var service Service
	var policy NetworkPolicy
	for _, value := range view.Services {
		if value.ID == permission.ServiceID {
			service = value
		}
	}
	for _, value := range view.Policies {
		if value.ID == permission.PolicyID {
			policy = value
		}
	}
	if permission.Validate() != nil || policy.Action != "allow" || policy.ValidateForService(service) != nil || !sameContractValue(service.TargetMatchers(view.DNSRecords...), permission.AllowedTargets) {
		return transportPath{}, 0, errors.New("inbound permission has no matching Service or Policy")
	}
	path, err := candidateTransportPath(view, permission.DeviceID, service, policy, permission.Candidate)
	if err != nil {
		return transportPath{}, 0, err
	}
	for i, resource := range path.hops {
		if resource.ID != permission.ResourceID {
			continue
		}
		want := pathPermission(path, i, permission.DeviceID, policy, service, permission.ExcludedTargets, view.DNSRecords...)
		if want.SenderID != permission.SenderID || want.ReceiverNodeID != permission.ReceiverNodeID {
			return transportPath{}, 0, errors.New("inbound permission skipped its exact predecessor")
		}
		return path, i, nil
	}
	return transportPath{}, 0, errors.New("inbound resource is outside the candidate")
}

func validateViewResources(view DeviceView) error {
	resources := map[string]TransportResource{}
	wgOwners := map[string]bool{}
	for i, resource := range view.Resources {
		if resource.Validate() != nil || validateCurrentTransportPayload(resource) != nil || (resource.Kind != "wireguard" && resource.Kind != "hysteria2") || i > 0 && view.Resources[i-1].ID >= resource.ID {
			return errors.New("view resources are invalid or not uniquely sorted")
		}
		if resource.OwnerNodeID == view.DeviceID && !containsString(view.Responsibilities, "internet_egress") && !containsString(view.Responsibilities, "forward") {
			return errors.New("owned resource has no serving responsibility")
		}
		if resource.Kind == "wireguard" {
			if wgOwners[resource.OwnerNodeID] {
				return errors.New("node has multiple WG resources; explicit consolidation required")
			}
			wgOwners[resource.OwnerNodeID] = true
		}
		resources[resource.ID] = resource
	}
	for i, link := range view.Links {
		if i > 0 && view.Links[i-1].ID >= link.ID {
			return errors.New("view Links are not uniquely sorted")
		}
		if _, _, _, err := linkResources(link, resources); err != nil {
			return err
		}
	}
	policies := map[string]NetworkPolicy{}
	for _, policy := range view.Policies {
		policies[policy.ID] = policy
	}
	passwords := map[string]bool{}
	for i, permission := range view.InboundCredentials {
		resource, exists := resources[permission.ResourceID]
		if !exists || permission.ReceiverNodeID != view.DeviceID || resource.OwnerNodeID != view.DeviceID || i > 0 && inboundCredentialOrder(view.InboundCredentials[i-1]) >= inboundCredentialOrder(permission) {
			return errors.New("inbound permission has no uniquely ordered owned receiver")
		}
		path, index, err := permissionPath(view, permission)
		if err != nil {
			return err
		}
		if index == len(path.hops)-1 {
			role := "internet_egress"
			if permission.Candidate.Scope == "local_network:"+permission.ServiceID {
				role = "forward"
			}
			if !containsString(view.Responsibilities, role) {
				return errors.New("final receiver lacks its Service endpoint responsibility")
			}
		} else if !containsString(view.Responsibilities, "forward") {
			return errors.New("intermediate receiver has no forwarding responsibility")
		}
		if resource.Kind == "hysteria2" {
			if index != 0 || path.local || permission.SenderID != permission.DeviceID || ValidatePublicKey(permission.Credential) != nil {
				return errors.New("Hy2 may only terminate a first-hop business session")
			}
			key := resource.ID + "\x00" + permission.Credential
			if passwords[key] {
				return errors.New("Hy2 resource has duplicated passwords")
			}
			passwords[key] = true
		} else if permission.Credential != "" {
			return errors.New("WireGuard permission cannot carry a proxy credential")
		}
	}
	return validateWireGuardAccessPeers(view, resources, policies)
}

func projectViewResources(projection Projection, view *DeviceView) (map[string]string, error) {
	services := executableServices(projection)
	policies := map[string]NetworkPolicy{}
	devices := map[string]DeviceAuthorization{}
	for _, value := range projection.NetworkIntent.Policies {
		policies[value.ID] = value
	}
	for _, value := range projection.DeviceAuthorizations {
		devices[value.ID] = value
	}
	allResources := []TransportResource{}
	resources := map[string]TransportResource{}
	for _, resource := range projection.NetworkIntent.Resources {
		if err := validateCurrentTransportPayload(resource); err != nil {
			return nil, errors.New("current resources require explicit forward replacement before a new View can be issued")
		}
		owner, found := devices[resource.OwnerNodeID]
		if !found || (!containsString(owner.Responsibilities, "internet_egress") && !containsString(owner.Responsibilities, "forward")) {
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
		if err := validateCurrentTransportPayload(link); err != nil {
			return nil, errors.New("current Links require explicit forward replacement before a new View can be issued")
		}
		if !containsString(devices[link.FromNodeID].Responsibilities, "forward") || (!containsString(devices[link.ToNodeID].Responsibilities, "forward") && !containsString(devices[link.ToNodeID].Responsibilities, "internet_egress")) {
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
	peers := map[string]WireGuardAccessPeer{}
	credentials := map[string]string{}
	view.Routes = []RouteCandidate{}
	for _, value := range view.Services {
		visibleServices[value.ID] = value
	}
	for _, value := range view.Policies {
		visiblePolicies[value.ID] = value
	}
	addLink := func(link NetworkLink) {
		visibleLinks[link.ID] = link
		visibleResources[link.FromResourceID] = resources[link.FromResourceID]
		visibleResources[link.ResourceID] = resources[link.ResourceID]
	}
	addSender := func(sender string, resource TransportResource) error {
		if view.DeviceID != sender && view.DeviceID != resource.OwnerNodeID {
			return nil
		}
		private, peer, err := deriveWireGuardAccess(projection.NetworkID, devices[sender], resource, allResources...)
		if err != nil {
			return err
		}

		if fixed, found, err := ownedWireGuard(allResources, sender); err != nil {
			return err
		} else if found {
			visibleResources[fixed.ID] = fixed
		}
		if view.DeviceID == sender {
			if prior, found := credentials[wireGuardSharedCredential]; found && prior != private {
				return errors.New("WG sender identity is ambiguous")
			}
			credentials[wireGuardSharedCredential] = private
		}
		if view.DeviceID == resource.OwnerNodeID {
			peers[wireGuardPeerOrder(peer)] = peer
		}
		return nil
	}
	for _, resource := range allResources {
		if resource.OwnerNodeID == view.DeviceID && (resource.Kind == "hysteria2" && !resource.LinkOnly || resource.Kind == "wireguard" && resource.AccessEnabled) {
			visibleResources[resource.ID] = resource
		}
	}
	for _, link := range links {
		if link.FromNodeID == view.DeviceID || link.ToNodeID == view.DeviceID {
			addLink(link)
			if err := addSender(link.FromNodeID, resources[link.ResourceID]); err != nil {
				return nil, err
			}
		}
	}
	for _, source := range projection.DeviceAuthorizations {
		if !containsString(source.Responsibilities, "access") {
			continue
		}
		for _, policyID := range source.PolicyIDs {
			policy, assigned := policies[policyID]
			service, present := services[policy.ServiceID]
			if !assigned || !present || policy.Action != "allow" || policy.ValidateForService(service) != nil {
				continue
			}
			if source.ID == view.DeviceID {
				exits := []string{}
				if policy.permitsDirect() {
					exits = append(exits, "direct")
				}
				if containsString(source.Responsibilities, "internet_egress") && policy.permitsLocalEgress(source.ID) {
					exits = append(exits, source.ID)
				}
				if service.LocalNetwork != nil && policy.permitsEndpoint(service, source.ID) && policy.EntryScope.Allows(source.ID) && containsString(source.Responsibilities, "forward") {
					exits = append(exits, source.ID)
				}
				for _, exit := range exits {
					candidate, err := localCandidate(service, policy, exit, view.DNSRecords...)
					if err != nil {
						return nil, err
					}
					view.Routes = append(view.Routes, candidate)
				}
			}
			paths, err := transportPaths(source.ID, containsString(source.Responsibilities, "forward"), service, policy, allResources, links, projectDNSRecords(projection.NetworkIntent.DNSRecords)...)
			if err != nil {
				return nil, err
			}
			excluded := []ServiceMatcher{}
			for _, otherID := range source.PolicyIDs {
				otherPolicy, ok := policies[otherID]
				otherService, exists := services[otherPolicy.ServiceID]
				if ok && exists && otherService.ID != service.ID {
					excluded = append(excluded, otherService.TargetMatchers()...)
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
				endpointRole := "internet_egress"
				if service.Kind == "local_network" {
					endpointRole = "forward"
				}
				if !containsString(devices[path.candidate.FinalExit].Responsibilities, endpointRole) {
					continue
				}
				valid := true
				for _, node := range path.candidate.NodeChain[:len(path.candidate.NodeChain)-1] {
					valid = valid && containsString(devices[node].Responsibilities, "forward")
				}
				if !valid {
					continue
				}
				visible := source.ID == view.DeviceID
				for _, hop := range path.hops {
					visible = visible || hop.OwnerNodeID == view.DeviceID
				}
				if !visible {
					continue
				}
				if source.ID == view.DeviceID {
					view.Routes = append(view.Routes, path.candidate)
				}
				for _, hop := range path.hops {
					visibleResources[hop.ID] = hop
				}
				for _, link := range path.links {
					addLink(link)
				}
				for index, resource := range path.hops {
					permission := pathPermission(path, index, source.ID, policy, service, unique, view.DNSRecords...)
					if resource.Kind == "wireguard" {
						if err := addSender(permission.SenderID, resource); err != nil {
							return nil, err
						}
					} else if source.ID == view.DeviceID || resource.OwnerNodeID == view.DeviceID {
						auth, err := digestContractValue("loom-resource-auth-v3\x00", resource.Authentication)
						if err != nil {
							return nil, err
						}
						root, err := base64.RawURLEncoding.DecodeString(source.RuntimeKey)
						if err != nil {
							return nil, errors.New("invalid credential root")
						}
						credential, err := DeriveServiceCredential(root, ServiceCredentialBinding{NetworkID: projection.NetworkID, DeviceID: source.ID, ServiceID: service.ID, PolicyID: policy.ID, ResourceID: resource.ID, ResourceAuthDigest: auth, ReceiverNodeID: resource.OwnerNodeID, Purpose: "service-auth", CandidateID: path.candidate.ID, SenderID: source.ID})
						clear(root)
						if err != nil {
							return nil, err
						}
						permission.Credential = credential
						if source.ID == view.DeviceID {
							credentials[path.candidate.ID] = credential
						}
					}
					if resource.OwnerNodeID == view.DeviceID {
						permissions[inboundCredentialOrder(permission)] = permission
						visibleServices[service.ID] = service
						visiblePolicies[policy.ID] = policy
					}
				}
			}
		}
	}
	view.Resources, view.Links, view.Services, view.Policies, view.InboundCredentials = []TransportResource{}, []NetworkLink{}, []Service{}, []NetworkPolicy{}, []InboundCredential{}
	view.WireGuardPeers = nil
	for _, value := range peers {
		view.WireGuardPeers = append(view.WireGuardPeers, value)
	}
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
	sort.Slice(view.WireGuardPeers, func(i, j int) bool {
		return wireGuardPeerOrder(view.WireGuardPeers[i]) < wireGuardPeerOrder(view.WireGuardPeers[j])
	})
	sort.Slice(view.Resources, func(i, j int) bool { return view.Resources[i].ID < view.Resources[j].ID })
	sort.Slice(view.Links, func(i, j int) bool { return view.Links[i].ID < view.Links[j].ID })
	sort.Slice(view.Services, func(i, j int) bool { return view.Services[i].ID < view.Services[j].ID })
	sort.Slice(view.Policies, func(i, j int) bool { return view.Policies[i].ID < view.Policies[j].ID })
	sort.Slice(view.Routes, func(i, j int) bool { return view.Routes[i].ID < view.Routes[j].ID })
	sort.Slice(view.InboundCredentials, func(i, j int) bool {
		return inboundCredentialOrder(view.InboundCredentials[i]) < inboundCredentialOrder(view.InboundCredentials[j])
	})
	return credentials, nil
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
