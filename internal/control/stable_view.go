package control

import (
	"encoding/base64"
	"errors"
	"sort"
)

func viewNodes(view DeviceView) map[string]ViewNode {
	values := make(map[string]ViewNode, len(view.Nodes)+1)
	self := ViewNode{WireGuardPublicKey: view.WireGuardPublicKey, DNSServers: view.DNSServers, ID: view.DeviceID, Responsibilities: view.Responsibilities, PolicyIDs: view.PolicyIDs}
	values[self.ID] = self
	for _, node := range view.Nodes {
		values[node.ID] = node
	}
	return values
}
func transportCredentialOrder(value TransportCredential) string {
	return value.ResourceID + "\x00" + value.SenderID
}
func TransportCredentialUser(network string, value TransportCredential) (string, error) {
	if ValidateID(network) != nil || value.Validate() != nil {
		return "", errors.New("invalid transport username input")
	}
	return TransportPrincipalID(network, value.ResourceID, value.SenderID)
}
func executionCredentials(view DeviceView) (map[string]string, error) {
	values := map[string]string{}
	for _, value := range view.TransportCredentials {
		if value.SenderID == view.DeviceID {
			values[value.ResourceID] = value.Credential
		}
	}
	if view.WireGuardPrivateKey != "" {
		values[wireGuardSharedCredential] = view.WireGuardPrivateKey
	}
	return values, nil
}
func stableExits(view DeviceView, policy NetworkPolicy, service Service) []string {
	values := []string{}
	if policy.Action != "allow" || service.LocalNetwork != nil && !service.LocalNetwork.Enabled {
		return values
	}
	role := "internet_egress"
	if service.Kind == "local_network" {
		role = "forward"
	}
	for id, node := range viewNodes(view) {
		if containsString(node.Responsibilities, role) && policy.permitsEndpoint(service, id) {
			values = append(values, id)
		}
	}
	sort.Strings(values)
	return values
}
func executionFacts(view DeviceView) (DeviceExecution, error) {
	value := DeviceExecution{DeviceView: view, SelectedPolicyIDs: []string{}, Routes: []RouteCandidate{}, BusinessProbeTargets: []ServiceProbeTargets{}, Links: []NetworkLink{}}
	services := map[string]Service{}
	for _, s := range view.Services {
		services[s.ID] = s
	}
	nodes := viewNodes(view)
	for _, policy := range view.Policies {
		if policy.Action == "allow" {
			value.PolicyExits = append(value.PolicyExits, PolicyExits{policy.ID, stableExits(view, policy, services[policy.ServiceID])})
		}
		for id, node := range nodes {
			if containsString(node.Responsibilities, "access") && containsString(node.PolicyIDs, policy.ID) && policy.Action == "allow" {
				value.AccessGrants = append(value.AccessGrants, AccessGrant{id, policy.ID})
			}
		}
	}
	sort.Slice(value.AccessGrants, func(i, j int) bool {
		a, b := value.AccessGrants[i], value.AccessGrants[j]
		return a.DeviceID < b.DeviceID || a.DeviceID == b.DeviceID && a.PolicyID < b.PolicyID
	})
	links, err := viewNetworkLinks(view)
	if err != nil {
		return DeviceExecution{}, err
	}
	value.Links = links
	for _, resource := range view.Resources {
		if resource.OwnerNodeID != view.DeviceID || resource.Kind != "wireguard" {
			continue
		}
		for id, node := range nodes {
			if id != view.DeviceID && node.WireGuardPublicKey != "" && senderMayAuthenticate(value, node, resource) {
				value.WireGuardPeers = append(value.WireGuardPeers, WireGuardAccessPeer{ResourceID: resource.ID, DeviceID: id, PublicKey: node.WireGuardPublicKey})
			}
		}
	}
	sort.Slice(value.WireGuardPeers, func(i, j int) bool {
		return wireGuardPeerOrder(value.WireGuardPeers[i]) < wireGuardPeerOrder(value.WireGuardPeers[j])
	})
	for _, service := range view.Services {
		for _, policy := range view.Policies {
			if policy.ServiceID == service.ID && policy.Action == "allow" && containsString(view.PolicyIDs, policy.ID) {
				value.BusinessProbeTargets = append(value.BusinessProbeTargets, ServiceProbeTargets{ServiceID: service.ID, Targets: service.ProbeURLsOrEmpty()})
				break
			}
		}
	}
	return value, nil
}
func senderMayAuthenticate(view DeviceExecution, sender ViewNode, resource TransportResource) bool {
	if resource.Kind == "wireguard" && sender.WireGuardPublicKey == "" {
		return false
	}
	if sender.ID == resource.OwnerNodeID {
		return false
	}
	if containsString(sender.Responsibilities, "forward") {
		return true
	}
	if !containsString(sender.Responsibilities, "access") || resource.Kind == "wireguard" && !resource.AccessEnabled || resource.Kind == "hysteria2" && resource.LinkOnly {
		return false
	}
	for _, policy := range view.Policies {
		if policy.Action == "allow" && containsString(sender.PolicyIDs, policy.ID) && policy.EntryScope.Allows(resource.OwnerNodeID) && policyCanReceive(view, policy, resource.OwnerNodeID) {
			return true
		}
	}
	return false
}
func validateStableView(view DeviceView) error {
	if view.WireGuardPublicKey != "" && validateWireGuardPublicKey(view.WireGuardPublicKey) != nil {
		return errors.New("View has an invalid registered WireGuard identity")
	}
	services, _, err := servicePermissionValues(view)
	if err != nil {
		return err
	}
	for i, node := range view.Nodes {
		if node.DNSServers != nil && len(node.DNSServers) == 0 || validateDeviceDNS(node.DNSServers) != nil || ValidateID(node.ID) != nil || node.ID == "direct" || node.ID == view.DeviceID || validateResponsibilities(node.Responsibilities, true) != nil || validateIDSet(node.PolicyIDs) != nil || !containsString(node.Responsibilities, "access") && len(node.PolicyIDs) > 0 || node.WireGuardPublicKey != "" && validateWireGuardPublicKey(node.WireGuardPublicKey) != nil || i > 0 && view.Nodes[i-1].ID >= node.ID {
			return errors.New("invalid public node authorization projection")
		}
	}
	nodes := viewNodes(view)
	wgKeys := map[string]string{}
	for id, node := range nodes {
		if node.WireGuardPublicKey == "" {
			continue
		}
		if prior, found := wgKeys[node.WireGuardPublicKey]; found && prior != id {
			return errors.New("ambiguous WG sender identity")
		}
		wgKeys[node.WireGuardPublicKey] = id
	}
	resources := map[string]TransportResource{}
	wgOwners := map[string]bool{}
	for i, resource := range view.Resources {
		owner, found := nodes[resource.OwnerNodeID]
		if resource.Validate() != nil || validateCurrentTransportPayload(resource) != nil || !found || !containsString(owner.Responsibilities, "forward") && !containsString(owner.Responsibilities, "internet_egress") || i > 0 && view.Resources[i-1].ID >= resource.ID {
			return errors.New("invalid or unqualified View resource")
		}
		if resource.Kind == "wireguard" {
			if wgOwners[owner.ID] || owner.WireGuardPublicKey != *resource.Authentication.PublicKey {
				return errors.New("WG resource differs from its stable node identity")
			}
			wgOwners[owner.ID] = true
		}
		resources[resource.ID] = resource
	}
	if view.WireGuardPrivateKey != "" {
		private, err := wireGuardAccessPrivate(view.WireGuardPrivateKey)
		if err != nil || base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()) != view.WireGuardPublicKey {
			return errors.New("WG private material differs from the registered identity")
		}
	}
	passwords := map[string]bool{}
	credentials := map[string]bool{}
	for i, value := range view.TransportCredentials {
		resource, found := resources[value.ResourceID]
		sender, known := nodes[value.SenderID]
		if value.Validate() != nil || !found || !known || resource.Kind != "hysteria2" || sender.ID == resource.OwnerNodeID || resource.OwnerNodeID != view.DeviceID && sender.ID != view.DeviceID || i > 0 && transportCredentialOrder(view.TransportCredentials[i-1]) >= transportCredentialOrder(value) {
			return errors.New("transport credential is outside this View's actual sender/resource boundary")
		}
		key := value.ResourceID + "\x00" + value.Credential
		if passwords[key] {
			return errors.New("duplicated authenticated transport secret")
		}
		passwords[key] = true
		credentials[transportCredentialOrder(value)] = true
	}
	facts, err := executionFacts(view)
	if err != nil {
		return err
	}
	for _, resource := range view.Resources {
		if resource.Kind != "hysteria2" {
			continue
		}
		for _, sender := range nodes {
			if resource.OwnerNodeID != view.DeviceID && sender.ID != view.DeviceID {
				continue
			}
			wanted := senderMayAuthenticate(facts, sender, resource)
			if credentials[resource.ID+"\x00"+sender.ID] != wanted {
				return errors.New("transport authentication projection is incomplete or unqualified")
			}
		}
	}
	for _, policy := range view.Policies {
		if service, exists := services[policy.ServiceID]; exists && policy.ValidateForService(service) != nil {
			return errors.New("Policy differs from its Service kind")
		}
	}
	for i, value := range view.ExpectedComponents {
		if value.Validate() != nil || i > 0 && (view.ExpectedComponents[i-1].ComponentID > value.ComponentID || view.ExpectedComponents[i-1].ComponentID == value.ComponentID && view.ExpectedComponents[i-1].Platform >= value.Platform) {
			return errors.New("expected components are invalid or unsorted")
		}
	}
	return nil
}

func TransportPrincipalID(network, resource, sender string) (string, error) {
	if ValidateID(network) != nil || ValidateID(resource) != nil || ValidateID(sender) != nil {
		return "", errors.New("invalid transport principal")
	}
	return digestContractValue("loom-inbound-user-v3\x00", map[string]any{"network_id": network, "resource_id": resource, "sender_id": sender})
}

// HasRuntime depends on actual responsibilities/resources and measurement I/O,
// never the presence of a signed or cached JSON runtime blob.
func HasRuntime(view DeviceView) bool {
	if containsString(view.Responsibilities, "access") {
		return true
	}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID == view.DeviceID {
			return true
		}
	}
	return hasEgressProbeDuty(view)
}
