package control

import "net/netip"

// InvitationDNSRequired checks the existing execution preconditions before a
// new Invite is signed. Historical signed Invite values retain their meaning.
func InvitationDNSRequired(projection Projection, invite Invite) (bool, error) {
	named := func(host string) bool { _, err := netip.ParseAddr(host); return err != nil }
	if named(invite.Endpoint.Host) {
		return true, nil
	}
	for _, endpoint := range projection.EndpointGenerations {
		if endpoint.State != "serving" && endpoint.State != "draining" {
			continue
		}
		if _, member := proofMember(projection.Config, endpoint.OwnerControlID); member && containsString(endpoint.Modes, "device") && named(endpoint.Host) {
			return true, nil
		}
	}
	if websites, err := WebsiteEndpoints(projection); err == nil {
		for _, website := range websites {
			if named(website.Host) {
				return true, nil
			}
		}
	}
	if !containsString(invite.Responsibilities, "access") {
		return false, nil
	}
	resources := []TransportResource{}
	for _, resource := range projection.NetworkIntent.Resources {
		for _, owner := range projection.DeviceAuthorizations {
			if resource.OwnerNodeID == owner.ID && (containsString(owner.Responsibilities, "forward") || containsString(owner.Responsibilities, "internet_egress")) {
				resources = append(resources, resource)
				break
			}
		}
	}
	links, err := DerivedNetworkLinks(projection)
	if err != nil {
		return false, err
	}
	services := executableServices(projection)
	for _, policy := range projection.NetworkIntent.Policies {
		service, active := services[policy.ServiceID]
		if !active || !containsString(invite.PolicyIDs, policy.ID) || policy.Action != "allow" || policy.ValidateForService(service) != nil {
			continue
		}
		paths, err := transportPaths(invite.DeviceID, containsString(invite.Responsibilities, "forward"), service, policy, resources, links, projectDNSRecords(projection.NetworkIntent.DNSRecords)...)
		if err != nil {
			return false, err
		}
		for _, path := range paths {
			for _, resource := range path.hops {
				if resource.OwnerNodeID != invite.DeviceID && named(resource.DialHost) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}
