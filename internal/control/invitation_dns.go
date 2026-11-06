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
	// Optional data resources resolve lazily when used. They must not make QR
	// generation or identity binding depend on every candidate's DNS readiness.
	return false, nil
}
