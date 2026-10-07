package control

// This is a disposable identity projection for authentication and readback,
// never an ordinary permission or a value written to authoritative storage.
type projectedDeviceIdentity struct {
	ID              string
	Name            string
	DevicePublicKey string
	Platform        string
	TransactionID   string
}

func controlOnlyIdentity(projection Projection, id string) (projectedDeviceIdentity, bool) {
	member := false
	for _, value := range projection.Config.Members {
		if value.NodeID == id {
			member = true
		}
	}
	if !member {
		return projectedDeviceIdentity{}, false
	}
	if target, found := projection.CurrentTarget("device", id); found && target.Conflicted {
		return projectedDeviceIdentity{}, false
	}
	var identity projectedDeviceIdentity
	found := false
	for _, join := range projection.ControlJoins {
		for _, invite := range projection.Invites {
			if invite.ID != join.TransactionID || invite.DeviceID != id {
				continue
			}
			target, exists := projection.CurrentTarget("invite", invite.ID)
			if !exists || target.Deleted || target.Conflicted {
				return projectedDeviceIdentity{}, false
			}
			for _, binding := range projection.Bindings {
				if binding.TransactionID != invite.ID || binding.DevicePublicKey != join.DevicePublicKey || binding.InviteMaterialID != join.InviteMaterialID {
					continue
				}
				if found {
					return projectedDeviceIdentity{}, false
				}
				identity = projectedDeviceIdentity{ID: id, Name: invite.Name, DevicePublicKey: binding.DevicePublicKey, Platform: binding.Platform, TransactionID: invite.ID}
				found = true
			}
		}
	}
	// Genesis members had an independent device key and an ordinary first
	// binding. Revoking ordinary permissions does not revoke their membership.
	if !found {
		target, revoked := projection.CurrentTarget("device", id)
		if !revoked || !target.Deleted || target.DeviceForReview == nil {
			return identity, false
		}
		for _, member := range projection.Config.Members {
			if member.NodeID != id {
				continue
			}
			for _, invite := range projection.Invites {
				if invite.DeviceID != id || invite.IssuerControlID != member.ControlID || !containsString(invite.Responsibilities, "control") {
					continue
				}
				state, exists := projection.CurrentTarget("invite", invite.ID)
				if !exists || state.Deleted || state.Conflicted {
					continue
				}
				for _, binding := range projection.Bindings {
					if binding.TransactionID != invite.ID {
						continue
					}
					if found {
						return projectedDeviceIdentity{}, false
					}
					identity, found = projectedDeviceIdentity{ID: id, Name: target.DeviceForReview.Name, DevicePublicKey: binding.DevicePublicKey, Platform: binding.Platform, TransactionID: invite.ID}, true
				}
			}
		}
	}
	return identity, found
}

func memberBindingFor(projection Projection, id string) (ControlJoinBinding, bool) {
	identity, found := controlOnlyIdentity(projection, id)
	if !found {
		return ControlJoinBinding{}, false
	}
	for _, join := range projection.ControlJoins {
		if join.TransactionID == identity.TransactionID {
			return join, true
		}
	}
	return ControlJoinBinding{}, false
}

func identityFor(projection Projection, id string) (projectedDeviceIdentity, bool) {
	if authorization, found := authorizationFor(projection, id); found {
		return projectedDeviceIdentity{ID: authorization.ID, Name: authorization.Name, DevicePublicKey: authorization.DevicePublicKey, Platform: authorization.Platform, TransactionID: authorization.TransactionID}, true
	}
	return controlOnlyIdentity(projection, id)
}
