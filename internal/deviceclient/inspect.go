package deviceclient

import "loom/internal/control"

// IdentityReadback returns the same identity before and after claim, without
// exporting its private key, capability, or private runtime configuration.
func (store *Store) IdentityReadback() (control.DeviceIdentityReadback, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state := store.state
	value := control.DeviceIdentityReadback{TransactionID: state.TransactionID(), ClaimRequestID: state.ClaimRequestID, DevicePublicKey: state.PublicKey, Platform: state.Platform, Joined: state.LKG != nil}
	if state.Invite == nil {
		value.GenesisDigest = state.InvitationReference.GenesisDigest
	} else {
		invite := state.Invite
		id, err := control.MaterialID(invite.Material)
		if err != nil {
			return control.DeviceIdentityReadback{}, err
		}
		value.NetworkID = invite.NetworkID
		value.GenesisDigest = invite.GenesisDigest
		value.DeviceID = invite.Material.Payload.(control.Invite).DeviceID
		value.InviteMaterialID = id
	}
	return value, value.Validate()
}
