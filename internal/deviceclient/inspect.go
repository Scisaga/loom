package deviceclient

import "loom/internal/control"

// IdentityReadback returns the same identity before and after claim, without
// exporting its private key, capability, or private runtime configuration.
func (store *Store) IdentityReadback() (control.DeviceIdentityReadback, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	invite := store.state.Invite
	id, err := control.MaterialID(invite.Material)
	if err != nil {
		return control.DeviceIdentityReadback{}, err
	}
	payload := invite.Material.Payload.(control.Invite)
	value := control.DeviceIdentityReadback{
		NetworkID: invite.NetworkID, GenesisDigest: invite.GenesisDigest,
		DeviceID: payload.DeviceID, TransactionID: payload.ID, InviteMaterialID: id,
		ClaimRequestID: store.state.ClaimRequestID, DevicePublicKey: store.state.PublicKey,
		Platform: store.state.Platform, Joined: store.state.LKG != nil,
	}
	return value, value.Validate()
}
