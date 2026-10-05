package control

import "errors"

// DeviceIdentityReadback is a public, one-way inspection of a device's sole
// protected identity. It is neither authorization nor an installation receipt;
// Joined only says that this device has persisted a certified View.
type DeviceIdentityReadback struct {
	NetworkID        string `json:"network_id"`
	GenesisDigest    string `json:"genesis_digest"`
	DeviceID         string `json:"device_id"`
	TransactionID    string `json:"transaction_id"`
	InviteMaterialID string `json:"invite_material_id"`
	ClaimRequestID   string `json:"claim_request_id"`
	DevicePublicKey  string `json:"device_public_key"`
	Platform         string `json:"platform"`
	Joined           bool   `json:"joined"`
}

func (value DeviceIdentityReadback) Validate() error {
	if ValidateID(value.NetworkID) != nil || ValidateDigest(value.GenesisDigest) != nil ||
		ValidateID(value.DeviceID) != nil || ValidateID(value.TransactionID) != nil ||
		ValidateDigest(value.InviteMaterialID) != nil || ValidateID(value.ClaimRequestID) != nil ||
		ValidatePublicKey(value.DevicePublicKey) != nil || !validatePlatform(value.Platform) {
		return errors.New("device identity inspection is invalid")
	}
	return nil
}

// InstallationReadback is an instantaneous, read-only check of the target and
// the exact candidate package. A later installation repeats these checks under
// its existing exclusive lock; this value never authorizes a device or update.
type InstallationReadback struct {
	Platform           string                  `json:"platform"`
	Architecture       string                  `json:"architecture"`
	Identity           *DeviceIdentityReadback `json:"identity,omitempty"`
	AcceptedGeneration *U64                    `json:"accepted_generation,omitempty"`
	CanInstall         bool                    `json:"can_install"`
	ErrorCode          string                  `json:"error_code,omitempty"`
}

func (value InstallationReadback) Validate() error {
	if value.Platform != "linux" || value.Architecture != "amd64" && value.Architecture != "arm64" ||
		value.Identity != nil && value.Identity.Validate() != nil ||
		value.AcceptedGeneration != nil && *value.AcceptedGeneration == 0 ||
		value.CanInstall != (value.ErrorCode == "") {
		return errors.New("installation inspection is invalid")
	}
	switch value.ErrorCode {
	case "", "existing_trust_differs", "existing_trust_unavailable", "existing_package_unverified", "package_would_rollback_or_equivocate", "existing_installation_unverified":
	default:
		return errors.New("installation inspection error code is undefined")
	}
	return nil
}
