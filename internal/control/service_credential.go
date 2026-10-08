package control

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// ServiceCredentialBinding is the input of the pure credential derivation in
// docs/core/current-contract.md#资源与用途隔离凭据. It is not an authorization:
// callers must obtain every reference from the effective allow projection.
// Names, unrelated policy assignments, and dial coordinates are intentionally
// absent, so changing them cannot rotate an otherwise unchanged credential.
type ServiceCredentialBinding struct {
	NetworkID          string `json:"network_id"`
	DeviceID           string `json:"device_id"`
	ServiceID          string `json:"service_id"`
	PolicyID           string `json:"policy_id"`
	ResourceID         string `json:"resource_id"`
	ResourceAuthDigest string `json:"resource_auth_digest"`
	ReceiverNodeID     string `json:"receiver_node_id"`
	Purpose            string `json:"purpose"`
	CandidateID        string `json:"candidate_id"`
	SenderID           string `json:"sender_id"`
}

func (binding ServiceCredentialBinding) Validate() error {
	for _, id := range []string{binding.NetworkID, binding.DeviceID, binding.ServiceID,
		binding.PolicyID, binding.ResourceID, binding.ReceiverNodeID, binding.SenderID} {
		if err := ValidateID(id); err != nil {
			return errors.New("service credential binding has an invalid identity")
		}
	}
	if binding.DeviceID == "direct" || binding.ReceiverNodeID == "direct" ||
		ValidateDigest(binding.ResourceAuthDigest) != nil || ValidateDigest(binding.CandidateID) != nil || binding.SenderID != binding.DeviceID {
		return errors.New("service credential binding has an invalid recipient, purpose or authentication digest")
	}
	if binding.Purpose != "service-auth" {
		return errors.New("Hy2 credentials authorize a first-hop business request only")
	}
	return nil
}

// DeriveServiceCredential implements the single declared service-auth purpose.
// It grants nothing by itself. Revocation removes the value from both client
// and recipient projections; callers must not use this function as a fallback
// when an authorization or resource is absent.
func DeriveServiceCredential(runtimeKey []byte, binding ServiceCredentialBinding) (string, error) {
	if len(runtimeKey) != 32 {
		return "", errors.New("service credential root key must contain 32 bytes")
	}
	if err := binding.Validate(); err != nil {
		return "", err
	}
	info, err := CanonicalEncode(binding)
	if err != nil {
		return "", err
	}
	key, err := hkdf.Key(sha256.New, runtimeKey, []byte("loom-runtime-key-v3\x00"), string(info), 32)
	if err != nil {
		return "", err
	}
	defer clear(key)
	return base64.RawURLEncoding.EncodeToString(key), nil
}
