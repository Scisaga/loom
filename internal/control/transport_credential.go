package control

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// A stable authenticated sender/resource binding, never a complete
// route, measurement or independently issued authorization object.
type TransportCredentialBinding struct {
	NetworkID          string `json:"network_id"`
	SenderID           string `json:"sender_id"`
	ResourceID         string `json:"resource_id"`
	ResourceAuthDigest string `json:"resource_auth_digest"`
	ReceiverNodeID     string `json:"receiver_node_id"`
	Purpose            string `json:"purpose"`
}

func (binding TransportCredentialBinding) Validate() error {
	for _, id := range []string{binding.NetworkID, binding.SenderID, binding.ResourceID, binding.ReceiverNodeID} {
		if ValidateID(id) != nil || id == "direct" {
			return errors.New("service credential binding has an invalid identity")
		}
	}
	if binding.SenderID == binding.ReceiverNodeID || ValidateDigest(binding.ResourceAuthDigest) != nil || binding.Purpose != "transport-auth" {
		return errors.New("service credential has an invalid receiving purpose or authentication")
	}
	return nil
}
func DeriveTransportCredential(runtimeKey []byte, binding TransportCredentialBinding) (string, error) {
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
