package clientadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"loom/internal/control"
)

// ResourceObservationCacheLimit is the existing private report input bound.
// A cache cannot make more samples reportable than that original boundary.
const ResourceObservationCacheLimit = 8 << 20

// This is a deletable diagnostic projection, never a second identity or LKG.
type resourceObservationCache struct {
	Schema         int                   `json:"schema"`
	IdentityDigest string                `json:"identity_digest"`
	Observations   []control.Observation `json:"observations"`
}

func (cache resourceObservationCache) Validate() error {
	if cache.Schema != 3 || control.ValidateDigest(cache.IdentityDigest) != nil || cache.Observations == nil {
		return errors.New("resource observation cache is invalid")
	}
	for i, observation := range cache.Observations {
		if observation.Validate() != nil || observation.Level != "resource" ||
			observation.Result != "available" && observation.Result != "unavailable" ||
			i > 0 && (cache.Observations[i-1].ResourceID >= observation.ResourceID || cache.Observations[i-1].NetworkGeneration != observation.NetworkGeneration) {
			return errors.New("resource observation cache samples are invalid")
		}
	}
	return nil
}

func resourceCacheIdentity(lkg control.DeviceViewEnvelope) (string, error) {
	if control.ValidateID(lkg.NetworkID) != nil || control.ValidateDigest(lkg.GenesisDigest) != nil ||
		control.ValidateID(lkg.View.DeviceID) != nil || control.ValidatePublicKey(lkg.View.DevicePublicKey) != nil {
		return "", errors.New("resource cache has no accepted identity binding")
	}
	body, err := control.CanonicalEncode(map[string]any{
		"network_id": lkg.NetworkID, "genesis_digest": lkg.GenesisDigest,
		"device_id": lkg.View.DeviceID, "device_public_key": lkg.View.DevicePublicKey, "platform": lkg.View.Platform,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("loom-resource-observation-cache-v3\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// EncodeResourceObservations only saves samples authorized by the current View.
// It retains their original times; serialization is not another observation.
func EncodeResourceObservations(lkg control.DeviceViewEnvelope, observations []control.Observation) ([]byte, error) {
	identity, err := resourceCacheIdentity(lkg)
	if err != nil {
		return nil, err
	}
	cache := resourceObservationCache{Schema: 3, IdentityDigest: identity, Observations: append([]control.Observation{}, observations...)}
	if err := cache.Validate(); err != nil {
		return nil, err
	}
	probes, err := control.FirstHopProbes(lkg.View)
	if err != nil {
		return nil, err
	}
	if len(observations) > 0 && len(RetainResourceObservations(probes, observations, observations[0].NetworkGeneration)) != len(observations) {
		return nil, errors.New("resource cache sample is outside the current authorization")
	}
	body, err := control.CanonicalEncode(cache)
	if err == nil && len(body) > ResourceObservationCacheLimit {
		return nil, errors.New("resource observation cache exceeds its input boundary")
	}
	return body, err
}

// DecodeResourceObservations restores only exact current execution inputs.
// It does not accept a View, select a route, or extend any validity window.
func DecodeResourceObservations(body []byte, lkg control.DeviceViewEnvelope, generation string) ([]control.Observation, error) {
	identity, err := resourceCacheIdentity(lkg)
	if err != nil || control.ValidateID(generation) != nil {
		return nil, errors.New("resource cache recovery inputs are invalid")
	}
	var cache resourceObservationCache
	if err := control.DecodeCanonical(body, &cache, control.ContractDecodeLimits{MaxBytes: ResourceObservationCacheLimit, MaxDepth: 16, MaxItems: ResourceObservationCacheLimit}); err != nil {
		return nil, err
	}
	if err := cache.Validate(); err != nil {
		return nil, err
	}
	if cache.IdentityDigest != identity {
		return []control.Observation{}, nil
	}
	probes, err := control.FirstHopProbes(lkg.View)
	if err != nil {
		return nil, err
	}
	return RetainResourceObservations(probes, cache.Observations, generation), nil
}
