package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
)

// CheckTransportReplacement verifies the original signed schema 3 bytes only
// for an explicitly requested, one-time forward replacement. It never returns
// a historical View, regenerates its runtime, or admits it to current decoding.
func CheckTransportReplacement(previousBytes []byte, next DeviceViewEnvelope, trusted BootstrapInvite, highWater []FactFrontier) error {
	if err := VerifyDeviceViewEnvelope(next, trusted); err != nil {
		return err
	}
	parsed, err := parseContractJSON(previousBytes, ContractDecodeLimits{MaxBytes: 5 << 20, MaxDepth: 128, MaxItems: 1 << 20})
	if err != nil || !bytes.Equal(previousBytes, appendContractJSON(nil, parsed)) {
		return errors.New("historical envelope is not bounded canonical JSON")
	}
	object, ok := parsed.(map[string]any)
	if !ok {
		return errors.New("historical envelope is not an object")
	}
	view, ok := object["view"].(map[string]any)
	if !ok {
		return errors.New("historical envelope has no View")
	}
	// The old signed execution sections remain opaque evidence. Only the
	// identity, member proof and authenticated progress are compared. This
	// closed top-level boundary deliberately has no old executable DTO.
	known := map[string]bool{"link_probe_credentials": true}
	viewType := reflect.TypeFor[DeviceView]()
	for i := range viewType.NumField() {
		name, option, _ := strings.Cut(viewType.Field(i).Tag.Get("json"), ",")
		if name == "network_id" {
			known[name] = true
			continue
		}
		known[name] = true
		if _, found := view[name]; !found && option != "omitempty" {
			return errors.New("historical View field is missing")
		}
	}
	for name := range view {
		if !known[name] {
			return errors.New("unknown historical View field or already current View")
		}
	}
	if network, present := view["network_id"]; present {
		if network != trusted.NetworkID {
			return errors.New("historical View network differs")
		}
		// Recognize only the retired independent-session projection. Its JSON is
		// inspected as opaque evidence and is never returned to a runtime decoder.
		profile, ok := view["runtime_profile"].(map[string]any)
		config, _ := profile["config"].(string)
		var retired struct {
			Endpoints []struct {
				Type string `json:"type"`
				Tag  string `json:"tag"`
			} `json:"endpoints"`
			DNS struct {
				FakeIP struct {
					Range string `json:"inet6_range"`
				} `json:"fakeip"`
			} `json:"dns"`
		}
		recognized := false
		if ok && json.Unmarshal([]byte(config), &retired) == nil {
			recognized = retired.DNS.FakeIP.Range == "2001:db8:8000::/49"
			for _, endpoint := range retired.Endpoints {
				recognized = recognized || endpoint.Type == "wireguard" && strings.HasPrefix(endpoint.Tag, "wg-send.") && ValidateID(strings.TrimPrefix(endpoint.Tag, "wg-send.")) == nil
			}
		}
		if !recognized {
			return errors.New("historical View is not a retired WG projection")
		}
	}
	viewBody := appendContractJSON(nil, view)
	sum := sha256.Sum256(append([]byte("loom-device-view-digest-v3\x00"), viewBody...))
	if object["view_digest"] != "sha256:"+hex.EncodeToString(sum[:]) {
		return errors.New("historical View digest is invalid")
	}
	// Decode the unchanged envelope header with the current exact field set.
	// The replacement below is private scratch space, never signed or persisted.
	currentView, err := contractJSONValue(reflect.ValueOf(next.View))
	if err != nil {
		return err
	}
	object["view"] = currentView
	var previous DeviceViewEnvelope
	if err := assignContractJSON(object, reflect.ValueOf(&previous).Elem()); err != nil {
		return err
	}
	object["view"] = view
	previous.View = DeviceView{}
	for name, target := range map[string]any{
		"schema": &previous.View.Schema, "device_id": &previous.View.DeviceID,
		"device_public_key": &previous.View.DevicePublicKey, "platform": &previous.View.Platform,
		"responsibilities": &previous.View.Responsibilities, "endpoints": &previous.View.Endpoints,
	} {
		if err := DecodeCanonical(appendContractJSON(nil, view[name]), target, ContractDecodeLimits{MaxBytes: 5 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
			return err
		}
	}
	if previous.Schema != 3 || previous.View.Schema != 3 || previous.NetworkID != trusted.NetworkID || previous.GenesisDigest != trusted.GenesisDigest ||
		previous.View.DeviceID != trusted.Material.Payload.(Invite).DeviceID || ValidatePublicKey(previous.View.DevicePublicKey) != nil ||
		!validatePlatform(previous.View.Platform) || validateResponsibilities(previous.View.Responsibilities, true) != nil || validateFactFrontier(previous.FactFrontier) != nil {
		return errors.New("historical identity or authenticated progress is invalid")
	}
	config, err := VerifyControlProofExtension(previous.ControlProof, trusted.ControlProof, trusted.NetworkID, trusted.GenesisDigest)
	if err != nil {
		return err
	}
	member, found := proofMember(config, previous.IssuerControlID)
	keyID, err := KeyID(member.PublicKey)
	if !found || err != nil || keyID != previous.IssuerKeyID {
		return errors.New("historical signer is not a proven member")
	}
	proven := map[string]bool{}
	for _, member := range config.Members {
		id, _ := KeyID(member.PublicKey)
		proven[id] = true
	}
	for _, certificate := range previous.ControlProof.Successors {
		for _, seal := range certificate.Config.SealedKeys {
			if frontierFor(previous.FactFrontier, seal.KeyID) != seal {
				return errors.New("historical frontier differs from its certified seal")
			}
			proven[seal.KeyID] = true
		}
	}
	for _, prefix := range previous.FactFrontier {
		if !proven[prefix.KeyID] {
			return errors.New("historical frontier key is not proven")
		}
	}
	delete(object, "signature")
	key, _ := base64.RawURLEncoding.DecodeString(member.PublicKey)
	signature, err := base64.RawURLEncoding.DecodeString(previous.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != previous.Signature ||
		!ed25519.Verify(ed25519.PublicKey(key), append([]byte(deviceViewDomain), appendContractJSON(nil, object)...), signature) {
		return errors.New("historical envelope signature is invalid")
	}
	return CheckDeviceViewAdvance(next, previous, highWater)
}
