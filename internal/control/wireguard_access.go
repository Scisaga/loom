package control

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
	"sync"
)

// WireGuardAccessPeer identifies the actual sending device, including a
// forwarding node. It is a private permission projection with no own lifecycle.
type WireGuardAccessPeer struct {
	ResourceID string `json:"resource_id"`
	DeviceID   string `json:"device_id"`
	PublicKey  string `json:"public_key"`
}

func (peer WireGuardAccessPeer) Validate() error {
	if ValidateID(peer.ResourceID) != nil || ValidateID(peer.DeviceID) != nil || peer.DeviceID == "direct" || validateWireGuardPublicKey(peer.PublicKey) != nil {
		return errors.New("WireGuard sender identity is invalid")
	}
	return nil
}

func wireGuardPeerOrder(peer WireGuardAccessPeer) string {
	return peer.ResourceID + "\x00" + peer.DeviceID
}

// Only the immutable mathematical property of an exact canonical public key is
// reusable. This bounded, disposable set never stores identity or authorization.
var validWireGuardKeys = struct {
	sync.Mutex
	keys map[string]struct{}
}{keys: make(map[string]struct{})}

func validateWireGuardPublicKey(encoded string) error {
	if ValidatePublicKey(encoded) != nil {
		return errors.New("WireGuard public key is not canonical")
	}
	validWireGuardKeys.Lock()
	_, known := validWireGuardKeys.keys[encoded]
	validWireGuardKeys.Unlock()
	if known {
		return nil
	}
	value, _ := base64.RawURLEncoding.DecodeString(encoded)
	public, err := ecdh.X25519().NewPublicKey(value)
	if err != nil {
		return errors.New("WireGuard public key is invalid")
	}
	probe := [32]byte{1}
	private, _ := ecdh.X25519().NewPrivateKey(probe[:])
	if _, err := private.ECDH(public); err != nil {
		return errors.New("WireGuard public key cannot establish a session")
	}
	validWireGuardKeys.Lock()
	if len(validWireGuardKeys.keys) == 256 {
		clear(validWireGuardKeys.keys)
	}
	validWireGuardKeys.keys[encoded] = struct{}{}
	validWireGuardKeys.Unlock()
	return nil
}

// WireGuardAccessAddress identifies execution DNS (empty peerKey) or the
// sender's DNS-only base address. It never grants business or host access.
func WireGuardAccessAddress(resource TransportResource, peerKey string) (netip.Addr, error) {
	if resource.Kind != "wireguard" || resource.Validate() != nil || resource.AccessHY2ResourceID != "" || validateWireGuardPublicKey(*resource.Authentication.PublicKey) != nil {
		return netip.Addr{}, errors.New("WireGuard address requires an independent resource")
	}
	if peerKey != "" && validateWireGuardPublicKey(peerKey) != nil {
		return netip.Addr{}, errors.New("WireGuard sender is invalid")
	}
	body, err := CanonicalEncode(map[string]any{"resource_id": resource.ID, "receiver_node_id": resource.OwnerNodeID, "receiver_public_key": *resource.Authentication.PublicKey, "peer_public_key": peerKey})
	if err != nil {
		return netip.Addr{}, err
	}
	digest := sha256.Sum256(append([]byte("loom-wg-access-address-v3\x00"), body...))
	var address [16]byte
	copy(address[:], digest[:16])
	address[0] = 0xfd
	return netip.AddrFrom16(address), nil
}

// WireGuardPacketSource is the receiver-specific address of the actual sender.
func WireGuardPacketSource(resource TransportResource, publicKey string) (netip.Addr, error) {
	return WireGuardAccessAddress(resource, publicKey)
}

func deriveWireGuardAccess(network string, source DeviceAuthorization, resource TransportResource) (string, WireGuardAccessPeer, error) {
	if ValidateID(network) != nil || source.Validate() != nil || resource.Kind != "wireguard" || resource.Validate() != nil || resource.AccessHY2ResourceID != "" {
		return "", WireGuardAccessPeer{}, errors.New("WireGuard derivation has invalid input")
	}
	if validateWireGuardPublicKey(source.WireGuardPublicKey) != nil {
		return "", WireGuardAccessPeer{}, errors.New("WireGuard sender has no registered identity")
	}
	private, public, err := derivedWireGuardIdentity(network, source)
	if err != nil {
		return "", WireGuardAccessPeer{}, err
	}
	if public != source.WireGuardPublicKey {
		private = ""
	}
	return private, WireGuardAccessPeer{ResourceID: resource.ID, DeviceID: source.ID, PublicKey: source.WireGuardPublicKey}, nil
}

// DerivedWireGuardPublicKey is used by initial enrollment and explicit forward
// registration. Runtime permission projections must use the registered value.
func DerivedWireGuardPublicKey(network string, source DeviceAuthorization) (string, error) {
	_, public, err := derivedWireGuardIdentity(network, source)
	return public, err
}

func derivedWireGuardIdentity(network string, source DeviceAuthorization) (string, string, error) {
	if ValidateID(network) != nil || source.Validate() != nil {
		return "", "", errors.New("WireGuard identity derivation has invalid input")
	}
	info, err := CanonicalEncode(map[string]any{"network_id": network, "device_id": source.ID, "purpose": "wireguard-access"})
	if err != nil {
		return "", "", err
	}
	root, err := base64.RawURLEncoding.DecodeString(source.RuntimeKey)
	if err != nil || len(root) != 32 {
		return "", "", errors.New("WireGuard sender root is invalid")
	}
	defer clear(root)
	key, err := hkdf.Key(sha256.New, root, []byte("loom-runtime-key-v3\x00"), string(info), 32)
	if err != nil {
		return "", "", err
	}
	defer clear(key)
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	private, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return "", "", errors.New("WireGuard key derivation failed")
	}
	return base64.StdEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), nil
}

func wireGuardAccessPrivate(encoded string) (*ecdh.PrivateKey, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != encoded || key[0]&7 != 0 || key[31]&192 != 64 {
		return nil, errors.New("WireGuard sender private key is not canonical")
	}
	defer clear(key)
	return ecdh.X25519().NewPrivateKey(key)
}
