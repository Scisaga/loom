package control

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
)

// WireGuardAccessPeer is a private execution projection of existing Service
// permissions, not a participant registry or an independently writable grant.
type WireGuardAccessPeer struct {
	ResourceID string `json:"resource_id"`
	DeviceID   string `json:"device_id"`
	PublicKey  string `json:"public_key"`
}

func (peer WireGuardAccessPeer) Validate() error {
	if ValidateID(peer.ResourceID) != nil || ValidateID(peer.DeviceID) != nil || peer.DeviceID == "direct" || validateWireGuardPublicKey(peer.PublicKey) != nil {
		return errors.New("WireGuard access peer identity is invalid")
	}
	return nil
}

func wireGuardPeerOrder(peer WireGuardAccessPeer) string {
	return peer.ResourceID + "\x00" + peer.DeviceID
}

func validateWireGuardPublicKey(encoded string) error {
	if ValidatePublicKey(encoded) != nil {
		return errors.New("WireGuard public key is not canonical")
	}
	value, _ := base64.RawURLEncoding.DecodeString(encoded)
	public, err := ecdh.X25519().NewPublicKey(value)
	if err != nil {
		return errors.New("WireGuard public key is invalid")
	}
	// Reject low-order public keys, which cannot establish an X25519 session.
	probe := [32]byte{1}
	private, _ := ecdh.X25519().NewPrivateKey(probe[:])
	if _, err := private.ECDH(public); err != nil {
		return errors.New("WireGuard public key cannot establish a session")
	}
	return nil
}

func WireGuardAccessTarget(resource TransportResource, resources map[string]TransportResource) (TransportResource, error) {
	target := resources[resource.AccessHY2ResourceID]
	if resource.AccessHY2ResourceID == "" || resource.Validate() != nil || target.Validate() != nil || target.Kind != "hysteria2" || target.LinkOnly || target.OwnerNodeID != resource.OwnerNodeID {
		return TransportResource{}, errors.New("WireGuard access has no authorized same-node Hy2 target")
	}
	if _, err := WGResourceAddress(resource); err != nil {
		return TransportResource{}, err
	}
	if err := validateWireGuardPublicKey(*resource.Authentication.PublicKey); err != nil {
		return TransportResource{}, err
	}
	return target, nil
}

// WireGuardAccessAddress is a pure, stable /128 projection. Empty peerKey
// denotes the receiver; it never allocates, persists, or widens an IP range.
func WireGuardAccessAddress(resource TransportResource, peerKey string) (netip.Addr, error) {
	if resource.Kind != "wireguard" || resource.Validate() != nil || resource.AccessHY2ResourceID == "" || validateWireGuardPublicKey(*resource.Authentication.PublicKey) != nil {
		return netip.Addr{}, errors.New("WireGuard access address has no valid resource")
	}
	if peerKey != "" && validateWireGuardPublicKey(peerKey) != nil {
		return netip.Addr{}, errors.New("WireGuard access address has no valid peer")
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

func wireGuardAccessTag(resourceID string) string { return "wg-access." + resourceID }

func deriveWireGuardAccess(network string, source DeviceAuthorization, resource TransportResource) (string, WireGuardAccessPeer, error) {
	if ValidateID(network) != nil || source.Validate() != nil || resource.Kind != "wireguard" || resource.Validate() != nil || resource.AccessHY2ResourceID == "" {
		return "", WireGuardAccessPeer{}, errors.New("WireGuard access derivation has invalid input")
	}
	digest, err := digestContractValue("loom-resource-auth-v3\x00", resource.Authentication)
	if err != nil {
		return "", WireGuardAccessPeer{}, err
	}
	info, err := CanonicalEncode(map[string]any{"network_id": network, "device_id": source.ID, "resource_id": resource.ID, "resource_auth_digest": digest, "receiver_node_id": resource.OwnerNodeID, "purpose": "wireguard-access"})
	if err != nil {
		return "", WireGuardAccessPeer{}, err
	}
	root, err := base64.RawURLEncoding.DecodeString(source.RuntimeKey)
	if err != nil || len(root) != 32 {
		return "", WireGuardAccessPeer{}, errors.New("WireGuard access root is invalid")
	}
	defer clear(root)
	key, err := hkdf.Key(sha256.New, root, []byte("loom-runtime-key-v3\x00"), string(info), 32)
	if err != nil {
		return "", WireGuardAccessPeer{}, err
	}
	defer clear(key)
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	private, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return "", WireGuardAccessPeer{}, errors.New("WireGuard access key derivation failed")
	}
	peer := WireGuardAccessPeer{ResourceID: resource.ID, DeviceID: source.ID, PublicKey: base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())}
	return base64.StdEncoding.EncodeToString(key), peer, nil
}

func wireGuardAccessPrivate(encoded string) (*ecdh.PrivateKey, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != encoded || key[0]&7 != 0 || key[31]&192 != 64 {
		return nil, errors.New("WireGuard access private key is not canonical")
	}
	defer clear(key)
	return ecdh.X25519().NewPrivateKey(key)
}

func wireGuardAccessOutbound(resource TransportResource, credential string) (map[string]any, error) {
	private, err := wireGuardAccessPrivate(credential)
	if err != nil {
		return nil, err
	}
	local, err := WireGuardAccessAddress(resource, base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()))
	if err != nil {
		return nil, err
	}
	remote, err := WireGuardAccessAddress(resource, "")
	if err != nil || local == remote {
		return nil, errors.New("WireGuard access addresses conflict")
	}
	public, _ := base64.RawURLEncoding.DecodeString(*resource.Authentication.PublicKey)
	return map[string]any{"type": "wireguard", "tag": wireGuardAccessTag(resource.ID), "system_interface": false,
		"private_key": credential, "local_address": []string{local.String() + "/128"},
		"peers": []any{map[string]any{"server": resource.DialHost, "server_port": resource.DialPort, "public_key": base64.StdEncoding.EncodeToString(public), "allowed_ips": []string{remote.String() + "/128"}}}}, nil
}

func validateWireGuardAccessPeers(view DeviceView, resources map[string]TransportResource, policies map[string]NetworkPolicy) error {
	if view.WireGuardPeers != nil && len(view.WireGuardPeers) == 0 {
		return errors.New("empty WireGuard access peers must be omitted")
	}
	wanted := map[string]bool{}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID != view.DeviceID || resource.AccessHY2ResourceID == "" {
			continue
		}
		if _, err := WireGuardAccessTarget(resource, resources); err != nil {
			continue
		}
		for _, credential := range view.InboundCredentials {
			if credential.ResourceID == resource.AccessHY2ResourceID && credential.DeviceID != view.DeviceID && policies[credential.PolicyID].EntryScope.Allows(view.DeviceID) {
				wanted[resource.ID+"\x00"+credential.DeviceID] = true
			}
		}
	}
	keys := map[string]bool{}
	addresses := map[netip.Addr]bool{}
	for _, resource := range view.Resources {
		if resource.Kind == "wireguard" {
			for _, text := range *resource.Authentication.LocalAddresses {
				prefix, _ := netip.ParsePrefix(text)
				addresses[prefix.Addr()] = true
			}
		}
	}
	for _, resource := range view.Resources {
		if resource.AccessHY2ResourceID != "" {
			address, err := WireGuardAccessAddress(resource, "")
			if err != nil || addresses[address] {
				return errors.New("WireGuard receiver address conflicts")
			}
			addresses[address] = true
		}
	}
	for index, peer := range view.WireGuardPeers {
		resource := resources[peer.ResourceID]
		order := wireGuardPeerOrder(peer)
		if peer.Validate() != nil || !wanted[order] || !containsString(view.Responsibilities, "forward") || index > 0 && wireGuardPeerOrder(view.WireGuardPeers[index-1]) >= order || keys[peer.PublicKey] || peer.PublicKey == *resource.Authentication.PublicKey {
			return errors.New("WireGuard peer has no unique current inbound permission")
		}
		address, err := WireGuardAccessAddress(resource, peer.PublicKey)
		if err != nil || addresses[address] {
			return errors.New("WireGuard peer address conflicts")
		}
		addresses[address], keys[peer.PublicKey] = true, true
		delete(wanted, order)
	}
	if len(wanted) != 0 {
		return errors.New("WireGuard access receiver is missing permitted peers")
	}
	return nil
}
