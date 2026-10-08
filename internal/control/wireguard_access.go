package control

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
	"sort"
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

func validateWireGuardPublicKey(encoded string) error {
	if ValidatePublicKey(encoded) != nil {
		return errors.New("WireGuard public key is not canonical")
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

func WireGuardIPv4Prefix(network string, resource TransportResource) (netip.Prefix, error) {
	if ValidateID(network) != nil || resource.Kind != "wireguard" || resource.Validate() != nil || resource.AccessHY2ResourceID != "" {
		return netip.Prefix{}, errors.New("invalid WireGuard mapping binding")
	}
	body, err := CanonicalEncode(map[string]any{"network_id": network, "resource_id": resource.ID, "receiver_public_key": *resource.Authentication.PublicKey})
	if err != nil {
		return netip.Prefix{}, err
	}
	digest := sha256.Sum256(append([]byte("loom-wg-ipv4-prefix-v3\x00"), body...))
	var address [16]byte
	copy(address[:12], digest[:12])
	address[0] = 0xfd
	return netip.PrefixFrom(netip.AddrFrom16(address), 96), nil
}

func WireGuardPacketSource(network string, permission InboundCredential, publicKey string) (netip.Addr, error) {
	if ValidateID(network) != nil || permission.Validate() != nil || validateWireGuardPublicKey(publicKey) != nil {
		return netip.Addr{}, errors.New("invalid WireGuard business source binding")
	}
	body, err := CanonicalEncode(map[string]any{"network_id": network, "device_id": permission.DeviceID, "policy_id": permission.PolicyID, "candidate_id": permission.Candidate.ID, "resource_id": permission.ResourceID, "sender_public_key": publicKey})
	if err != nil {
		return netip.Addr{}, err
	}
	digest := sha256.Sum256(append([]byte("loom-wg-packet-source-v3\x00"), body...))
	var address [16]byte
	copy(address[:], digest[:16])
	address[0] = 0xfd
	return netip.AddrFrom16(address), nil
}

func WireGuardSenderTag(resourceID string) string { return "wg-send." + resourceID }
func wireGuardAccessTag(resourceID string) string { return WireGuardSenderTag(resourceID) }

func deriveWireGuardAccess(network string, source DeviceAuthorization, resource TransportResource) (string, WireGuardAccessPeer, error) {
	if ValidateID(network) != nil || source.Validate() != nil || resource.Kind != "wireguard" || resource.Validate() != nil || resource.AccessHY2ResourceID != "" {
		return "", WireGuardAccessPeer{}, errors.New("WireGuard derivation has invalid input")
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
		return "", WireGuardAccessPeer{}, errors.New("WireGuard sender root is invalid")
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
		return "", WireGuardAccessPeer{}, errors.New("WireGuard key derivation failed")
	}
	peer := WireGuardAccessPeer{ResourceID: resource.ID, DeviceID: source.ID, PublicKey: base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())}
	return base64.StdEncoding.EncodeToString(key), peer, nil
}

func wireGuardAccessPrivate(encoded string) (*ecdh.PrivateKey, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != encoded || key[0]&7 != 0 || key[31]&192 != 64 {
		return nil, errors.New("WireGuard sender private key is not canonical")
	}
	defer clear(key)
	return ecdh.X25519().NewPrivateKey(key)
}

func wireGuardSenderEndpoint(network string, resource TransportResource, credential string, addresses []string) (map[string]any, error) {
	private, err := wireGuardAccessPrivate(credential)
	if err != nil {
		return nil, err
	}
	base, err := WireGuardAccessAddress(resource, base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()))
	if err != nil {
		return nil, err
	}
	prefix, err := WireGuardIPv4Prefix(network, resource)
	if err != nil {
		return nil, err
	}
	addresses = append(append([]string{}, addresses...), base.String()+"/128")
	sort.Strings(addresses)
	for i, address := range addresses {
		if i > 0 && addresses[i-1] == address {
			return nil, errors.New("WireGuard source addresses conflict")
		}
	}
	public, _ := base64.RawURLEncoding.DecodeString(*resource.Authentication.PublicKey)
	return map[string]any{"type": "wireguard", "tag": WireGuardSenderTag(resource.ID), "system": false,
		"private_key": credential, "address": addresses, "inet4_mapped_prefix": prefix.String(),
		"peers": []any{map[string]any{"address": resource.DialHost, "port": resource.DialPort, "public_key": base64.StdEncoding.EncodeToString(public), "allowed_ips": []string{"::/0"}}}}, nil
}

func validateWireGuardAccessPeers(view DeviceView, resources map[string]TransportResource, policies map[string]NetworkPolicy) error {
	if view.WireGuardPeers != nil && len(view.WireGuardPeers) == 0 {
		return errors.New("empty WireGuard peers must be omitted")
	}
	wanted := map[string]bool{}
	for _, permission := range view.InboundCredentials {
		if resources[permission.ResourceID].Kind == "wireguard" {
			wanted[permission.ResourceID+"\x00"+permission.SenderID] = true
		}
	}
	for _, link := range view.Links {
		if link.ToNodeID == view.DeviceID {
			wanted[link.ResourceID+"\x00"+link.FromNodeID] = true
		}
	}
	keys := map[string]bool{}
	addresses := map[netip.Addr]bool{}
	for index, peer := range view.WireGuardPeers {
		resource := resources[peer.ResourceID]
		order := wireGuardPeerOrder(peer)
		if peer.Validate() != nil || !wanted[order] || resource.Kind != "wireguard" || resource.OwnerNodeID != view.DeviceID || peer.DeviceID == view.DeviceID ||
			index > 0 && wireGuardPeerOrder(view.WireGuardPeers[index-1]) >= order || keys[peer.PublicKey] || peer.PublicKey == *resource.Authentication.PublicKey {
			return errors.New("WireGuard peer has no unique current receiving permission")
		}
		base, err := WireGuardAccessAddress(resource, peer.PublicKey)
		if err != nil || addresses[base] {
			return errors.New("WireGuard sender base addresses conflict")
		}
		addresses[base], keys[peer.PublicKey] = true, true
		for _, permission := range view.InboundCredentials {
			if permission.ResourceID != peer.ResourceID || permission.SenderID != peer.DeviceID {
				continue
			}
			address, err := WireGuardPacketSource(view.NetworkID, permission, peer.PublicKey)
			if err != nil || addresses[address] {
				return errors.New("WireGuard business source addresses conflict")
			}
			addresses[address] = true
		}
		delete(wanted, order)
	}
	if len(wanted) != 0 {
		return errors.New("WireGuard receiver is missing an authorized sender")
	}
	return nil
}
