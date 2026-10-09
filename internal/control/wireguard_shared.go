package control

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
	"sort"
)

const wireGuardSharedCredential = "wg-shared"

func ownedWireGuard(resources []TransportResource, node string) (TransportResource, bool, error) {
	var result TransportResource
	found := false
	for _, resource := range resources {
		if resource.Kind != "wireguard" || resource.OwnerNodeID != node {
			continue
		}
		if found {
			return TransportResource{}, false, errors.New("node WireGuard resources require explicit consolidation")
		}
		result, found = resource, true
	}
	return result, found, nil
}

func WireGuardTargetPrefix(network string, resource TransportResource) (netip.Prefix, error) {
	if ValidateID(network) != nil || resource.Kind != "wireguard" || resource.Validate() != nil || resource.AccessHY2ResourceID != "" {
		return netip.Prefix{}, errors.New("invalid WireGuard target pool binding")
	}
	body, err := CanonicalEncode(map[string]any{"network_id": network, "resource_id": resource.ID, "receiver_public_key": *resource.Authentication.PublicKey})
	if err != nil {
		return netip.Prefix{}, err
	}
	digest := sha256.Sum256(append([]byte("loom-wg-target-prefix-v3\x00"), body...))
	var address [16]byte
	copy(address[:8], digest[:8])
	address[0] = 0xfd
	return netip.PrefixFrom(netip.AddrFrom16(address), 64), nil
}

func sharedWireGuardIdentity(view DeviceView, credentials map[string]string) (string, string, error) {
	resource, found, err := ownedWireGuard(view.Resources, view.DeviceID)
	if err != nil {
		return "", "", err
	}
	if found {
		return ResourceInboundTag(resource.ID), *resource.Authentication.PublicKey, nil
	}
	private, err := wireGuardAccessPrivate(credentials[wireGuardSharedCredential])
	if err != nil {
		return "", "", err
	}
	return wireGuardSharedCredential, base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), nil
}

// The temporary peer accumulator is discarded after rendering. Resource and
// permission facts remain the only source of keys, addresses and directions.
func sharedWireGuardEndpoint(view DeviceView, credentials map[string]string, sources map[string]map[string]bool) (map[string]any, error) {
	tag, public, err := sharedWireGuardIdentity(view, credentials)
	if err != nil {
		return nil, err
	}
	owned, hasOwned, err := ownedWireGuard(view.Resources, view.DeviceID)
	if err != nil {
		return nil, err
	}
	resources := map[string]TransportResource{}
	for _, resource := range view.Resources {
		resources[resource.ID] = resource
	}
	type peerValue struct {
		value     map[string]any
		allowed   map[string]bool
		direction string
	}
	peers := map[string]*peerValue{}
	peerFor := func(key string) *peerValue {
		if p := peers[key]; p != nil {
			return p
		}
		bytes, _ := base64.RawURLEncoding.DecodeString(key)
		p := &peerValue{value: map[string]any{"public_key": base64.StdEncoding.EncodeToString(bytes)}, allowed: map[string]bool{}}
		peers[key] = p
		return p
	}
	addresses := map[string]bool{}
	if hasOwned {
		dns, err := WireGuardAccessAddress(owned, "")
		if err != nil {
			return nil, err
		}
		addresses[dns.String()+"/128"] = true
	}
	for _, link := range view.Links {
		if link.FromNodeID != view.DeviceID && link.ToNodeID != view.DeviceID {
			continue
		}
		local, remote := resources[link.FromResourceID], resources[link.ResourceID]
		if link.ToNodeID == view.DeviceID {
			local, remote = remote, local
		}
		if !hasOwned || local.ID != owned.ID {
			return nil, errors.New("WG Link has no shared local resource")
		}
		p := peerFor(*remote.Authentication.PublicKey)
		if p.direction != "" && p.direction != link.InitiatorNodeID {
			return nil, errors.New("WG peer has conflicting initiation directions")
		}
		p.direction = link.InitiatorNodeID
		address, err := WGResourceAddress(remote)
		if err != nil {
			return nil, err
		}
		p.allowed[netip.PrefixFrom(address, address.BitLen()).String()] = true
		if link.InitiatorNodeID == view.DeviceID {
			p.value["address"], p.value["port"], p.value["persistent_keepalive_interval"] = remote.DialHost, remote.DialPort, 25
		}
	}
	for _, binding := range view.WireGuardPeers {
		resource := resources[binding.ResourceID]
		if !hasOwned || resource.ID != owned.ID {
			return nil, errors.New("WG incoming peer has no shared local resource")
		}
		p := peerFor(binding.PublicKey)
		base, err := WireGuardAccessAddress(resource, binding.PublicKey)
		if err != nil {
			return nil, err
		}
		p.allowed[base.String()+"/128"] = true
		for _, permission := range view.InboundCredentials {
			if permission.ResourceID != resource.ID || permission.SenderID != binding.DeviceID {
				continue
			}
			source, err := WireGuardPacketSource(view.NetworkID, permission, binding.PublicKey)
			if err != nil {
				return nil, err
			}
			p.allowed[source.String()+"/128"] = true
		}
	}
	sourceRoutes := []map[string]string{}
	for resourceID, values := range sources {
		resource := resources[resourceID]
		p := peerFor(*resource.Authentication.PublicKey)
		if p.direction == "" {
			p.value["address"], p.value["port"] = resource.DialHost, resource.DialPort
		}
		prefix, err := WireGuardTargetPrefix(view.NetworkID, resource)
		if err != nil {
			return nil, err
		}
		dns, err := WireGuardAccessAddress(resource, "")
		if err != nil {
			return nil, err
		}
		base, err := WireGuardAccessAddress(resource, public)
		if err != nil {
			return nil, err
		}
		p.allowed[dns.String()+"/128"] = true
		if len(values) > 0 {
			p.allowed[prefix.String()] = true
		}
		addresses[base.String()+"/128"] = true
		sourceRoutes = append(sourceRoutes, map[string]string{"source": base.String(), "destination": dns.String() + "/128"})
		for source := range values {
			addresses[source] = true
			address, err := netip.ParsePrefix(source)
			if err != nil || address.Bits() != 128 {
				return nil, errors.New("invalid WG business source")
			}
			sourceRoutes = append(sourceRoutes, map[string]string{"source": address.Addr().String(), "destination": prefix.String()})
		}
	}
	keys := []string{}
	for key := range peers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	peerList := []any{}
	allPrefixes := map[netip.Prefix]string{}
	for _, key := range keys {
		if key == public {
			return nil, errors.New("WG cannot peer with its own key")
		}
		p := peers[key]
		allowed := []string{}
		for text := range p.allowed {
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				return nil, err
			}
			for other, owner := range allPrefixes {
				if owner != key && prefix.Overlaps(other) {
					return nil, errors.New("WG peers have overlapping addresses")
				}
			}
			allPrefixes[prefix] = key
			allowed = append(allowed, text)
		}
		sort.Strings(allowed)
		p.value["allowed_ips"] = allowed
		peerList = append(peerList, p.value)
	}
	localAddresses := []string{}
	for text := range addresses {
		address, err := netip.ParsePrefix(text)
		if err != nil {
			return nil, err
		}
		for prefix := range allPrefixes {
			if prefix.Contains(address.Addr()) {
				return nil, errors.New("WG local source overlaps a peer address")
			}
		}
		localAddresses = append(localAddresses, text)
	}
	sort.Strings(localAddresses)
	sort.Slice(sourceRoutes, func(i, j int) bool { return sourceRoutes[i]["source"] < sourceRoutes[j]["source"] })
	for i := 1; i < len(sourceRoutes); i++ {
		if sourceRoutes[i-1]["source"] == sourceRoutes[i]["source"] {
			return nil, errors.New("WG source has multiple destinations")
		}
	}
	endpoint := map[string]any{"type": "wireguard", "tag": tag, "system": false, "address": localAddresses, "source_routes": sourceRoutes, "peers": peerList}
	if hasOwned {
		endpoint["listen_port"] = owned.DialPort
	} else {
		endpoint["private_key"] = credentials[wireGuardSharedCredential]
	}
	return endpoint, nil
}
