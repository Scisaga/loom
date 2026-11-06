package control

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
	"sort"
)

const WireGuardEndpointTag = "wg-shared"
const wireGuardSharedCredential = WireGuardEndpointTag

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
	if validateWireGuardPublicKey(view.WireGuardPublicKey) != nil {
		return "", "", errors.New("WG execution requires its registered node identity")
	}
	if encoded := credentials[wireGuardSharedCredential]; encoded != "" {
		private, err := wireGuardAccessPrivate(encoded)
		if err != nil || base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()) != view.WireGuardPublicKey {
			return "", "", errors.New("WG execution key differs from its registered node identity")
		}
	}
	return WireGuardEndpointTag, view.WireGuardPublicKey, nil
}

// The temporary peer accumulator is discarded after rendering. Resource and
// permission facts remain the only source of keys, addresses and directions.
func sharedWireGuardEndpoint(view DeviceExecution, credentials map[string]string, sources map[string]map[string]bool) (map[string]any, error) {
	tag, public, err := sharedWireGuardIdentity(view.DeviceView, credentials)
	if err != nil {
		return nil, err
	}
	owned, hasOwned, err := ownedWireGuard(view.Resources, view.DeviceID)
	if err != nil {
		return nil, err
	}
	type peerValue struct {
		value   map[string]any
		allowed map[string]bool
	}
	peers := map[string]*peerValue{}
	peerFor := func(key string) *peerValue {
		if p := peers[key]; p != nil {
			return p
		}
		raw, _ := base64.RawURLEncoding.DecodeString(key)
		p := &peerValue{value: map[string]any{"public_key": base64.StdEncoding.EncodeToString(raw)}, allowed: map[string]bool{}}
		peers[key] = p
		return p
	}
	// Stack defaults initialize both protocols once. Exact resource senders and
	// the owned execution address remain separate authentication/receive values;
	// retain their collision checks without adding them to the stack address set.
	stackAddresses := []string{"127.0.0.1/32", "::1/128"}
	coordinates := map[string]bool{}
	for _, address := range stackAddresses {
		coordinates[address] = true
	}
	sourceRoutes := []map[string]string{}
	if hasOwned {
		execution, err := WireGuardAccessAddress(owned, "")
		if err != nil {
			return nil, err
		}
		coordinates[execution.String()+"/128"] = true
	}
	// Outgoing resource transports are shared by every Policy and final exit.
	ids := []string{}
	for id := range sources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	byID := map[string]TransportResource{}
	for _, resource := range view.Resources {
		byID[resource.ID] = resource
	}
	for _, id := range ids {
		resource := byID[id]
		p := peerFor(*resource.Authentication.PublicKey)
		p.value["address"], p.value["port"] = resource.DialHost, resource.DialPort
		p.value["persistent_keepalive_interval"] = 25
		execution, err := WireGuardAccessAddress(resource, "")
		if err != nil {
			return nil, err
		}
		pool, err := WireGuardTargetPrefix(view.NetworkID, resource)
		if err != nil {
			return nil, err
		}
		base, err := WireGuardAccessAddress(resource, public)
		if err != nil {
			return nil, err
		}
		p.allowed[execution.String()+"/128"], p.allowed[pool.String()] = true, true
		coordinates[base.String()+"/128"] = true
		sourceRoutes = append(sourceRoutes, map[string]string{"source": base.String(), "destination": pool.String(), "execution": execution.String()})
	}
	if hasOwned {
		for _, peer := range view.WireGuardPeers {
			if peer.ResourceID != owned.ID {
				continue
			}
			p := peerFor(peer.PublicKey)
			base, err := WireGuardAccessAddress(owned, peer.PublicKey)
			if err != nil {
				return nil, err
			}
			p.allowed[base.String()+"/128"] = true
			// Keep the authenticated receiver peer's public dial coordinates.
			for _, remote := range view.Resources {
				if remote.Kind == "wireguard" && remote.OwnerNodeID == peer.DeviceID {
					if p.value["address"] == nil {
						p.value["address"], p.value["port"] = remote.DialHost, remote.DialPort
					}
				}
			}
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
			return nil, errors.New("WG cannot peer with its own identity")
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
					return nil, errors.New("WG peer addresses overlap")
				}
			}
			allPrefixes[prefix] = key
			allowed = append(allowed, text)
		}
		sort.Strings(allowed)
		p.value["allowed_ips"] = allowed
		peerList = append(peerList, p.value)
	}
	for text := range coordinates {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return nil, err
		}
		for other := range allPrefixes {
			if other.Contains(prefix.Addr()) {
				return nil, errors.New("WG local and peer addresses overlap")
			}
		}
	}
	sort.Slice(sourceRoutes, func(i, j int) bool { return sourceRoutes[i]["source"] < sourceRoutes[j]["source"] })
	for i := 1; i < len(sourceRoutes); i++ {
		if sourceRoutes[i-1]["source"] == sourceRoutes[i]["source"] {
			return nil, errors.New("WG source belongs to multiple resources")
		}
	}
	result := map[string]any{"type": "wireguard", "tag": tag, "system": false, "address": stackAddresses, "source_routes": sourceRoutes, "peers": peerList}
	if view.WireGuardPrivateKey != "" {
		result["private_key"] = view.WireGuardPrivateKey
	}
	return result, nil
}
