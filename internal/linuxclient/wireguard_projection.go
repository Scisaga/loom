package linuxclient

import (
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"loom/internal/control"
)

func projectWireGuard(view control.DeviceView) (wireGuardExecution, *wireGuardIdentity, error) {
	result := wireGuardExecution{WireGuard: []wireGuardExecutionLink{}}
	resources := map[string]control.TransportResource{}
	for _, resource := range view.Resources {
		resources[resource.ID] = resource
	}
	byInterface := map[string]wireGuardExecutionLink{}
	identity := &wireGuardIdentity{}
	for _, link := range view.Links {
		if link.FromNodeID != view.DeviceID && link.ToNodeID != view.DeviceID {
			continue
		}
		local, peer := resources[link.FromResourceID], resources[link.ResourceID]
		if link.ToNodeID == view.DeviceID {
			local, peer = peer, local
		}
		localAddress, e1 := control.WGResourceAddress(local)
		peerAddress, e2 := control.WGResourceAddress(peer)
		if e1 != nil || e2 != nil || local.OwnerNodeID != view.DeviceID || len(local.ListenerID) > 15 || strings.ContainsAny(local.ListenerID, "/: ") {
			return result, nil, errors.New("WireGuard Link execution identities are invalid")
		}
		localKey, _ := base64.RawURLEncoding.DecodeString(*local.Authentication.PublicKey)
		peerKey, _ := base64.RawURLEncoding.DecodeString(*peer.Authentication.PublicKey)
		publicKey := base64.StdEncoding.EncodeToString(localKey)
		if identity.WGPublicKey != "" && identity.WGPublicKey != publicKey {
			return result, nil, errors.New("WireGuard resources do not share this node's fixed key reference")
		}
		identity.WGPublicKey = publicKey
		value := wireGuardExecutionLink{LinkID: local.ID, Interface: local.ListenerID, LocalAddress: netip.PrefixFrom(localAddress, localAddress.BitLen()).String(), PeerID: peer.OwnerNodeID,
			PeerPublicKey: base64.StdEncoding.EncodeToString(peerKey), AllowedIP: netip.PrefixFrom(peerAddress, peerAddress.BitLen()).String(), Mode: "acceptor", ListenPort: local.DialPort}
		if link.InitiatorNodeID == view.DeviceID {
			value.Mode, value.ListenPort, value.PersistentKeepalive = "initiator", 0, 25
			value.Endpoint = net.JoinHostPort(peer.DialHost, strconv.Itoa(peer.DialPort))
		}
		if prior, found := byInterface[value.Interface]; found && !reflect.DeepEqual(prior, value) {
			return result, nil, errors.New("WireGuard resource has conflicting peer or direction projections")
		}
		byInterface[value.Interface] = value
	}
	for _, value := range byInterface {
		result.WireGuard = append(result.WireGuard, value)
	}
	sort.Slice(result.WireGuard, func(i, j int) bool { return result.WireGuard[i].Interface < result.WireGuard[j].Interface })
	if len(result.WireGuard) == 0 {
		return result, nil, nil
	}
	return result, identity, nil
}
