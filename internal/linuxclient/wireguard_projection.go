package linuxclient

import (
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
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
		result.WireGuard = append(result.WireGuard, value)
	}
	for _, peer := range view.WireGuardPeers {
		resource := resources[peer.ResourceID]
		target, err := control.WireGuardAccessTarget(resource, resources)
		local, addressErr := control.WGResourceAddress(resource)
		if err != nil || addressErr != nil || resource.OwnerNodeID != view.DeviceID || len(resource.ListenerID) > 15 || strings.ContainsAny(resource.ListenerID, "/: ") {
			return result, nil, errors.New("WireGuard access receiver has no exact owned resource")
		}
		access, err := control.WireGuardAccessAddress(resource, "")
		if err != nil {
			return result, nil, err
		}
		remote, err := control.WireGuardAccessAddress(resource, peer.PublicKey)
		if err != nil {
			return result, nil, err
		}
		localKey, _ := base64.RawURLEncoding.DecodeString(*resource.Authentication.PublicKey)
		publicKey := base64.StdEncoding.EncodeToString(localKey)
		if identity.WGPublicKey != "" && identity.WGPublicKey != publicKey {
			return result, nil, errors.New("WireGuard resources do not share this node's fixed key reference")
		}
		identity.WGPublicKey = publicKey
		peerKey, _ := base64.RawURLEncoding.DecodeString(peer.PublicKey)
		result.WireGuard = append(result.WireGuard, wireGuardExecutionLink{LinkID: resource.ID, Interface: resource.ListenerID,
			LocalAddress: netip.PrefixFrom(local, local.BitLen()).String(), PeerID: peer.DeviceID, PeerPublicKey: base64.StdEncoding.EncodeToString(peerKey),
			AllowedIP: remote.String() + "/128", Mode: "acceptor", ListenPort: resource.DialPort, AccessAddress: access.String() + "/128", AccessPort: target.DialPort})
	}
	groups, err := groupWireGuardLinks(result.WireGuard)
	if err != nil {
		return wireGuardExecution{}, nil, err
	}
	result.WireGuard = []wireGuardExecutionLink{}
	for _, group := range groups {
		result.WireGuard = append(result.WireGuard, group.peerLinks()...)
	}
	if len(result.WireGuard) == 0 {
		return result, nil, nil
	}
	return result, identity, nil
}
