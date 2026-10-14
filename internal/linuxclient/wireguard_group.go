package linuxclient

import (
	"errors"
	"net/netip"
	"sort"
)

// Derived business directions retain independent observations while sharing
// one native management interface. Grouping does not grant Service permission
// or acquire ownership of an existing host device.
func groupWireGuardLinks(values []wireGuardExecutionLink) ([]wireGuardOwnedLink, error) {
	ordered := append([]wireGuardExecutionLink{}, values...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Interface != ordered[j].Interface {
			return ordered[i].Interface < ordered[j].Interface
		}
		return ordered[i].PeerPublicKey < ordered[j].PeerPublicKey
	})
	groups := []wireGuardOwnedLink{}
	var addresses map[string]bool
	port := 0
	accessAddress, accessPort := "", 0
	for _, value := range ordered {
		if value.AccessAddress != "" || value.AccessPort != 0 {
			local, e1 := netip.ParsePrefix(value.AccessAddress)
			peer, e2 := netip.ParsePrefix(value.AllowedIP)
			if e1 != nil || e2 != nil || !local.Addr().Is6() || !peer.Addr().Is6() || !local.Addr().IsPrivate() || !peer.Addr().IsPrivate() || local.Bits() != 128 || peer.Bits() != 128 || local == peer || value.AccessAddress == value.LocalAddress || value.Mode != "acceptor" || value.AccessPort < 1 || value.AccessPort > 65535 {
				return nil, errors.New("WireGuard access peer has no exact private address and Hy2 port")
			}
		}
		if value.Mode != "initiator" && value.Mode != "acceptor" || value.ListenPort < 0 || value.ListenPort > 65535 || value.Mode == "acceptor" && value.ListenPort == 0 {
			return nil, errors.New("WireGuard peer direction or listener is invalid")
		}
		if len(groups) == 0 || groups[len(groups)-1].link.Interface != value.Interface {
			groups = append(groups, wireGuardOwnedLink{link: value})
			addresses = map[string]bool{value.AllowedIP: true}
			port = 0
			accessAddress, accessPort = value.AccessAddress, value.AccessPort
			if value.ListenPort > 0 {
				port = value.ListenPort
			}
			continue
		}
		group := &groups[len(groups)-1]
		if value.AccessAddress != "" {
			if accessAddress != "" && (accessAddress != value.AccessAddress || accessPort != value.AccessPort) {
				return nil, errors.New("WireGuard access peers have conflicting Hy2 targets")
			}
			accessAddress, accessPort = value.AccessAddress, value.AccessPort
		}
		if group.link.LinkID != value.LinkID || group.link.LocalAddress != value.LocalAddress {
			return nil, errors.New("WireGuard interface has conflicting local resource identities")
		}
		prior := group.link
		if len(group.peers) != 0 {
			prior = group.peers[len(group.peers)-1]
		}
		if prior.PeerPublicKey == value.PeerPublicKey {
			if prior != value {
				return nil, errors.New("WireGuard public key has conflicting peer projections")
			}
			continue
		}
		if addresses[value.AllowedIP] || value.ListenPort > 0 && port != 0 && port != value.ListenPort {
			return nil, errors.New("WireGuard interface has conflicting peer addresses or listener ports")
		}
		addresses[value.AllowedIP] = true
		if value.ListenPort > 0 {
			port = value.ListenPort
		}
		group.peers = append(group.peers, value)
	}
	return groups, nil
}

func (owned wireGuardOwnedLink) localAddresses() []string {
	values := []string{owned.link.LocalAddress}
	for _, peer := range owned.peerLinks() {
		if peer.AccessAddress != "" {
			values = append(values, peer.AccessAddress)
			break
		}
	}
	sort.Strings(values)
	return values
}

func (owned wireGuardOwnedLink) hasAccessPeers() bool {
	for _, peer := range owned.peerLinks() {
		if peer.AccessAddress != "" {
			return true
		}
	}
	return false
}

func (owned wireGuardOwnedLink) peerLinks() []wireGuardExecutionLink {
	return append([]wireGuardExecutionLink{owned.link}, owned.peers...)
}

func (owned wireGuardOwnedLink) listenPort() int {
	for _, peer := range owned.peerLinks() {
		if peer.ListenPort > 0 {
			return peer.ListenPort
		}
	}
	return 0
}
