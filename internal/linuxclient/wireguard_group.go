package linuxclient

import (
	"errors"
	"sort"
)

// Links remain independent permissions; this only groups their execution on
// one kernel interface. It neither creates a peer nor owns an existing device.
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
	for _, value := range ordered {
		if value.Mode != "initiator" && value.Mode != "acceptor" || value.Mode == "acceptor" && (value.ListenPort < 1 || value.ListenPort > 65535) {
			return nil, errors.New("WireGuard peer direction or listener is invalid")
		}
		if len(groups) == 0 || groups[len(groups)-1].link.Interface != value.Interface {
			groups = append(groups, wireGuardOwnedLink{link: value})
			addresses = map[string]bool{value.AllowedIP: true}
			port = 0
			if value.Mode == "acceptor" {
				port = value.ListenPort
			}
			continue
		}
		group := &groups[len(groups)-1]
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
		if addresses[value.AllowedIP] || value.Mode == "acceptor" && port != 0 && port != value.ListenPort {
			return nil, errors.New("WireGuard interface has conflicting peer addresses or listener ports")
		}
		addresses[value.AllowedIP] = true
		if value.Mode == "acceptor" {
			port = value.ListenPort
		}
		group.peers = append(group.peers, value)
	}
	return groups, nil
}

func (owned wireGuardOwnedLink) peerLinks() []wireGuardExecutionLink {
	return append([]wireGuardExecutionLink{owned.link}, owned.peers...)
}

func (owned wireGuardOwnedLink) listenPort() int {
	for _, peer := range owned.peerLinks() {
		if peer.Mode == "acceptor" {
			return peer.ListenPort
		}
	}
	return 0
}
