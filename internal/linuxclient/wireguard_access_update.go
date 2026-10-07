package linuxclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
)

// Reconcile only ordinary access peers on an unchanged owned interface. WG
// preserves the session keys of untouched peers; rebuilding the interface
// would leave their clients sending against a session the receiver forgot.
// The existing cleanup record temporarily covers the union, never authority.
func (transaction *wireGuardTransaction) reconcileAccessPeers(profile wireGuardExecution, identity *wireGuardIdentity) (bool, error) {
	if transaction == nil || identity == nil || len(transaction.owned) == 0 {
		return false, nil
	}
	desired, err := groupWireGuardLinks(profile.WireGuard)
	if err != nil {
		return true, err
	}
	if len(desired) != len(transaction.owned) {
		return false, nil
	}
	unions := make([]wireGuardOwnedLink, len(desired))
	next := make([]wireGuardOwnedLink, len(desired))
	for i, group := range desired {
		owned := transaction.owned[i]
		if !owned.configured || owned.alias == "" || owned.publicKey != identity.WGPublicKey ||
			owned.link.Interface != group.link.Interface || owned.link.LinkID != group.link.LinkID ||
			owned.listenPort() != group.listenPort() || !reflect.DeepEqual(owned.localAddresses(), group.localAddresses()) {
			return false, nil
		}
		candidate := owned
		candidate.link, candidate.peers = group.link, group.peers
		before, _ := json.Marshal(wireGuardFilterObjects(owned))
		after, _ := json.Marshal(wireGuardFilterObjects(candidate))
		if !bytes.Equal(before, after) {
			return false, nil
		}
		oldByKey := map[string]wireGuardExecutionLink{}
		for _, peer := range owned.peerLinks() {
			oldByKey[peer.PeerPublicKey] = peer
		}
		union := owned.peerLinks()
		newKeys := map[string]bool{}
		for _, peer := range group.peerLinks() {
			newKeys[peer.PeerPublicKey] = true
			if previous, found := oldByKey[peer.PeerPublicKey]; found {
				if previous != peer {
					return false, nil
				}
			} else {
				if peer.AccessAddress == "" {
					return false, nil
				}
				union = append(union, peer)
			}
		}
		for _, peer := range owned.peerLinks() {
			if !newKeys[peer.PeerPublicKey] && peer.AccessAddress == "" {
				return false, nil
			}
		}
		groups, err := groupWireGuardLinks(union)
		if err != nil || len(groups) != 1 {
			return false, nil
		}
		unions[i] = owned
		unions[i].link, unions[i].peers = groups[0].link, groups[0].peers
		next[i] = candidate
	}
	options := transaction.options
	if err := checkWireGuardAccessAddresses(options, desired); err != nil {
		return true, err
	}
	public, err := privateWireGuardPublicKey(options.WireGuard, options.WireGuardPrivateKey)
	if err != nil || public != identity.WGPublicKey {
		return true, errors.New("WireGuard access update has no matching node identity")
	}
	for _, owned := range transaction.owned {
		actual, exists, err := inspectOwnedWireGuardInterface(options, owned)
		if err != nil || !exists || actual.Name != owned.link.Interface || actual.Index != owned.index || actual.Alias != owned.alias || actual.Info.Kind != "wireguard" {
			return true, errors.Join(ErrWireGuardOwnership, err)
		}
		if err := verifyOwnedWireGuardLink(options, owned); err != nil {
			return true, err
		}
	}
	if err := transaction.verifyFilters(); err != nil {
		return true, err
	}
	previous := transaction.owned
	transaction.owned = unions
	fail := func(err error) (bool, error) { return true, errors.Join(err, transaction.Cleanup()) }
	// Persist the superset before any peer or route mutation. After a crash,
	// cleanup accepts only these exact objects, including partial application.
	if err := transaction.saveOwnership(); err != nil {
		return fail(err)
	}
	for index, owned := range previous {
		oldKeys, newKeys := map[string]bool{}, map[string]bool{}
		for _, peer := range owned.peerLinks() {
			oldKeys[peer.PeerPublicKey] = true
		}
		for _, peer := range next[index].peerLinks() {
			newKeys[peer.PeerPublicKey] = true
		}
		arguments := []string{"set", owned.link.Interface}
		for _, peer := range owned.peerLinks() {
			if !newKeys[peer.PeerPublicKey] {
				arguments = append(arguments, "peer", peer.PeerPublicKey, "remove")
			}
		}
		for _, peer := range next[index].peerLinks() {
			if !oldKeys[peer.PeerPublicKey] {
				exists, err := wireGuardRouteState(options, peer.AllowedIP, owned.link.Interface)
				if err != nil || exists {
					return fail(errors.Join(ErrWireGuardOwnership, err))
				}
				arguments = append(arguments, "peer", peer.PeerPublicKey, "allowed-ips", peer.AllowedIP)
			}
		}
		if len(arguments) > 2 {
			if _, err := runHostCommand(options.WireGuard, arguments...); err != nil {
				return fail(err)
			}
		}
		for _, peer := range owned.peerLinks() {
			if !newKeys[peer.PeerPublicKey] {
				exists, err := wireGuardRouteState(options, peer.AllowedIP, owned.link.Interface)
				if err != nil {
					return fail(err)
				}
				if exists {
					if _, err := runHostCommand(options.IP, wireGuardRouteArguments("delete", peer, owned.link.Interface)...); err != nil {
						return fail(err)
					}
				}
			}
		}
		for _, peer := range next[index].peerLinks() {
			if !oldKeys[peer.PeerPublicKey] {
				if _, err := runHostCommand(options.IP, wireGuardRouteArguments("add", peer, owned.link.Interface)...); err != nil {
					return fail(err)
				}
			}
		}
	}
	if err := readbackWireGuard(profile, options); err != nil {
		return fail(err)
	}
	transaction.owned = next
	if err := transaction.verifyFilters(); err != nil {
		return fail(err)
	}
	if err := transaction.saveOwnership(); err != nil {
		return fail(err)
	}
	return true, nil
}

// An authenticated address does not grant ownership of a pre-existing local
// address. Check both the listener and new peer host routes before mutation.
func checkWireGuardAccessAddresses(options Options, groups []wireGuardOwnedLink) error {
	wanted := map[netip.Addr]string{}
	for _, group := range groups {
		for _, peer := range group.peerLinks() {
			if peer.AccessAddress == "" {
				continue
			}
			for _, text := range []string{peer.AccessAddress, peer.AllowedIP} {
				prefix, err := netip.ParsePrefix(text)
				if err != nil {
					return ErrWireGuardOwnership
				}
				allowedInterface := ""
				if text == peer.AccessAddress {
					allowedInterface = group.link.Interface
				}
				if previous, exists := wanted[prefix.Addr()]; exists && previous != allowedInterface {
					return ErrWireGuardOwnership
				}
				wanted[prefix.Addr()] = allowedInterface
			}
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	body, err := runHostCommand(options.IP, "-json", "address", "show")
	if err != nil || len(body) > 8<<20 {
		return errors.Join(ErrWireGuardOwnership, err)
	}
	var interfaces []struct {
		Name      string `json:"ifname"`
		Addresses []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(body, &interfaces) != nil || interfaces == nil {
		return ErrWireGuardOwnership
	}
	for _, iface := range interfaces {
		for _, local := range iface.Addresses {
			address, err := netip.ParseAddr(local.Local)
			if err != nil {
				return ErrWireGuardOwnership
			}
			if allowed, exists := wanted[address]; exists && (allowed == "" || allowed != iface.Name) {
				return errors.New("WireGuard access address conflicts with an existing local address")
			}
		}
	}
	return nil
}

func wireGuardRouteArguments(operation string, peer wireGuardExecutionLink, iface string) []string {
	arguments := []string{"route", operation, peer.AllowedIP, "dev", iface, "proto", "static", "scope", "link"}
	if strings.Contains(peer.AllowedIP, ":") {
		arguments = append(arguments, "metric", "1")
	}
	return arguments
}
