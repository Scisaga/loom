package linuxclient

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"loom/internal/control"
)

// This handle owns only exact host management interfaces/routes. All business
// packets stay in the authenticated native endpoint and shared policy router.
// No business peer acquires a host route or firewall exception.
func prepareNativeWireGuard(view control.DeviceView, profile wireGuardExecution, options Options) (*wireGuardTransaction, error) {
	groups, err := groupWireGuardLinks(profile.WireGuard)
	if err != nil {
		return nil, err
	}
	transaction := &wireGuardTransaction{options: options}
	if len(groups) == 0 {
		return transaction, nil
	}
	links, err := readWireGuardLinks(options)
	if err != nil {
		return nil, err
	}
	resources := map[string]control.TransportResource{}
	for _, r := range view.Resources {
		resources[r.ID] = r
	}
	for _, group := range groups {
		for _, actual := range links {
			if actual.Name == group.link.Interface {
				return nil, ErrWireGuardOwnership
			}
		}
		for _, peer := range group.peerLinks() {
			exists, err := wireGuardRouteState(options, peer.AllowedIP, group.link.Interface)
			if err != nil || exists {
				return nil, errors.Join(ErrWireGuardOwnership, err)
			}
		}

		var token [16]byte
		if _, err := rand.Read(token[:]); err != nil {
			return nil, err
		}
		group.native = true
		group.alias = "loom-runtime:" + hex.EncodeToString(token[:])
		group.creationName = "lm" + hex.EncodeToString(token[:])[:13]
		key, _ := base64.RawURLEncoding.DecodeString(*resources[group.link.LinkID].Authentication.PublicKey)
		group.publicKey = base64.StdEncoding.EncodeToString(key)
		transaction.owned = append(transaction.owned, group)
	}
	return transaction, nil
}

func nativePrivateKey(path string) (string, string, error) {
	file, err := openPrivateWireGuardKey(path)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", "", err
	}
	defer clear(body)
	text := strings.TrimSpace(string(body))
	key, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != text {
		return "", "", errors.New("fixed WG key is not canonical")
	}
	defer clear(key)
	private, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return "", "", errors.New("fixed WG key is invalid")
	}
	return text, base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), nil
}

// appendNativeReceivers consumes local key bytes only here. The signed profile
// contains neither fixed receiver private keys nor host execution ownership.
func appendNativeReceivers(config string, view control.DeviceView, profile wireGuardExecution, transaction *wireGuardTransaction, keyPath string) (string, error) {
	owned := []control.TransportResource{}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID == view.DeviceID && resource.Kind == "wireguard" {
			owned = append(owned, resource)
		}
	}
	if len(owned) == 0 {
		return config, nil
	}
	private, public, err := nativePrivateKey(keyPath)
	if err != nil {
		return "", err
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	endpoints, _ := document["endpoints"].([]any)
	for _, resource := range owned {
		if *resource.Authentication.PublicKey != public {
			return "", errors.New("fixed WG key differs from receiving resource")
		}
		dns, err := control.WireGuardAccessAddress(resource, "")
		if err != nil {
			return "", err
		}
		prefix, err := control.WireGuardIPv4Prefix(view.NetworkID, resource)
		if err != nil {
			return "", err
		}
		endpoint := map[string]any{"type": "wireguard", "tag": control.ResourceInboundTag(resource.ID), "system": false, "private_key": private, "listen_port": resource.DialPort, "inet4_mapped_prefix": prefix.String()}
		addresses := []string{dns.String() + "/128"}
		peers := []any{}
		hostSources := []string{}
		for _, peer := range profile.WireGuard {
			if peer.LinkID != resource.ID {
				continue
			}
			if len(hostSources) == 0 {
				addresses = []string{peer.LocalAddress}
			}
			hostSources = append(hostSources, peer.AllowedIP)
			value := map[string]any{"public_key": peer.PeerPublicKey, "allowed_ips": []string{peer.AllowedIP}}
			if peer.Mode == "initiator" {
				host, port, err := net.SplitHostPort(peer.Endpoint)
				if err != nil {
					return "", err
				}
				number, _ := strconv.Atoi(port)
				value["address"], value["port"], value["persistent_keepalive_interval"] = host, number, 25
			}
			peers = append(peers, value)
		}
		if len(hostSources) > 0 {
			name := resource.ListenerID
			if transaction != nil {
				for _, handle := range transaction.owned {
					if handle.link.LinkID == resource.ID {
						name = handle.creationName
					}
				}
			}
			endpoint["system"], endpoint["name"], endpoint["host_sources"] = true, name, hostSources
		}
		for _, peer := range view.WireGuardPeers {
			if peer.ResourceID != resource.ID {
				continue
			}
			base, err := control.WireGuardAccessAddress(resource, peer.PublicKey)
			if err != nil {
				return "", err
			}
			allowed := []string{base.String() + "/128"}
			for _, permission := range view.InboundCredentials {
				if permission.ResourceID == resource.ID && permission.SenderID == peer.DeviceID {
					source, err := control.WireGuardPacketSource(view.NetworkID, permission, peer.PublicKey)
					if err != nil {
						return "", err
					}
					allowed = append(allowed, source.String()+"/128")
				}
			}
			sort.Strings(allowed)
			key, _ := base64.RawURLEncoding.DecodeString(peer.PublicKey)
			peers = append(peers, map[string]any{"public_key": base64.StdEncoding.EncodeToString(key), "allowed_ips": allowed})
		}
		sort.Strings(addresses)
		sort.Strings(hostSources)
		sort.Slice(peers, func(i, j int) bool {
			return peers[i].(map[string]any)["public_key"].(string) < peers[j].(map[string]any)["public_key"].(string)
		})
		endpoint["address"], endpoint["peers"] = addresses, peers
		endpoints = append(endpoints, endpoint)
	}
	document["endpoints"] = endpoints
	body, err := json.Marshal(document)
	return string(body), err
}

func (transaction *wireGuardTransaction) activateNative(ctx context.Context, pid int, done <-chan error) error {
	if transaction == nil {
		return nil
	}
	pending, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for index := range transaction.owned {
		owned := &transaction.owned[index]
		if !owned.native {
			return errors.New("native activation received a historical cleanup handle")
		}
		var actual ipLinkDocument
		for {
			value, found, err := findWireGuardLink(transaction.options, owned.creationName)
			if err != nil {
				return err
			}
			if found {
				actual = value
				break
			}
			select {
			case <-pending.Done():
				return errors.New("native WG interface did not start")
			case <-done:
				return errors.New("native WG process exited before readback")
			case <-time.After(25 * time.Millisecond):
			}
		}
		if actual.Info.Kind != "tun" || actual.Alias != "" || !processOwnsTUN(pid, actual.Name) {
			return ErrWireGuardOwnership
		}
		// TUN's kernel-generated link-local address is not management authority.
		// Disable generation on this process-owned interface and remove only the
		// exact automatic link-local prefix, never an address on a shared device.
		if _, err := runHostCommand(transaction.options.IP, "link", "set", "dev", actual.Name, "addrgenmode", "none"); err != nil {
			return err
		}
		addresses, err := interfaceAddresses(transaction.options.IP, actual.Name)
		if err != nil {
			return err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address)
			if err == nil && prefix.Addr().Is6() && prefix.Addr().IsLinkLocalUnicast() && prefix.Bits() == 64 {
				if _, err := runHostCommand(transaction.options.IP, "address", "delete", address, "dev", actual.Name); err != nil {
					return err
				}
			}
		}
		owned.index = actual.Index
		if err := transaction.saveOwnership(); err != nil {
			return err
		}
		if _, err := runHostCommand(transaction.options.IP, "link", "set", "dev", actual.Name, "alias", owned.alias); err != nil {
			return err
		}
		if _, err := runHostCommand(transaction.options.IP, "link", "set", "dev", actual.Name, "name", owned.link.Interface); err != nil {
			return err
		}
		for _, peer := range owned.peerLinks() {
			if _, err := runHostCommand(transaction.options.IP, wireGuardRouteArguments("add", peer, owned.link.Interface)...); err != nil {
				return err
			}
		}
		owned.configured = true
		if err := transaction.saveOwnership(); err != nil {
			return err
		}
		if err := verifyNativeHost(transaction.options, *owned); err != nil {
			return err
		}
	}
	return nil
}

func processOwnsTUN(pid int, name string) bool {
	base := "/proc/" + strconv.Itoa(pid) + "/fdinfo"
	entries, err := os.ReadDir(base)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		body, err := os.ReadFile(base + "/" + entry.Name())
		if err == nil {
			for _, line := range strings.Split(string(body), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 2 && fields[0] == "iff:" && fields[1] == name {
					return true
				}
			}
		}
	}
	return false
}

func verifyNativeHost(options Options, owned wireGuardOwnedLink) error {
	actual, found, err := inspectOwnedWireGuardInterface(options, owned)
	if err != nil {
		return err
	}
	if !found || actual.Info.Kind != "tun" || owned.index != 0 && actual.Index != owned.index || actual.Alias != owned.alias && !(actual.Name == owned.creationName && actual.Alias == "" && !owned.configured) {
		return ErrWireGuardOwnership
	}
	addresses, err := interfaceAddresses(options.IP, actual.Name)
	if err != nil {
		return err
	}
	want := owned.localAddresses()
	if strings.Join(addresses, "\x00") != strings.Join(want, "\x00") {
		return errors.New("native WG host addresses differ from exact ownership")
	}
	for _, family := range []string{"-4", "-6"} {
		body, err := runHostCommand(options.IP, "-json", family, "route", "show", "table", "all", "dev", actual.Name)
		if err != nil {
			return err
		}
		var routes []ipRouteDocument
		if json.Unmarshal(body, &routes) != nil || routes == nil {
			return ErrWireGuardOwnership
		}
		for _, route := range routes {
			if route.Device != "" && route.Device != actual.Name || route.Gateway != "" || len(route.Multipath) != 0 {
				return ErrWireGuardOwnership
			}
			local := string(route.Table) == `"local"` || string(route.Table) == "255"
			main := len(route.Table) == 0 || string(route.Table) == `"main"` || string(route.Table) == "254"
			if family == "-6" && local && route.Type == "multicast" && route.Destination == "ff00::/8" && route.Protocol == "kernel" && route.Metric == 256 {
				continue
			}
			permitted := false
			for _, address := range want {
				prefix, _ := netip.ParsePrefix(address)
				if sameRoutePrefix(route.Destination, address) && route.Protocol == "kernel" && (route.Source == "" || route.Source == prefix.Addr().String()) && ((local && route.Type == "local" && (route.Metric == 0 || family == "-6" && route.Metric == 256)) || (main && (route.Type == "" || route.Type == "unicast") && (route.Metric == 0 || family == "-6" && route.Metric == 256))) {
					permitted = true
				}
			}
			for _, peer := range owned.peerLinks() {
				if main && (route.Type == "" || route.Type == "unicast") && route.Protocol == "static" && sameRoutePrefix(route.Destination, peer.AllowedIP) && route.Source == "" && (family == "-4" && route.Scope == "link" && route.Metric == 0 || family == "-6" && route.Metric == 1) {
					permitted = true
				}
			}
			if !permitted {
				return errors.New("native WG interface has an unowned host route")
			}
		}
	}
	if owned.configured {
		for _, peer := range owned.peerLinks() {
			exists, err := wireGuardRouteState(options, peer.AllowedIP, actual.Name)
			if err != nil || !exists {
				return errors.New("native WG management return route is missing")
			}
		}
	}
	return nil
}

func (transaction *wireGuardTransaction) readbackNative() error {
	if transaction == nil {
		return nil
	}
	for _, owned := range transaction.owned {
		if !owned.native {
			return errors.New("historical WG execution cannot run")
		}
		if err := verifyNativeHost(transaction.options, owned); err != nil {
			return err
		}
	}
	return nil
}
