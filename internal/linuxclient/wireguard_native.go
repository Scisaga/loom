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
	"net/netip"
	"os"
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

// appendNativeWireGuard hydrates the registered node key independently of
// receiving resources. Host facilities still require their exact ownership.
func appendNativeWireGuard(config string, view control.DeviceView, profile wireGuardExecution, _ *wireGuardTransaction, keyPath string) (string, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	endpoints, _ := document["endpoints"].([]any)
	if len(endpoints) == 0 {
		return config, nil
	}
	if len(endpoints) != 1 {
		return "", errors.New("WG requires one shared native endpoint")
	}
	endpoint, ok := endpoints[0].(map[string]any)
	if !ok || endpoint["type"] != "wireguard" || endpoint["tag"] != control.WireGuardEndpointTag || view.WireGuardPublicKey == "" {
		return "", errors.New("WG endpoint lacks its registered node identity")
	}
	private, public := view.WireGuardPrivateKey, view.WireGuardPublicKey
	if private == "" {
		var err error
		private, public, err = nativePrivateKey(keyPath)
		if err != nil {
			return "", err
		}
		if public != view.WireGuardPublicKey {
			return "", errors.New("fixed WG key differs from its registered node identity")
		}
	} else if endpoint["private_key"] != private {
		return "", errors.New("native WG sender differs from its certified private material")
	}
	endpoint["private_key"] = private
	owned := []control.TransportResource{}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID == view.DeviceID && resource.Kind == "wireguard" {
			owned = append(owned, resource)
		}
	}
	for _, resource := range owned {
		if profile.ListenPort < 1 || profile.ListenPort > 65535 {
			return "", errors.New("WG receiver has no validated local listener port")
		}
		endpoint["listen_port"] = profile.ListenPort
		if *resource.Authentication.PublicKey != public {
			return "", errors.New("fixed WG key differs from receiving resource")
		}
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
		if err := verifyNativeHost(transaction.options, *owned); err != nil {
			return err
		}
		if err := transaction.saveOwnership(); err != nil {
			return err
		}
		if _, err := runHostCommand(transaction.options.IP, "link", "set", "dev", actual.Name, "alias", owned.alias); err != nil {
			return err
		}
		// Older kernels reject renaming an UP TUN. This interface is still the
		// new process-owned temporary device: bring it down for the rename, then
		// activate its final name before installing any management return route.
		if _, err := runHostCommand(transaction.options.IP, "link", "set", "dev", actual.Name, "down"); err != nil {
			return err
		}
		if _, err := runHostCommand(transaction.options.IP, "link", "set", "dev", actual.Name, "name", owned.link.Interface); err != nil {
			return err
		}
		if _, err := runHostCommand(transaction.options.IP, "link", "set", "dev", owned.link.Interface, "up"); err != nil {
			return err
		}
		if err := restoreNativeHostAddresses(transaction.options, *owned, pid); err != nil {
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

// Linux may remove IPv6 addresses when the new TUN is brought down for its
// rename. Restore only missing authorized addresses on this exact owned link;
// an additional address is ownership drift, not something to delete or accept.
func restoreNativeHostAddresses(options Options, owned wireGuardOwnedLink, pid int) error {
	actual, found, err := inspectOwnedWireGuardInterface(options, owned)
	if err != nil {
		return err
	}
	if !found || owned.index == 0 || actual.Index != owned.index || actual.Name != owned.link.Interface || actual.Info.Kind != "tun" || actual.Alias != owned.alias || !processOwnsTUN(pid, actual.Name) {
		return ErrWireGuardOwnership
	}
	addresses, err := interfaceAddresses(options.IP, actual.Name)
	if err != nil {
		return err
	}
	wanted := owned.localAddresses()
	missing := make(map[string]bool, len(wanted))
	for _, address := range wanted {
		missing[address] = true
	}
	for _, address := range addresses {
		if !missing[address] {
			return ErrWireGuardOwnership
		}
		missing[address] = false
	}
	for _, address := range wanted {
		if missing[address] {
			if _, err := runHostCommand(options.IP, "address", "add", address, "dev", actual.Name); err != nil {
				return err
			}
		}
	}
	return verifyNativeHost(options, owned)
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

// A verified native update changes socket/peer execution metadata, while the
// token, interface, exact addresses and return routes keep their original owner.
func (transaction *wireGuardTransaction) updateNativeExecution(profile wireGuardExecution) error {
	if transaction == nil {
		return nil
	}
	for i := range transaction.owned {
		owned := &transaction.owned[i]
		update := func(value *wireGuardExecutionLink) {
			for _, next := range profile.WireGuard {
				if next.LinkID == value.LinkID && next.PeerPublicKey == value.PeerPublicKey {
					value.ListenPort, value.Endpoint, value.PersistentKeepalive = next.ListenPort, next.Endpoint, next.PersistentKeepalive
				}
			}
		}
		update(&owned.link)
		for j := range owned.peers {
			update(&owned.peers[j])
		}
	}
	return transaction.saveOwnership()
}
