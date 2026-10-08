package linuxclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// These values are execution arguments projected from TransportResource/Link.
// Only public cleanup ownership is retained across a process crash; it cannot
// be used to restore permission or start a runtime.
type wireGuardExecutionLink struct {
	LinkID              string `json:"link_id"`
	Interface           string `json:"interface"`
	LocalAddress        string `json:"local_address"`
	PeerID              string `json:"peer_id"`
	PeerPublicKey       string `json:"peer_public_key"`
	AllowedIP           string `json:"allowed_ip"`
	Mode                string `json:"mode"`
	Endpoint            string `json:"endpoint"`
	ProbeTarget         string `json:"probe_target"`
	ListenPort          int    `json:"listen_port"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
	AccessAddress       string `json:"access_address,omitempty"`
	AccessPort          int    `json:"access_port,omitempty"`
}
type wireGuardExecution struct{ WireGuard []wireGuardExecutionLink }
type wireGuardIdentity struct{ WGPublicKey string }

// An authenticated profile authorizes a desired configuration, but cannot prove
// ownership of an existing host interface. Only a handle from this process's
// successful link creation permits cleanup.
var (
	ErrWireGuardOwnership = errors.New("WireGuard runtime ownership cannot be verified")
	ErrWireGuardCleanup   = errors.New("WireGuard runtime cleanup failed")
)

type wireGuardOwnedLink struct {
	native       bool
	link         wireGuardExecutionLink
	peers        []wireGuardExecutionLink
	alias        string
	creationName string
	index        int
	publicKey    string
	configured   bool
}

type wireGuardTransaction struct {
	options Options
	owned   []wireGuardOwnedLink
}

type ipLinkDocument struct {
	Index int    `json:"ifindex"`
	Name  string `json:"ifname"`
	Alias string `json:"ifalias"`
	Info  struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

type ipAddressDocument struct {
	Addresses []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

type ipRouteDocument struct {
	Destination string            `json:"dst"`
	Device      string            `json:"dev"`
	Type        string            `json:"type"`
	Protocol    string            `json:"protocol"`
	Scope       string            `json:"scope"`
	Table       json.RawMessage   `json:"table,omitempty"`
	Gateway     string            `json:"gateway"`
	Source      string            `json:"prefsrc"`
	Metric      int               `json:"metric"`
	Multipath   []json.RawMessage `json:"nexthops"`
}

func runHostCommand(name string, arguments ...string) ([]byte, error) {
	command := exec.Command(name, arguments...)
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("host command %s failed", filepath.Base(name))
	}
	return output, nil
}

func privateWireGuardPublicKey(wg, path string) (string, error) {
	file, err := openPrivateWireGuardKey(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	command := exec.Command(wg, "pubkey")
	command.Stdin = file
	output, err := command.Output()
	if err != nil || len(output) > 256 {
		return "", errors.New("WireGuard public key derivation failed")
	}
	return strings.TrimSpace(string(output)), nil
}

func openPrivateWireGuardKey(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("WireGuard private key is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		info.Size() < 1 || info.Size() > 4096 || !ok || stat.Uid != 0 {
		return nil, errors.New("WireGuard private key must be an owner-only root-owned regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("WireGuard private key is unavailable")
	}
	actual, err := file.Stat()
	if err != nil || !os.SameFile(info, actual) {
		_ = file.Close()
		return nil, errors.New("WireGuard private key changed while opening")
	}
	return file, nil
}

func WireGuardPublicKey(path string) (string, error) {
	return privateWireGuardPublicKey("/usr/bin/wg", path)
}

func interfaceAddresses(ip, name string) ([]string, error) {
	body, err := runHostCommand(ip, "-json", "address", "show", "dev", name)
	if err != nil {
		return nil, err
	}
	var documents []ipAddressDocument
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&documents); err != nil || len(documents) != 1 {
		return nil, errors.New("WireGuard interface address readback is invalid")
	}
	result := make([]string, 0, len(documents[0].Addresses))
	for _, address := range documents[0].Addresses {
		value := net.ParseIP(address.Local)
		if value == nil || address.PrefixLen < 0 || address.PrefixLen > 128 {
			return nil, errors.New("WireGuard interface address readback is invalid")
		}
		result = append(result, value.String()+"/"+strconv.Itoa(address.PrefixLen))
	}
	sort.Strings(result)
	return result, nil
}

// Rollback only removes this generation. Restoring a previous snapshot could
// restore a peer or route that the newly accepted LKG has revoked.
func (transaction *wireGuardTransaction) Rollback() error { return transaction.Cleanup() }

// Commit deliberately retains the ownership handle for normal runtime stop.
func (transaction *wireGuardTransaction) Commit() {}

func readWireGuardLinks(options Options) ([]ipLinkDocument, error) {
	body, err := runHostCommand(options.IP, "-json", "-details", "link", "show")
	if err != nil {
		return nil, err
	}
	var links []ipLinkDocument
	if err := json.Unmarshal(body, &links); err != nil || links == nil {
		return nil, errors.New("WireGuard interface ownership readback is invalid")
	}
	seen := map[string]bool{}
	indices := map[int]bool{}
	for _, link := range links {
		if link.Index <= 0 || link.Name == "" || seen[link.Name] || indices[link.Index] {
			return nil, errors.New("WireGuard interface ownership readback is invalid")
		}
		seen[link.Name] = true
		indices[link.Index] = true
	}
	return links, nil
}

func findWireGuardLink(options Options, name string) (ipLinkDocument, bool, error) {
	links, err := readWireGuardLinks(options)
	if err != nil {
		return ipLinkDocument{}, false, err
	}
	for _, link := range links {
		if link.Name == name {
			return link, true, nil
		}
	}
	return ipLinkDocument{}, false, nil
}

func inspectOwnedWireGuardInterface(options Options, owned wireGuardOwnedLink) (ipLinkDocument, bool, error) {
	links, err := readWireGuardLinks(options)
	if err != nil {
		return ipLinkDocument{}, false, err
	}
	var actual ipLinkDocument
	exists := false
	// A generation-unique creation name is the atomic marker on kernels whose
	// WireGuard newlink handler discards IFLA_IFALIAS during initial setup.
	for _, link := range links {
		if owned.creationName != "" && link.Name == owned.creationName {
			return link, true, nil
		}
	}
	for _, link := range links {
		if link.Name == owned.link.Interface {
			actual, exists = link, true
		} else if link.Alias == owned.alias || owned.index != 0 && link.Index == owned.index {
			// A rename is not successful cleanup. The old generation may still
			// be forwarding, but the changed host object cannot be removed.
			return ipLinkDocument{}, false, ErrWireGuardOwnership
		}
	}
	return actual, exists, nil
}

func (transaction *wireGuardTransaction) Cleanup() error {
	if transaction == nil {
		return nil
	}
	var cleanupErr error
	for index := len(transaction.owned) - 1; index >= 0; index-- {
		owned := &transaction.owned[index]
		if owned.alias == "" {
			continue
		}
		actual, exists, err := inspectOwnedWireGuardInterface(transaction.options, *owned)
		if err == nil && !exists {
			if err := cleanupWireGuardFilter(transaction.options, *owned); err != nil {
				cleanupErr = errors.Join(cleanupErr, err)
				continue
			}
			owned.alias = ""
			continue
		}
		if err == nil && owned.native {
			if err = verifyNativeHost(transaction.options, *owned); err == nil {
				_, err = runHostCommand(transaction.options.IP, "link", "delete", "dev", actual.Name)
				if err == nil {
					_, remains, e := inspectOwnedWireGuardInterface(transaction.options, *owned)
					if e != nil || remains {
						err = ErrWireGuardCleanup
					}
				}
			}
			if err != nil {
				cleanupErr = errors.Join(cleanupErr, err)
			} else {
				owned.alias = ""
			}
			continue
		}
		creation := actual.Name == owned.creationName && owned.creationName != "" && actual.Alias == "" && !owned.configured
		if err == nil && (actual.Alias != owned.alias && !creation || actual.Info.Kind != "wireguard" ||
			owned.index != 0 && actual.Index != owned.index) {
			err = ErrWireGuardOwnership
		}
		if err == nil {
			checking := *owned
			checking.link.Interface = actual.Name
			err = verifyOwnedWireGuardLink(transaction.options, checking)
		}
		if err == nil {
			current, present, readErr := inspectOwnedWireGuardInterface(transaction.options, *owned)
			if readErr != nil || !present || current.Index != actual.Index || current.Name != actual.Name || current.Alias != actual.Alias || current.Info.Kind != "wireguard" {
				err = ErrWireGuardOwnership
			}
		}
		if err == nil {
			_, err = runHostCommand(transaction.options.IP, "link", "delete", "dev", actual.Name)
		}
		if err == nil {
			_, remains, readErr := inspectOwnedWireGuardInterface(transaction.options, *owned)
			if readErr != nil || remains {
				err = errors.New("WireGuard interface removal could not be verified")
			}
		}
		if err == nil {
			err = cleanupWireGuardFilter(transaction.options, *owned)
		}
		if err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}
		owned.alias = ""
	}
	if cleanupErr != nil {
		return errors.Join(ErrWireGuardCleanup, cleanupErr)
	}
	return transaction.saveOwnership()
}

func verifyOwnedWireGuardLink(options Options, owned wireGuardOwnedLink) error {
	link := owned.link
	// A per-interface dump contains private key bytes. They are inspected only
	// in memory and never included in a snapshot, file, error or log.
	body, err := runHostCommand(options.WireGuard, "show", link.Interface, "dump")
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	peers := owned.peerLinks()
	if len(body) == 0 || len(body) > 1<<20 || len(lines) > len(peers)+1 {
		return fmt.Errorf("%w: dump shape", ErrWireGuardOwnership)
	}
	header := strings.Split(lines[0], "\t")
	if len(header) != 4 || header[1] != owned.publicKey && (owned.configured || header[1] != "(none)") ||
		header[3] != "off" && header[3] != "0" {
		return fmt.Errorf("%w: local public key or mark", ErrWireGuardOwnership)
	}
	port, err := strconv.Atoi(header[2])
	if err != nil || port < 0 || port > 65535 || owned.listenPort() != 0 && port != owned.listenPort() && (owned.configured || port != 0) {
		return fmt.Errorf("%w: listen port", ErrWireGuardOwnership)
	}
	expected := map[string]wireGuardExecutionLink{}
	for _, value := range peers {
		expected[value.PeerPublicKey] = value
	}
	seen := map[string]bool{}
	for _, line := range lines[1:] {
		peer := strings.Split(line, "\t")
		if len(peer) != 8 {
			return fmt.Errorf("%w: peer shape", ErrWireGuardOwnership)
		}
		value, exists := expected[peer[0]]
		if !exists || seen[peer[0]] || peer[1] != "(none)" ||
			peer[3] != value.AllowedIP && (owned.configured || peer[3] != "(none)") {
			return fmt.Errorf("%w: peer or AllowedIPs", ErrWireGuardOwnership)
		}
		seen[peer[0]] = true
		keepalive := peer[7]
		if keepalive == "off" {
			keepalive = "0"
		}
		if keepalive != strconv.Itoa(value.PersistentKeepalive) && (owned.configured || keepalive != "0") {
			return fmt.Errorf("%w: keepalive", ErrWireGuardOwnership)
		}
		// Authenticated WG roaming may change an acceptor's endpoint. Its peer
		// key and permitted addresses remain exact; no extra peer is accepted.
		if value.Mode == "initiator" && peer[2] != "(none)" && !endpointMatches(value.Endpoint, peer[2]) {
			return fmt.Errorf("%w: endpoint", ErrWireGuardOwnership)
		}
	}
	addresses, err := interfaceAddresses(options.IP, link.Interface)
	if err != nil {
		return err
	}
	localIPs := []net.IP{}
	wantedAddresses := owned.localAddresses()
	for _, address := range addresses {
		index := sort.SearchStrings(wantedAddresses, address)
		if index == len(wantedAddresses) || wantedAddresses[index] != address {
			return fmt.Errorf("%w: local addresses", ErrWireGuardOwnership)
		}
	}
	for _, address := range wantedAddresses {
		localIP, _, parseErr := net.ParseCIDR(address)
		if parseErr != nil {
			return fmt.Errorf("%w: local prefix", ErrWireGuardOwnership)
		}
		localIPs = append(localIPs, localIP)
	}
	for _, family := range []string{"-4", "-6"} {
		body, err := runHostCommand(options.IP, "-json", family, "route", "show", "table", "all", "dev", link.Interface)
		if err != nil {
			return err
		}
		var routes []ipRouteDocument
		if err := json.Unmarshal(body, &routes); err != nil || routes == nil {
			return fmt.Errorf("%w: route ownership", ErrWireGuardOwnership)
		}
		for _, route := range routes {
			// iproute2 omits dev when the query already fixes the interface.
			if route.Device != "" && route.Device != link.Interface || route.Gateway != "" || len(route.Multipath) != 0 {
				return fmt.Errorf("%w: unexpected route", ErrWireGuardOwnership)
			}
			local := string(route.Table) == `"local"` || string(route.Table) == "255"
			// The owned interface's UP transition creates this exact kernel
			// multicast route even without a configured IPv6 unicast address.
			if family == "-6" && local && route.Type == "multicast" && route.Destination == "ff00::/8" && route.Protocol == "kernel" && route.Metric == 256 && route.Source == "" && route.Scope == "" {
				continue
			}
			main := len(route.Table) == 0 || string(route.Table) == `"main"` || string(route.Table) == "254"
			allowed := false
			for _, peer := range peers {
				allowed = allowed || sameRoutePrefix(route.Destination, peer.AllowedIP)
			}
			if main && (route.Type == "" || route.Type == "unicast") && route.Protocol == "static" &&
				(family == "-4" && route.Scope == "link" && route.Metric == 0 || family == "-6" && route.Scope == "" && route.Metric == 1) && route.Source == "" && allowed {
				continue
			}
			// address add installs this exact local route even with
			// noprefixroute. No connected subnet or unrelated route is owned.
			ownedLocal := false
			for _, localIP := range localIPs {
				ownedLocal = ownedLocal || net.ParseIP(route.Destination).Equal(localIP) && (route.Source == "" || net.ParseIP(route.Source).Equal(localIP))
			}
			if local && route.Type == "local" && route.Protocol == "kernel" && route.Metric == 0 &&
				(route.Scope == "host" || route.Scope == "") && ownedLocal {
				continue
			}
			return ErrWireGuardOwnership
		}
	}
	return nil
}

func wireGuardRouteState(options Options, allowedIP, name string) (bool, error) {
	family := "-4"
	if strings.Contains(allowedIP, ":") {
		family = "-6"
	}
	body, err := runHostCommand(options.IP, "-json", family, "route", "show", "exact", allowedIP)
	if err != nil {
		return false, err
	}
	var routes []ipRouteDocument
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&routes); err != nil {
		return false, errors.New("WireGuard route readback is invalid")
	}
	if len(routes) == 0 {
		return false, nil
	}
	if len(routes) != 1 || !sameRoutePrefix(routes[0].Destination, allowedIP) || routes[0].Device != name {
		return false, errors.New("WireGuard route conflicts with another runtime")
	}
	return true, nil
}

func sameRoutePrefix(actual, expected string) bool {
	expectedIP, expectedNetwork, err := net.ParseCIDR(expected)
	if err != nil {
		return false
	}
	if actualIP := net.ParseIP(actual); actualIP != nil {
		ones, bits := expectedNetwork.Mask.Size()
		return ones == bits && expectedIP.Equal(actualIP)
	}
	actualIP, actualNetwork, err := net.ParseCIDR(actual)
	if err != nil {
		return false
	}
	actualOnes, actualBits := actualNetwork.Mask.Size()
	expectedOnes, expectedBits := expectedNetwork.Mask.Size()
	return actualBits == expectedBits && actualOnes == expectedOnes && actualIP.Equal(expectedIP)
}

func endpointMatches(expected, actual string) bool {
	expectedHost, expectedPort, expectedErr := net.SplitHostPort(expected)
	actualHost, actualPort, actualErr := net.SplitHostPort(actual)
	if expectedErr != nil || actualErr != nil || expectedPort != actualPort {
		return false
	}
	expectedIP, actualIP := net.ParseIP(expectedHost), net.ParseIP(actualHost)
	return expectedIP != nil && actualIP != nil && expectedIP.Equal(actualIP)
}
