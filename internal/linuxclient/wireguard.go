package linuxclient

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
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
	link         wireGuardExecutionLink
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

type wireGuardActual struct {
	Interface  string
	PublicKey  string
	Endpoint   string
	AllowedIPs string
	Keepalive  int
	ListenPort int
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
			owned.alias = ""
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
	if len(body) == 0 || len(body) > 1<<20 || len(lines) > 2 {
		return fmt.Errorf("%w: dump shape", ErrWireGuardOwnership)
	}
	header := strings.Split(lines[0], "\t")
	if len(header) != 4 || header[1] != owned.publicKey && (owned.configured || header[1] != "(none)") ||
		header[3] != "off" && header[3] != "0" {
		return fmt.Errorf("%w: local public key or mark", ErrWireGuardOwnership)
	}
	port, err := strconv.Atoi(header[2])
	if err != nil || port < 0 || port > 65535 || link.Mode == "acceptor" && port != link.ListenPort && (owned.configured || port != 0) {
		return fmt.Errorf("%w: listen port", ErrWireGuardOwnership)
	}
	if len(lines) == 2 {
		peer := strings.Split(lines[1], "\t")
		if len(peer) != 8 || peer[0] != link.PeerPublicKey || peer[1] != "(none)" ||
			peer[3] != link.AllowedIP && (owned.configured || peer[3] != "(none)") {
			return fmt.Errorf("%w: peer or AllowedIPs", ErrWireGuardOwnership)
		}
		keepalive := peer[7]
		if keepalive == "off" {
			keepalive = "0"
		}
		if keepalive != strconv.Itoa(link.PersistentKeepalive) && (owned.configured || keepalive != "0") {
			return fmt.Errorf("%w: keepalive", ErrWireGuardOwnership)
		}
		// Authenticated WG roaming may change an acceptor's endpoint. Its peer
		// key and permitted addresses remain exact; no extra peer is accepted.
		if link.Mode == "initiator" && peer[2] != "(none)" && !endpointMatches(link.Endpoint, peer[2]) {
			return fmt.Errorf("%w: endpoint", ErrWireGuardOwnership)
		}
	}
	addresses, err := interfaceAddresses(options.IP, link.Interface)
	if err != nil {
		return err
	}
	if len(addresses) > 1 || len(addresses) == 1 && addresses[0] != link.LocalAddress {
		return fmt.Errorf("%w: local addresses", ErrWireGuardOwnership)
	}
	localIP, _, parseErr := net.ParseCIDR(link.LocalAddress)
	if parseErr != nil {
		return fmt.Errorf("%w: local prefix", ErrWireGuardOwnership)
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
			if route.Metric != 0 {
				return fmt.Errorf("%w: unexpected route metric", ErrWireGuardOwnership)
			}
			main := len(route.Table) == 0 || string(route.Table) == `"main"` || string(route.Table) == "254"
			if main && (route.Type == "" || route.Type == "unicast") && route.Protocol == "static" &&
				route.Scope == "link" && route.Source == "" && sameRoutePrefix(route.Destination, link.AllowedIP) {
				continue
			}
			// address add installs this exact local route even with
			// noprefixroute. No connected subnet or unrelated route is owned.
			if local && route.Type == "local" && route.Protocol == "kernel" &&
				(route.Scope == "host" || route.Scope == "") && net.ParseIP(route.Destination).Equal(localIP) &&
				(route.Source == "" || net.ParseIP(route.Source).Equal(localIP)) {
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

func configureWireGuardLink(options Options, owned *wireGuardOwnedLink) error {
	link, localPublicKey := owned.link, owned.publicKey
	arguments := []string{"set", link.Interface}
	actualPublic, err := runHostCommand(options.WireGuard, "show", link.Interface, "public-key")
	if err != nil {
		return err
	}
	needsPrivateKey := strings.TrimSpace(string(actualPublic)) != localPublicKey
	var privateKey *os.File
	var privateKeyInfo os.FileInfo
	if needsPrivateKey {
		privateKey, err = openPrivateWireGuardKey(options.WireGuardPrivateKey)
		if err != nil {
			return err
		}
		defer privateKey.Close()
		privateKeyInfo, err = privateKey.Stat()
		if err != nil {
			return errors.New("WireGuard private key cannot be inspected")
		}
		// Ubuntu's wg AppArmor profile deliberately permits only
		// /etc/wireguard/** and denies /dev/stdin and arbitrary descriptors.
		// The path is therefore part of the deployment boundary; verify it both
		// before and after wg reopens it and remove this generation on change.
		arguments = append(arguments, "private-key", options.WireGuardPrivateKey)
	}
	if link.Mode == "acceptor" {
		arguments = append(arguments, "listen-port", strconv.Itoa(link.ListenPort))
	} else {
		// Clear a previously certified fixed acceptor port. The kernel may use
		// an ephemeral source port for replies, but no stable ingress remains.
		arguments = append(arguments, "listen-port", "0")
	}
	arguments = append(arguments, "peer", link.PeerPublicKey, "allowed-ips", link.AllowedIP)
	if link.Mode == "initiator" {
		arguments = append(arguments, "endpoint", link.Endpoint, "persistent-keepalive", strconv.Itoa(link.PersistentKeepalive))
	}
	command := exec.Command(options.WireGuard, arguments...)
	if err := command.Run(); err != nil {
		return errors.New("WireGuard configuration failed")
	}
	owned.configured = true
	if needsPrivateKey {
		after, err := os.Lstat(options.WireGuardPrivateKey)
		if err != nil || !os.SameFile(privateKeyInfo, after) {
			return errors.New("WireGuard private key changed during configuration")
		}
	}
	if _, err := runHostCommand(options.IP, "address", "add", link.LocalAddress, "dev", link.Interface, "noprefixroute"); err != nil {
		return err
	}
	if _, err = runHostCommand(options.IP, "link", "set", "dev", link.Interface, "up"); err != nil {
		return err
	}
	_, err = runHostCommand(options.IP, "route", "add", link.AllowedIP, "dev", link.Interface, "proto", "static", "scope", "link")
	return err
}

func parseWireGuardActual(body []byte) (map[string]wireGuardActual, error) {
	if len(body) == 0 || len(body) > 8<<20 {
		return nil, errors.New("WireGuard runtime dump is invalid")
	}
	listenPorts := map[string]int{}
	result := map[string]wireGuardActual{}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) == 5 {
			port, err := strconv.Atoi(fields[3])
			if err != nil {
				return nil, errors.New("WireGuard runtime dump is invalid")
			}
			listenPorts[fields[0]] = port
			continue
		}
		if len(fields) != 9 {
			return nil, fmt.Errorf("WireGuard runtime dump row has %d fields", len(fields))
		}
		keepalive := 0
		var err error
		if fields[8] != "off" {
			keepalive, err = strconv.Atoi(fields[8])
		}
		if err != nil {
			return nil, fmt.Errorf("WireGuard runtime keepalive %q is invalid", fields[8])
		}
		if fields[0] == "" || fields[1] == "" {
			return nil, errors.New("WireGuard runtime dump identity is invalid")
		}
		if _, duplicate := result[fields[1]]; duplicate {
			return nil, errors.New("WireGuard peer appears more than once")
		}
		result[fields[1]] = wireGuardActual{Interface: fields[0], PublicKey: fields[1], Endpoint: fields[3],
			AllowedIPs: fields[4], Keepalive: keepalive}
	}
	for key, value := range result {
		value.ListenPort = listenPorts[value.Interface]
		result[key] = value
	}
	return result, nil
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

func readbackWireGuard(profile wireGuardExecution, options Options) error {
	if len(profile.WireGuard) == 0 {
		return nil
	}
	body, err := runHostCommand(options.WireGuard, "show", "all", "dump")
	if err != nil {
		return err
	}
	actual, err := parseWireGuardActual(body)
	if err != nil {
		return err
	}
	for _, link := range profile.WireGuard {
		peer, ok := actual[link.PeerPublicKey]
		if !ok || peer.Interface != link.Interface || peer.AllowedIPs != link.AllowedIP {
			return errors.New("WireGuard peer readback does not match the certified runtime")
		}
		if link.Mode == "acceptor" && peer.ListenPort != link.ListenPort ||
			link.Mode == "initiator" && (peer.Keepalive != link.PersistentKeepalive || !endpointMatches(link.Endpoint, peer.Endpoint)) {
			return errors.New("WireGuard direction readback does not match the certified runtime")
		}
		addresses, err := interfaceAddresses(options.IP, link.Interface)
		addressIndex := sort.SearchStrings(addresses, link.LocalAddress)
		if err != nil || addressIndex == len(addresses) || addresses[addressIndex] != link.LocalAddress {
			return errors.New("WireGuard address readback does not match the certified runtime")
		}
		route, err := wireGuardRouteState(options, link.AllowedIP, link.Interface)
		if err != nil || !route {
			return errors.New("WireGuard route readback does not match the certified runtime")
		}
	}
	return nil
}

func applyWireGuard(profile, previous *wireGuardExecution, server *wireGuardIdentity, options Options) (*wireGuardTransaction, error) {
	if profile == nil {
		profile = &wireGuardExecution{}
	}
	if len(profile.WireGuard) == 0 && (previous == nil || len(previous.WireGuard) == 0) {
		return &wireGuardTransaction{}, nil
	}
	if len(profile.WireGuard) != 0 && server == nil {
		return nil, errors.New("WireGuard runtime has no certified server identity")
	}
	for _, link := range profile.WireGuard {
		if link.Mode == "initiator" && !endpointMatches(link.Endpoint, link.Endpoint) {
			return nil, errors.New("WireGuard runtime requires a resolved literal endpoint")
		}
	}
	// Previous authority cannot claim an interface. The caller first cleans
	// any recorded generation using its independent kernel ownership token.
	links, err := readWireGuardLinks(options)
	if err != nil {
		return nil, errors.Join(ErrWireGuardOwnership, err)
	}
	names := map[string]bool{}
	for _, link := range profile.WireGuard {
		if names[link.Interface] {
			return nil, errors.New("WireGuard runtime reuses an interface")
		}
		names[link.Interface] = true
	}
	if previous != nil {
		for _, link := range previous.WireGuard {
			names[link.Interface] = true
		}
	}
	for _, actual := range links {
		if names[actual.Name] {
			return nil, ErrWireGuardOwnership
		}
	}
	for _, link := range profile.WireGuard {
		exists, err := wireGuardRouteState(options, link.AllowedIP, link.Interface)
		if err != nil || exists {
			return nil, errors.Join(ErrWireGuardOwnership, err)
		}
	}
	localPublicKey := ""
	if len(profile.WireGuard) != 0 {
		publicKey, err := privateWireGuardPublicKey(options.WireGuard, options.WireGuardPrivateKey)
		if err != nil || publicKey != server.WGPublicKey {
			return nil, errors.New("WireGuard private key does not match the certified server identity")
		}
		localPublicKey = publicKey
	}
	transaction := &wireGuardTransaction{options: options}
	fail := func(err error) (*wireGuardTransaction, error) {
		return nil, errors.Join(err, transaction.Cleanup())
	}
	for _, link := range profile.WireGuard {
		var token [16]byte
		_, err := rand.Read(token[:])
		if err != nil {
			return fail(err)
		}
		owned := wireGuardOwnedLink{link: link, alias: "loom-runtime:" + hex.EncodeToString(token[:]), creationName: "lm" + hex.EncodeToString(token[:])[:13], publicKey: localPublicKey}
		// Create with a generation-unique name first. The WG kernel driver on
		// some supported hosts resets ifalias in its newlink callback. A random
		// creation name remains an atomic ownership marker through that window.
		transaction.owned = append(transaction.owned, owned)
		if err := transaction.saveOwnership(); err != nil {
			return fail(err)
		}
		if _, err := runHostCommand(options.IP, "link", "add", "dev", owned.creationName, "alias", owned.alias, "type", "wireguard"); err != nil {
			return fail(err)
		}
		current := &transaction.owned[len(transaction.owned)-1]
		actual, exists, err := findWireGuardLink(options, owned.creationName)
		if err != nil || !exists || actual.Alias != "" && actual.Alias != owned.alias || actual.Info.Kind != "wireguard" {
			return fail(errors.Join(ErrWireGuardOwnership, err))
		}
		current.index = actual.Index
		if err := transaction.saveOwnership(); err != nil {
			return fail(err)
		}
		if _, err := runHostCommand(options.IP, "link", "set", "dev", owned.creationName, "alias", owned.alias); err != nil {
			return fail(err)
		}
		actual, exists, err = findWireGuardLink(options, owned.creationName)
		if err != nil || !exists || actual.Index != current.index || actual.Alias != owned.alias || actual.Info.Kind != "wireguard" {
			return fail(ErrWireGuardOwnership)
		}
		if _, err := runHostCommand(options.IP, "link", "set", "dev", owned.creationName, "name", link.Interface); err != nil {
			return fail(err)
		}
		actual, exists, err = findWireGuardLink(options, link.Interface)
		if err != nil || !exists || actual.Index != current.index || actual.Alias != owned.alias || actual.Info.Kind != "wireguard" {
			return fail(ErrWireGuardOwnership)
		}
		if err := configureWireGuardLink(options, current); err != nil {
			return fail(err)
		}
		if err := transaction.saveOwnership(); err != nil {
			return fail(err)
		}
		if err := verifyOwnedWireGuardLink(options, *current); err != nil {
			return fail(errors.Join(ErrWireGuardOwnership, err))
		}
	}
	if err := readbackWireGuard(*profile, options); err != nil {
		return fail(err)
	}
	return transaction, nil
}
