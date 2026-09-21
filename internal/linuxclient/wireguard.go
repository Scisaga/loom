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

	"loom/internal/control"
)

type wireGuardSnapshot struct {
	Interface string
	Existed   bool
	Config    string
	Addresses []string
}

type wireGuardTransaction struct {
	options   Options
	directory string
	snapshots []wireGuardSnapshot
	committed bool
}

type ipAddressDocument struct {
	Addresses []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
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

func (transaction *wireGuardTransaction) Rollback() {
	if transaction == nil || transaction.committed {
		return
	}
	for index := len(transaction.snapshots) - 1; index >= 0; index-- {
		snapshot := transaction.snapshots[index]
		if !snapshot.Existed {
			_, _ = runHostCommand(transaction.options.IP, "link", "delete", "dev", snapshot.Interface)
			continue
		}
		configPath := filepath.Join(transaction.directory, snapshot.Interface+".conf")
		_ = os.WriteFile(configPath, []byte(snapshot.Config), 0o600)
		_, _ = runHostCommand(transaction.options.WireGuard, "syncconf", snapshot.Interface, configPath)
		_, _ = runHostCommand(transaction.options.IP, "address", "flush", "dev", snapshot.Interface)
		for _, address := range snapshot.Addresses {
			_, _ = runHostCommand(transaction.options.IP, "address", "add", address, "dev", snapshot.Interface)
		}
		_, _ = runHostCommand(transaction.options.IP, "link", "set", "dev", snapshot.Interface, "up")
	}
	_ = os.RemoveAll(transaction.directory)
}

func (transaction *wireGuardTransaction) Commit() {
	if transaction == nil {
		return
	}
	transaction.committed = true
	_ = os.RemoveAll(transaction.directory)
}

func snapshotWireGuardInterface(options Options, name string) (wireGuardSnapshot, error) {
	snapshot := wireGuardSnapshot{Interface: name}
	if _, err := runHostCommand(options.IP, "link", "show", "dev", name); err != nil {
		return snapshot, nil
	}
	snapshot.Existed = true
	config, err := runHostCommand(options.WireGuard, "showconf", name)
	if err != nil || len(config) == 0 || len(config) > 1<<20 {
		return snapshot, errors.New("existing interface is not a readable WireGuard interface")
	}
	addresses, err := interfaceAddresses(options.IP, name)
	if err != nil {
		return snapshot, err
	}
	snapshot.Config, snapshot.Addresses = string(config), addresses
	return snapshot, nil
}

func configureWireGuardLink(options Options, link control.ServerWireGuardRuntime, localPublicKey string) error {
	if _, err := runHostCommand(options.IP, "link", "show", "dev", link.Interface); err != nil {
		if _, err := runHostCommand(options.IP, "link", "add", "dev", link.Interface, "type", "wireguard"); err != nil {
			return err
		}
	}
	peers, err := runHostCommand(options.WireGuard, "show", link.Interface, "peers")
	if err != nil {
		return err
	}
	for _, peer := range strings.Fields(string(peers)) {
		if peer != link.PeerPublicKey {
			if _, err := runHostCommand(options.WireGuard, "set", link.Interface, "peer", peer, "remove"); err != nil {
				return err
			}
		}
	}
	arguments := []string{"set", link.Interface}
	actualPublic, _ := runHostCommand(options.WireGuard, "show", link.Interface, "public-key")
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
		// before and after wg reopens it and roll back the transaction on change.
		arguments = append(arguments, "private-key", options.WireGuardPrivateKey)
	}
	if link.Mode == "acceptor" {
		// A peer keeps its endpoint and persistent keepalive until explicitly
		// replaced. Remove it only when an old initiator configuration is still
		// present; reapplying an unchanged acceptor remains handshake-preserving.
		if containsWireGuardInitiatorState(options.WireGuard, link.Interface, link.PeerPublicKey) {
			if _, err := runHostCommand(options.WireGuard, "set", link.Interface, "peer", link.PeerPublicKey, "remove"); err != nil {
				return err
			}
		}
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
	if needsPrivateKey {
		after, err := os.Lstat(options.WireGuardPrivateKey)
		if err != nil || !os.SameFile(privateKeyInfo, after) {
			return errors.New("WireGuard private key changed during configuration")
		}
	}
	if _, err := runHostCommand(options.IP, "address", "replace", link.LocalAddress, "dev", link.Interface); err != nil {
		return err
	}
	_, err = runHostCommand(options.IP, "link", "set", "dev", link.Interface, "up")
	return err
}

func wireGuardPeerValue(wg, name, field, peer string) string {
	body, err := runHostCommand(wg, "show", name, field)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[0] == peer {
			return strings.Join(parts[1:], " ")
		}
	}
	return ""
}

func containsWireGuardInitiatorState(wg, name, peer string) bool {
	endpoint := wireGuardPeerValue(wg, name, "endpoints", peer)
	keepalive := wireGuardPeerValue(wg, name, "persistent-keepalive", peer)
	return endpoint != "" && endpoint != "(none)" || keepalive != "" && keepalive != "off" && keepalive != "0"
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
	if net.ParseIP(expectedHost) == nil {
		return net.ParseIP(actualHost) != nil || strings.EqualFold(expectedHost, actualHost)
	}
	return net.ParseIP(expectedHost).Equal(net.ParseIP(actualHost))
}

func readbackWireGuard(profile control.ServerRuntimeProfile, options Options) error {
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
	}
	return nil
}

func applyWireGuard(profile, previous *control.ServerRuntimeProfile, server *control.ServerIntent, options Options) (*wireGuardTransaction, error) {
	if profile == nil && previous == nil {
		return &wireGuardTransaction{committed: true}, nil
	}
	if profile == nil {
		profile = &control.ServerRuntimeProfile{}
	}
	if len(profile.WireGuard) != 0 && server == nil {
		return nil, errors.New("WireGuard runtime has no certified server identity")
	}
	localPublicKey := ""
	if len(profile.WireGuard) != 0 {
		publicKey, err := privateWireGuardPublicKey(options.WireGuard, options.WireGuardPrivateKey)
		if err != nil || publicKey != server.WGPublicKey {
			return nil, errors.New("WireGuard private key does not match the certified server identity")
		}
		localPublicKey = publicKey
	}
	// Ubuntu's wg AppArmor profile permits configuration files only below
	// /etc/wireguard. Rollback material is owner-only and short-lived, but it
	// must live inside that allowed boundary or syncconf cannot restore it.
	directory, err := os.MkdirTemp("/etc/wireguard", ".loom-rollback-*")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		return nil, err
	}
	transaction := &wireGuardTransaction{options: options, directory: directory}
	desired := map[string]bool{}
	for _, link := range profile.WireGuard {
		desired[link.Interface] = true
	}
	stale := map[string]bool{}
	if previous != nil {
		for _, link := range previous.WireGuard {
			stale[link.Interface] = true
		}
	}
	for name := range stale {
		if desired[name] {
			continue
		}
		snapshot, snapshotErr := snapshotWireGuardInterface(options, name)
		if snapshotErr != nil {
			transaction.Rollback()
			return nil, snapshotErr
		}
		if !snapshot.Existed {
			continue
		}
		transaction.snapshots = append(transaction.snapshots, snapshot)
		if _, deleteErr := runHostCommand(options.IP, "link", "delete", "dev", name); deleteErr != nil {
			transaction.Rollback()
			return nil, deleteErr
		}
	}
	for _, link := range profile.WireGuard {
		snapshot, err := snapshotWireGuardInterface(options, link.Interface)
		if err != nil {
			transaction.Rollback()
			return nil, err
		}
		transaction.snapshots = append(transaction.snapshots, snapshot)
		if err := configureWireGuardLink(options, link, localPublicKey); err != nil {
			transaction.Rollback()
			return nil, err
		}
	}
	if err := readbackWireGuard(*profile, options); err != nil {
		transaction.Rollback()
		return nil, err
	}
	return transaction, nil
}
