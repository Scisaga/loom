package protocol

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// ConnectionTargetKey scopes a routing hint to one transport. It does not
// change the host/port Service permission checked by the receiving node.
func ConnectionTargetKey(network, host string, port uint16) (string, error) {
	if network != "tcp" && network != "udp" || !CanonicalHost(host) || port == 0 {
		return "", errors.New("invalid network connection target")
	}
	return network + "://" + net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// ParseConnectionTargetKey rejects bare and noncanonical keys. Historical
// report targets are handled only by their signed-report reader.
func ParseConnectionTargetKey(value string) (network, host string, port uint16, err error) {
	network, address, ok := strings.Cut(value, "://")
	if !ok {
		return "", "", 0, errors.New("connection target lacks its network")
	}
	host, text, splitErr := net.SplitHostPort(address)
	number, portErr := strconv.ParseUint(text, 10, 16)
	if splitErr != nil || portErr != nil {
		return "", "", 0, errors.New("invalid network connection target")
	}
	key, keyErr := ConnectionTargetKey(network, host, uint16(number))
	if keyErr != nil || key != value {
		return "", "", 0, errors.New("noncanonical network connection target")
	}
	return network, host, uint16(number), nil
}
