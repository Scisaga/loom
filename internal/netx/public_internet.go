package netx

import (
	"net/netip"
	"sort"
	"strings"
)

// PublicInternetExclusions is execution input shared by capture, permission
// matching and the final dial guard. It does not turn a default route into a
// capture grant. Exact management and underlay endpoints are restricted too by
// the host adapter's current authenticated projection.
var publicInternetExclusions = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{224}), 3), netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0/96"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

var publicInternetCapturePrefixes = buildPublicInternetPrefixes()

// PublicInternetPrefixes is the positive CIDR projection of the same public
// address scope enforced by IsPublicInternetAddress. Host-specific endpoint
// exclusions and separately authorized LANs remain the host adapter's inputs.
func PublicInternetPrefixes() []string {
	return append([]string(nil), publicInternetCapturePrefixes...)
}

func buildPublicInternetPrefixes() []string {
	values := []netip.Prefix{
		netip.PrefixFrom(netip.IPv4Unspecified(), 0),
		netip.PrefixFrom(netip.IPv6Unspecified(), 0),
	}
	for _, denied := range publicInternetExclusions {
		var next []netip.Prefix
		for _, prefix := range values {
			next = append(next, subtractCapturePrefix(prefix, denied)...)
		}
		values = next
	}
	sort.Slice(values, func(i, j int) bool {
		if order := values[i].Addr().Compare(values[j].Addr()); order != 0 {
			return order < 0
		}
		return values[i].Bits() < values[j].Bits()
	})
	result := make([]string, len(values))
	for i, prefix := range values {
		result[i] = prefix.String()
	}
	return result
}

func subtractCapturePrefix(prefix, denied netip.Prefix) []netip.Prefix {
	if !prefix.Overlaps(denied) {
		return []netip.Prefix{prefix}
	}
	if denied.Bits() <= prefix.Bits() {
		return nil
	}
	bits := prefix.Bits()
	var right netip.Addr
	if prefix.Addr().Is4() {
		value := prefix.Addr().As4()
		value[bits/8] |= 1 << (7 - bits%8)
		right = netip.AddrFrom4(value)
	} else {
		value := prefix.Addr().As16()
		value[bits/8] |= 1 << (7 - bits%8)
		right = netip.AddrFrom16(value)
	}
	left := netip.PrefixFrom(prefix.Addr(), bits+1)
	return append(subtractCapturePrefix(left, denied), subtractCapturePrefix(netip.PrefixFrom(right, bits+1), denied)...)
}

func IsPublicInternetAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range publicInternetExclusions {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func IsPublicInternetName(name string) bool {
	if name == "" || !strings.Contains(name, ".") {
		return false
	}
	for _, suffix := range []string{"loom", "local", "localhost", "invalid", "home.arpa"} {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return false
		}
	}
	return true
}

func PublicInternetExclusions() []string {
	result := make([]string, len(publicInternetExclusions))
	for index, prefix := range publicInternetExclusions {
		result[index] = prefix.String()
	}
	return result
}
