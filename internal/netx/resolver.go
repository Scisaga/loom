package netx

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// DNSResolver is a parsed value, never an independent configuration authority.
type DNSResolver struct {
	IP      netip.Addr
	HTTPS   string
	Address string
}

func ParseDNSResolver(value string) (DNSResolver, error) {
	validIP := func(value string) (netip.Addr, bool) {
		ip, err := netip.ParseAddr(value)
		return ip, err == nil && ip.Zone() == "" && !ip.Is4In6() && !ip.IsUnspecified() && !ip.IsMulticast() && ip.String() == value
	}
	if ip, ok := validIP(value); ok {
		return DNSResolver{IP: ip, Address: net.JoinHostPort(value, "53")}, nil
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || strings.ContainsAny(value, "?#") || u.Opaque != "" {
		return DNSResolver{}, errors.New("DNS resolver requires a canonical IP or literal-IP HTTPS URL")
	}
	ip, ok := validIP(u.Hostname())
	if !ok || !(ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) || u.Path == "" || !strings.HasPrefix(u.Path, "/") || path.Clean(u.Path) != u.Path || u.RawPath != "" || u.EscapedPath() != u.Path {
		return DNSResolver{}, errors.New("DoH requires a canonical literal IP and absolute path")
	}
	port := u.Port()
	host := ip.String()
	if ip.Is6() {
		host = "[" + host + "]"
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || n == 443 || strconv.Itoa(n) != port {
			return DNSResolver{}, errors.New("DoH port is not canonical")
		}
		host += ":" + port
	} else {
		port = "443"
	}
	if value != "https://"+host+u.Path {
		return DNSResolver{}, errors.New("DoH URL is not canonical")
	}
	return DNSResolver{IP: ip, HTTPS: value, Address: net.JoinHostPort(ip.String(), port)}, nil
}

func (r DNSResolver) RuntimeAddress() string {
	if r.HTTPS != "" {
		return r.HTTPS
	}
	return "udp://" + r.Address
}

// ValidateDNSResolvers accepts the same transport for every element. Ordering
// belongs to the containing canonical value; operational callers may use a list.
func ValidateDNSResolvers(values []string) error {
	var encrypted bool
	for i, value := range values {
		r, err := ParseDNSResolver(value)
		if err != nil {
			return err
		}
		if i > 0 && encrypted != (r.HTTPS != "") {
			return errors.New("DNS resolvers cannot mix HTTPS and plaintext")
		}
		encrypted = r.HTTPS != ""
	}
	return nil
}

// Presets fill reviewed drafts and the single-host bootstrap lookup only.
// Accepted device Views never fall back to these values.
func DomesticDNSResolvers() []string {
	return []string{"https://223.5.5.5/dns-query", "https://223.6.6.6/dns-query"}
}

func GlobalDNSResolvers() []string {
	return []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}
}
