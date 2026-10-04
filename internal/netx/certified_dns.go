package netx

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// ResolveCertifiedIPs queries only the supplied literal resolvers. It never
// consults hosts, the OS resolver, a proxy or an application tunnel. The caller
// supplies its platform underlay dialer; answers are disposable dial addresses.
func ResolveCertifiedIPs(ctx context.Context, host string, servers []string, dial func(context.Context, string, string) (net.Conn, error)) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		return []netip.Addr{ip.Unmap()}, nil
	}
	if len(servers) == 0 {
		return nil, errors.New("hostname requires authenticated DNS resolvers")
	}
	for _, server := range servers {
		ip, err := netip.ParseAddr(server)
		if err != nil || ip.Zone() != "" || ip.String() != server || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("authenticated DNS resolver is not a canonical unicast address")
		}
	}
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	for _, server := range servers {
		var result []netip.Addr
		for _, kind := range []uint16{1, 28} {
			query := make([]byte, 12)
			if _, err := rand.Read(query[:2]); err != nil {
				return nil, err
			}
			binary.BigEndian.PutUint16(query[2:], 0x0100)
			binary.BigEndian.PutUint16(query[4:], 1)
			if host == "" || len(host) > 253 {
				return nil, errors.New("DNS name is invalid")
			}
			for _, label := range strings.Split(host, ".") {
				if len(label) == 0 || len(label) > 63 {
					return nil, errors.New("DNS name is invalid")
				}
				query = append(query, byte(len(label)))
				query = append(query, label...)
			}
			query = append(query, 0, byte(kind>>8), byte(kind), 0, 1)
			attempt, cancel := context.WithTimeout(ctx, 4*time.Second)
			response, err := exchangeDNS(attempt, dial, "udp", net.JoinHostPort(server, "53"), query)
			if err == nil && len(response) >= 4 && binary.BigEndian.Uint16(response[2:4])&0x0200 != 0 {
				response, err = exchangeDNS(attempt, dial, "tcp", net.JoinHostPort(server, "53"), query)
			}
			cancel()
			if err == nil {
				addresses, parseErr := DNSAnswers(query, response, kind)
				if parseErr == nil {
					result = append(result, addresses...)
				}
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if len(result) > 0 {
			slices.SortFunc(result, func(a, b netip.Addr) int { return a.Compare(b) })
			return slices.Compact(result), nil
		}
	}
	return nil, errors.New("authenticated DNS returned no usable address")
}

func exchangeDNS(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), network, address string, query []byte) ([]byte, error) {
	connection, err := dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	packet := query
	if network == "tcp" {
		packet = make([]byte, len(query)+2)
		binary.BigEndian.PutUint16(packet, uint16(len(query)))
		copy(packet[2:], query)
	}
	if _, err := connection.Write(packet); err != nil {
		return nil, err
	}
	if network == "tcp" {
		var length [2]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			return nil, err
		}
		answer := make([]byte, binary.BigEndian.Uint16(length[:]))
		_, err := io.ReadFull(connection, answer)
		return answer, err
	}
	answer := make([]byte, 65535)
	n, err := connection.Read(answer)
	return answer[:n], err
}
