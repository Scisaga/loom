package netx

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// ResolveCertifiedIPs queries only the supplied literal resolvers. It never
// consults hosts, the OS resolver, a proxy or an application tunnel. The caller
// supplies its platform underlay dialer; answers are disposable dial addresses.
// At most two resolvers run concurrently, each querying both address families.
// Both families share half the remaining caller budget, capped at four seconds.
// A completed usable resolver cancels competitors and waits for their sockets.
func ResolveCertifiedIPs(ctx context.Context, host string, servers []string, dial func(context.Context, string, string) (net.Conn, error)) ([]netip.Addr, error) {
	return resolveCertifiedIPs(ctx, host, servers, dial, nil)
}

func resolveCertifiedIPs(ctx context.Context, host string, servers []string, dial func(context.Context, string, string) (net.Conn, error), tlsConfig *tls.Config) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		return []netip.Addr{ip.Unmap()}, nil
	}
	if len(servers) == 0 {
		return nil, errors.New("hostname requires authenticated DNS resolvers")
	}
	if err := ValidateDNSResolvers(servers); err != nil {
		return nil, err
	}
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	budget := 4 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		budget = min(budget, time.Until(deadline)/2)
	}
	queries := make([][]byte, 2)
	for i, kind := range []uint16{1, 28} {
		query, err := certifiedDNSQuery(host, kind)
		if err != nil {
			return nil, err
		}
		queries[i] = query
	}
	attempts, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	// Allocate the one DNS budget across all two-resolver waves. Recomputing
	// half the remaining parent budget per wave would consume the dial budget.
	resolverBudget := budget / time.Duration((len(servers)+1)/2)
	results := make(chan []netip.Addr, 2)
	active, next := 0, 0
	start := func() {
		server := servers[next]
		next++
		active++
		go func() { results <- resolveCertifiedServer(attempts, server, queries, resolverBudget, dial, tlsConfig) }()
	}
	for active < 2 && next < len(servers) && attempts.Err() == nil {
		start()
	}
	for active > 0 {
		result := <-results
		active--
		if len(result) > 0 || attempts.Err() != nil {
			cancel()
			// Every attempt closes its sockets and joins both address families
			// before publishing a result, including attempts cancelled here.
			for active > 0 {
				other := <-results
				active--
				if len(result) == 0 {
					result = other
				}
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if len(result) == 0 {
				return nil, errors.New("authenticated DNS returned no usable address")
			}
			return result, nil
		}
		if next < len(servers) {
			start()
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("authenticated DNS returned no usable address")
}

func certifiedDNSQuery(host string, kind uint16) ([]byte, error) {
	if host == "" || len(host) > 253 {
		return nil, errors.New("DNS name is invalid")
	}
	query := make([]byte, 12)
	if _, err := rand.Read(query[:2]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(query[2:], 0x0100)
	binary.BigEndian.PutUint16(query[4:], 1)
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, errors.New("DNS name is invalid")
		}
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	return append(query, 0, byte(kind>>8), byte(kind), 0, 1), nil
}

func resolveCertifiedServer(ctx context.Context, server string, queries [][]byte, budget time.Duration, dial func(context.Context, string, string) (net.Conn, error), tlsConfig *tls.Config) []netip.Addr {
	attempt, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	resolver, err := ParseDNSResolver(server)
	if err != nil {
		return nil
	}
	var client *http.Client
	if resolver.HTTPS != "" {
		config := &tls.Config{MinVersion: tls.VersionTLS12}
		if tlsConfig != nil {
			config = tlsConfig.Clone()
		}
		// Transport may finish a response while a competing dial is still
		// unwinding. Own and join this attempt's sockets before publishing it.
		var lock sync.Mutex
		var dialing sync.WaitGroup
		var sockets []net.Conn
		closed := false
		transport := &http.Transport{Proxy: nil, TLSClientConfig: config, MaxConnsPerHost: 2, MaxResponseHeaderBytes: 16 << 10, ResponseHeaderTimeout: budget, TLSHandshakeTimeout: budget}
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			lock.Lock()
			if closed {
				lock.Unlock()
				return nil, context.Canceled
			}
			dialing.Add(1)
			lock.Unlock()
			defer dialing.Done()
			pending, stop := context.WithCancel(ctx)
			detach := context.AfterFunc(attempt, stop)
			defer detach()
			defer stop()
			connection, err := dial(pending, network, address)
			if err != nil {
				return nil, err
			}
			lock.Lock()
			defer lock.Unlock()
			if closed {
				_ = connection.Close()
				return nil, context.Canceled
			}
			sockets = append(sockets, connection)
			return connection, nil
		}
		defer func() {
			cancel()
			lock.Lock()
			closed = true
			owned := sockets
			lock.Unlock()
			transport.CloseIdleConnections()
			for _, connection := range owned {
				_ = connection.Close()
			}
			dialing.Wait()
		}()
		client = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("DoH redirect is forbidden") }}
	}
	answers := make(chan []netip.Addr, len(queries))
	for _, query := range queries {
		go func() {
			var response []byte
			var err error
			if client != nil {
				response, err = exchangeDoH(attempt, client, resolver.HTTPS, query)
			} else {
				response, err = exchangeDNS(attempt, dial, "udp", resolver.Address, query)
				if err == nil && len(response) >= 4 && binary.BigEndian.Uint16(response[2:4])&0x0200 != 0 {
					response, err = exchangeDNS(attempt, dial, "tcp", resolver.Address, query)
				}
			}
			var addresses []netip.Addr
			if err == nil {
				addresses, _ = DNSAnswers(query, response, binary.BigEndian.Uint16(query[len(query)-4:]))
			}
			answers <- addresses
		}()
	}
	var result []netip.Addr
	for range queries {
		result = append(result, <-answers...)
	}
	slices.SortFunc(result, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(result)
}

func exchangeDoH(ctx context.Context, client *http.Client, endpoint string, query []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || response.StatusCode != http.StatusOK || mediaType != "application/dns-message" || response.Header.Get("Content-Encoding") != "" || response.ContentLength > 65535 {
		return nil, errors.New("DoH response status, type or length is invalid")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil || len(body) < 12 || len(body) > 65535 || binary.BigEndian.Uint16(body[2:4])&0x0200 != 0 {
		return nil, errors.New("DoH response is incomplete or truncated")
	}
	return body, nil
}

func exchangeDNS(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), network, address string, query []byte) ([]byte, error) {
	connection, err := dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = connection.Close()
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
		_ = connection.Close()
	}()
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
