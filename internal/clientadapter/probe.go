package clientadapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"loom/internal/netx"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"loom/internal/control"
)

// BusinessProbe uses the local SOCKS listener for both HTTPS and UDP/DNS.
// No request or name lookup can silently use the host's direct network path.
func BusinessProbe(proxyAddress, dnsAddress, target string) (Probe, error) {
	host, port, err := net.SplitHostPort(proxyAddress)
	proxyIP := net.ParseIP(host)
	proxyPort, portErr := strconv.Atoi(port)
	parsed, targetErr := url.Parse(target)
	if err != nil || proxyIP == nil || !proxyIP.IsLoopback() || portErr != nil || proxyPort < 1 || proxyPort > 65535 ||
		net.ParseIP(dnsAddress) == nil || targetErr != nil || control.ValidateHTTPSURL(target) != nil {
		return nil, errors.New("certified business probe target or local proxy is invalid")
	}
	return func(ctx context.Context) ProbeResult {
		started := time.Now()
		probeContext, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		addresses, err := probeDNS(probeContext, proxyAddress, dnsAddress, parsed.Hostname())
		if err != nil {
			return ProbeResult{Metric: time.Since(started), Description: "UDP/DNS: " + err.Error()}
		}
		if err := probeHTTPS(probeContext, proxyAddress, parsed.String(), addresses, &tls.Config{MinVersion: tls.VersionTLS12}); err != nil {
			return ProbeResult{Metric: time.Since(started), Description: "TCP/TLS: " + err.Error()}
		}
		return ProbeResult{Available: true, Metric: time.Since(started), Description: "TCP/TLS and UDP/DNS succeeded"}
	}, nil
}

// HTTPSBusinessProbe sends the original authority through SOCKS. Name resolution
// belongs to the selected proxy path; an absent certified DNS service neither
// invents a DNS permission nor prevents testing an authorized HTTPS Service.
func HTTPSBusinessProbe(proxyAddress, target string) (Probe, error) {
	host, port, err := net.SplitHostPort(proxyAddress)
	ip := net.ParseIP(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || number < 1 || number > 65535 || control.ValidateHTTPSURL(target) != nil {
		return nil, errors.New("HTTPS probe target or local proxy is invalid")
	}
	return func(ctx context.Context) ProbeResult {
		started := time.Now()
		pending, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				connection, _, err := socksRequest(ctx, proxyAddress, 1, address)
				return connection, err
			}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		request, err := http.NewRequestWithContext(pending, http.MethodGet, target, nil)
		if err != nil {
			return ProbeResult{Description: "HTTPS request invalid"}
		}
		response, err := client.Do(request)
		if err != nil {
			return ProbeResult{Metric: time.Since(started), Description: "HTTPS request failed"}
		}
		defer response.Body.Close()
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return ProbeResult{Available: readErr == nil && response.StatusCode >= 200 && response.StatusCode < 400,
			Metric: time.Since(started), Description: "HTTPS response received"}
	}, nil
}

func probeHTTPS(ctx context.Context, proxyAddress, target string, addresses []netip.Addr, tlsConfig *tls.Config) error {
	if len(addresses) == 0 {
		return errors.New("certified DNS returned no target address")
	}
	var lastErr error
	for _, address := range addresses {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !address.IsValid() || address.Zone() != "" {
			return errors.New("certified DNS returned an invalid target address")
		}
		// Give every certified address a bounded turn within the original probe
		// deadline. TLS identity and HTTP authority remain the original URL.
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		lastErr = probeHTTPSAddress(attempt, proxyAddress, target, address, tlsConfig)
		cancel()
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}

func probeHTTPSAddress(ctx context.Context, proxyAddress, target string, address netip.Addr, tlsConfig *tls.Config) error {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true,
		TLSClientConfig: tlsConfig,
		DialContext: func(ctx context.Context, _, requested string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(requested)
			if err != nil {
				return nil, err
			}
			connection, _, err := socksRequest(ctx, proxyAddress, 1, net.JoinHostPort(address.String(), port))
			return connection, err
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return fmt.Errorf("business probe returned HTTP status %d", response.StatusCode)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return err
}

func socksAddress(address string) ([]byte, error) {
	host, port, err := net.SplitHostPort(address)
	value, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || value < 0 || value > 65535 || len(host) == 0 || len(host) > 255 {
		return nil, errors.New("SOCKS target address is invalid")
	}
	var body []byte
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			body = append([]byte{1}, ipv4...)
		} else {
			body = append([]byte{4}, ip...)
		}
	} else {
		body = append([]byte{3, byte(len(host))}, host...)
	}
	return append(body, byte(value>>8), byte(value)), nil
}

func readSOCKSAddress(reader io.Reader) (string, error) {
	header := make([]byte, 1)
	if _, err := io.ReadFull(reader, header); err != nil {
		return "", err
	}
	size, domain := 0, false
	switch header[0] {
	case 1:
		size = net.IPv4len
	case 4:
		size = net.IPv6len
	case 3:
		if _, err := io.ReadFull(reader, header); err != nil {
			return "", err
		}
		size, domain = int(header[0]), true
	default:
		return "", errors.New("SOCKS response address is invalid")
	}
	if size == 0 {
		return "", errors.New("SOCKS response address is empty")
	}
	body := make([]byte, size+2)
	if _, err := io.ReadFull(reader, body); err != nil {
		return "", err
	}
	host := string(body[:size])
	if !domain {
		host = net.IP(body[:size]).String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(body[size:])))), nil
}

func socksRequest(ctx context.Context, proxyAddress string, command byte, target string) (net.Conn, string, error) {
	address, err := socksAddress(target)
	if err != nil {
		return nil, "", err
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, "", err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = connection.Close()
		}
	}()
	if deadline, found := ctx.Deadline(); found {
		_ = connection.SetDeadline(deadline)
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stopCancel()
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		return nil, "", err
	}
	hello := make([]byte, 2)
	if _, err := io.ReadFull(connection, hello); err != nil || !bytes.Equal(hello, []byte{5, 0}) {
		return nil, "", errors.New("local SOCKS authentication failed")
	}
	if _, err := connection.Write(append([]byte{5, command, 0}, address...)); err != nil {
		return nil, "", err
	}
	reply := make([]byte, 3)
	if _, err := io.ReadFull(connection, reply); err != nil || !bytes.Equal(reply, []byte{5, 0, 0}) {
		return nil, "", errors.New("local SOCKS request failed")
	}
	bound, err := readSOCKSAddress(connection)
	if err != nil {
		return nil, "", err
	}
	succeeded = true
	return connection, bound, nil
}

func probeDNS(ctx context.Context, proxyAddress, dnsAddress, name string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(name); err == nil && address.Zone() == "" {
		return []netip.Addr{address.Unmap()}, nil
	}
	var addresses []netip.Addr
	for _, kind := range []uint16{1, 28} {
		answer, err := probeDNSQuestion(ctx, proxyAddress, dnsAddress, name, kind)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, answer...)
	}
	// Ordering is independent of answer order and host routing/resolver state.
	slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	addresses = slices.Compact(addresses)
	if len(addresses) == 0 {
		return nil, errors.New("certified DNS returned no target address")
	}
	return addresses, nil
}

func probeDNSQuestion(ctx context.Context, proxyAddress, dnsAddress, name string, kind uint16) ([]netip.Addr, error) {
	query := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, query[:2]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, errors.New("certified DNS probe name is invalid")
		}
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, byte(kind>>8), byte(kind), 0, 1)
	if len(query) > 271 {
		return nil, errors.New("certified DNS probe name is too long")
	}
	control, relay, err := socksRequest(ctx, proxyAddress, 3, "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	defer control.Close()
	host, port, err := net.SplitHostPort(relay)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() && !ip.IsUnspecified() {
		return nil, errors.New("local SOCKS UDP relay is not a loopback address")
	}
	if ip.IsUnspecified() {
		host, _, _ = net.SplitHostPort(proxyAddress)
		relay = net.JoinHostPort(host, port)
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "udp", relay)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stopCancel()
	if deadline, found := ctx.Deadline(); found {
		_ = connection.SetDeadline(deadline)
	}
	target := net.JoinHostPort(dnsAddress, "53")
	address, _ := socksAddress(target)
	packet := append(append([]byte{0, 0, 0}, address...), query...)
	if _, err := connection.Write(packet); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	read, err := connection.Read(response)
	if err != nil {
		return nil, err
	}
	if read < 4 || !bytes.Equal(response[:3], []byte{0, 0, 0}) {
		return nil, errors.New("SOCKS UDP response is invalid")
	}
	reader := bytes.NewReader(response[3:read])
	source, err := readSOCKSAddress(reader)
	if err != nil || source != target {
		return nil, errors.New("SOCKS DNS response source differs from the certified resolver")
	}
	answer, _ := io.ReadAll(reader)
	return netx.DNSAnswers(query, answer, kind)
}
