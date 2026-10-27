package clientadapter

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"loom/internal/control"
)

// HTTPSBusinessProbe sends the original authority through SOCKS. Name resolution
// belongs to the selected proxy path; an absent certified DNS service neither
// invents a DNS permission nor prevents testing an authorized HTTPS Service.
func HTTPSBusinessProbe(proxyAddress, target string) (Probe, error) {
	return httpsBusinessProbe(proxyAddress, target, &tls.Config{MinVersion: tls.VersionTLS12})
}

func httpsBusinessProbe(proxyAddress, target string, tlsConfig *tls.Config) (Probe, error) {
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
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: tlsConfig,
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				connection, _, err := socksRequest(ctx, proxyAddress, 1, address)
				return connection, err
			}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		request, err := http.NewRequestWithContext(pending, http.MethodGet, target, nil)
		if err != nil {
			return ProbeResult{Action: "https_request", Description: "HTTPS request invalid"}
		}
		response, err := client.Do(request)
		if err != nil {
			return ProbeResult{Action: "https_request", Metric: time.Since(started), Description: "HTTPS request failed"}
		}
		defer response.Body.Close()
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return ProbeResult{Action: "https_request", Available: readErr == nil && response.StatusCode >= 200 && response.StatusCode < 400,
			Metric: time.Since(started), Description: "HTTPS response received"}
	}, nil
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
