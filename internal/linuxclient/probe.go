package linuxclient

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"loom/internal/control"
)

func namespaceBusinessProbe(ctx context.Context, namespace *os.File, target string) ProbeResult {
	started := time.Now()
	result := ProbeResult{Action: "https_request"}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if control.ValidateHTTPSURL(target) != nil {
		result.Description = "business probe target is invalid"
		return result
	}
	dial := namespaceDialer(namespace)
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dial(ctx, network, "172.19.0.2:53")
	}}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(host) != nil {
			return dial(ctx, network, address)
		}
		addresses, err := resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		var failures []error
		for _, ip := range addresses {
			connection, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return connection, nil
			}
			failures = append(failures, err)
		}
		return nil, errors.Join(append(failures, errors.New("capture DNS returned no reachable business address"))...)
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err == nil {
		var response *http.Response
		response, err = client.Do(request)
		if err == nil {
			_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			if response.StatusCode < 200 || response.StatusCode >= 400 {
				err = fmt.Errorf("business probe returned HTTP status %d", response.StatusCode)
			}
		}
	}
	result.Metric = time.Since(started)
	result.Available = err == nil
	result.Description = "HTTPS through the isolated TUN succeeded"
	if err != nil {
		result.Description = "HTTPS through the isolated TUN failed"
	}
	return result
}

// businessProbe uses only the authenticated DNS and HTTPS target supplied by
// the caller, after selector readback within the isolated access namespace.
func businessProbe(ctx context.Context, dnsAddress, target string) ProbeResult {
	started := time.Now()
	probeContext, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := probeTCP(probeContext, dnsAddress, target); err != nil {
		return ProbeResult{Metric: time.Since(started), Description: "TCP: " + err.Error()}
	}
	parsed, _ := url.Parse(target)
	if err := probeDNS(probeContext, dnsAddress, parsed.Hostname()); err != nil {
		return ProbeResult{Metric: time.Since(started), Description: "UDP/DNS: " + err.Error()}
	}
	return ProbeResult{Available: true, Metric: time.Since(started), Description: "TCP, UDP and DNS succeeded"}
}

func probeTCP(ctx context.Context, dnsAddress, target string) error {
	dnsServer, err := dnsEndpoint(dnsAddress)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(target)
	if err != nil || control.ValidateHTTPSURL(target) != nil {
		return errors.New("business probe target is invalid")
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", dnsServer)
		},
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true,
		DialContext:     (&net.Dialer{Timeout: 5 * time.Second, Resolver: resolver}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
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

func dnsQuery(name string) ([]byte, uint16, error) {
	idBytes := make([]byte, 2)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idBytes)
	body := make([]byte, 12)
	binary.BigEndian.PutUint16(body[0:2], id)
	binary.BigEndian.PutUint16(body[2:4], 0x0100)
	binary.BigEndian.PutUint16(body[4:6], 1)
	labelStart := 0
	for index := 0; index <= len(name); index++ {
		if index != len(name) && name[index] != '.' {
			continue
		}
		label := name[labelStart:index]
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, errors.New("DNS probe name is invalid")
		}
		body = append(body, byte(len(label)))
		body = append(body, label...)
		labelStart = index + 1
	}
	body = append(body, 0, 0, 1, 0, 1)
	return body, id, nil
}

func probeDNS(ctx context.Context, dnsAddress, name string) error {
	query, id, err := dnsQuery(name)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	dnsServer, err := dnsEndpoint(dnsAddress)
	if err != nil {
		return err
	}
	connection, err := dialer.DialContext(ctx, "udp", dnsServer)
	if err != nil {
		return err
	}
	defer connection.Close()
	deadline, found := ctx.Deadline()
	if found {
		_ = connection.SetDeadline(deadline)
	}
	if _, err := connection.Write(query); err != nil {
		return err
	}
	response := make([]byte, 1500)
	read, err := connection.Read(response)
	if err != nil {
		return err
	}
	if read < 12 || binary.BigEndian.Uint16(response[0:2]) != id || binary.BigEndian.Uint16(response[2:4])&0x8000 == 0 ||
		binary.BigEndian.Uint16(response[2:4])&0x000f != 0 || binary.BigEndian.Uint16(response[6:8]) == 0 {
		return fmt.Errorf("DNS response is not a successful answer")
	}
	return nil
}

func dnsEndpoint(address string) (string, error) {
	if net.ParseIP(address) == nil {
		return "", errors.New("DNS probe address is invalid")
	}
	return net.JoinHostPort(address, "53"), nil
}
