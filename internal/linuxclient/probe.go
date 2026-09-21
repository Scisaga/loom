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
	"time"
)

// BusinessProbe verifies a real TCP/TLS exchange and a UDP DNS exchange after
// the selector has been read back. DNS is deliberately carried over UDP so the
// one bounded probe covers the three issue-required data-plane classes.
func BusinessProbe(ctx context.Context) ProbeResult {
	return businessProbe(ctx, "1.1.1.1", "https://www.baidu.com/")
}

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
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.Port() != "" && parsed.Port() != "443" {
		return errors.New("business probe target is invalid")
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", dnsServer)
		},
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true,
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
