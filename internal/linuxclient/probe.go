package linuxclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"loom/internal/control"
	"loom/internal/netx"
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
		// Query only this capture's DNS. Its synthetic address carries the
		// original domain through TUN; hosts and the host resolver cannot
		// substitute a client-side business address.
		addresses, err := netx.ResolveCertifiedIPs(ctx, host, []string{"172.19.0.2"}, dial)
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
