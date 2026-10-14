package clientadapter

import (
	"context"
	"crypto/tls"
	"golang.org/x/net/proxy"
	"io"
	"loom/internal/control"
	"net"
	"net/http"
	"time"
)

// ProbeCandidateBusiness uses the existing authenticated local diagnostic
// entry. Its certified rules select one candidate and enforce the same Service
// exclusions. It does not change a production selector or close connections.
func ProbeCandidateBusiness(ctx context.Context, candidate, target string) ProbeResult {
	return probeCandidateBusiness(ctx, candidate, target, &tls.Config{MinVersion: tls.VersionTLS12})
}

func probeCandidateBusiness(ctx context.Context, candidate, target string, tlsConfig *tls.Config) ProbeResult {
	diagnostic, ok := ctx.Value(nativeDiagnosticKey{}).(nativeDiagnostic)
	if !ok || control.ValidateDigest(candidate) != nil || control.ValidateHTTPSURL(target) != nil {
		return ProbeResult{Action: "https_request", Description: "candidate diagnostic unavailable"}
	}
	started := time.Now()
	pending, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	dialer, err := proxy.SOCKS5("tcp", NativeProbeAddress, &proxy.Auth{User: candidate, Password: diagnostic.secret}, diagnosticDialer{diagnostic, pending})
	if err != nil {
		return ProbeResult{Action: "https_request", Description: "candidate diagnostic invalid"}
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: tlsConfig, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(pending, http.MethodGet, target, nil)
	if err != nil {
		return ProbeResult{Action: "https_request", Description: "candidate target invalid"}
	}
	response, err := client.Do(request)
	result := ProbeResult{Action: "https_request", Target: target, Metric: time.Since(started), Description: "candidate HTTPS failed"}
	if err != nil {
		return result
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	result.Metric = time.Since(started)
	result.Available = err == nil && response.StatusCode >= 200 && response.StatusCode < 400
	if result.Available {
		result.Description = "candidate HTTPS response received"
	}
	return result
}

func candidateDiagnosticAvailable(ctx context.Context) bool {
	_, ok := ctx.Value(nativeDiagnosticKey{}).(nativeDiagnostic)
	return ok
}
