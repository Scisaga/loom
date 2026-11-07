package clientadapter

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"loom/internal/control"
	"loom/protocol"
)

// ProbeEgressBusiness consumes an exit task derived from the current accepted
// View. The existing worker owns qualification, the budget and the commit fence.
// Local native I/O supplies the platform underlay; it cannot select a Policy.
func ProbeEgressBusiness(ctx context.Context, probe control.EgressProbe) ProbeResult {
	diagnostic, ok := ctx.Value(nativeDiagnosticKey{}).(nativeDiagnostic)
	if !ok {
		return ProbeResult{Deferred: true, Action: "https_request", Description: "exit-local I/O unavailable"}
	}
	result, err := runMeasurement(ctx, measurementIdentity(ctx, "egress-https", diagnostic.secret, probe.SpecDigest), 32<<10, func(pending context.Context) (ProbeResult, error) {
		return probeEgressBusiness(pending, probe, &tls.Config{MinVersion: tls.VersionTLS12}), nil
	})
	if err != nil {
		return ProbeResult{Deferred: errors.Is(err, ErrMeasurementDeferred) || errors.Is(err, context.Canceled), Action: "https_request", Description: "exit-local measurement deferred"}
	}
	return result
}

func probeEgressBusiness(ctx context.Context, probe control.EgressProbe, tlsConfig *tls.Config) ProbeResult {
	diagnostic, ok := ctx.Value(nativeDiagnosticKey{}).(nativeDiagnostic)
	if !ok || control.ValidateDigest(probe.SpecDigest) != nil || control.ValidateHTTPSURL(probe.Target) != nil || !probe.PublicInternet {
		return ProbeResult{Deferred: true, Action: "https_request", Description: "invalid exit-local task"}
	}
	started := time.Now()
	pending, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	return probeHTTPS(pending, probe.Target, tlsConfig, func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialNativeEgress(ctx, diagnostic, network, address)
	}, started, nil)
}

type egressConn struct {
	net.Conn
	reader *bufio.Reader
}

func (conn *egressConn) Read(body []byte) (int, error) { return conn.reader.Read(body) }

// CONNECT owns only establishment. After handoff, net/http owns cancellation
// and closure for its TLS/HTTP exchange. The native side retains the original
// attempt deadline and its server lifetime, independently of Request.Context.
func dialNativeEgress(ctx context.Context, diagnostic nativeDiagnostic, network, address string) (net.Conn, error) {
	return dialNativeConnect(ctx, diagnostic, "/loom/egress", "", "", network, address)
}

func dialNativeConnect(ctx context.Context, diagnostic nativeDiagnostic, path, scope, revision, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("exit-local measurement requires TCP")
	}
	host, text, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid exit-local target")
	}
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil {
		return nil, errors.New("invalid exit-local target port")
	}
	target, err := protocol.ConnectionTargetKey(network, host, uint16(port))
	if err != nil {
		return nil, err
	}
	local, err := diagnostic.dial(ctx, "tcp", "127.0.0.1:61800")
	if err != nil {
		return nil, err
	}
	local = measurementConnection(ctx, local)
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { local.Close(); close(closed) })
	var detached sync.Once
	detach := func() {
		detached.Do(func() {
			if !stop() {
				<-closed
			}
		})
	}
	succeeded := false
	defer func() {
		detach()
		if !succeeded {
			local.Close()
		}
	}()
	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, "http://127.0.0.1:61800"+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+diagnostic.secret)
	request.Header.Set("X-Loom-Target", target)
	if id, _ := ctx.Value(echoDiagnosticIDKey{}).(string); path == "/loom/probe" && id != "" {
		request.Header.Set("X-Loom-Echo-ID", id)
	}
	if scope != "" {
		request.Header.Set("X-Loom-Scope", scope)
	}
	if revision != "" {
		request.Header.Set("X-Loom-Expected-Revision", revision)
	}
	if err = request.Write(local); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(local)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusServiceUnavailable || response.StatusCode == http.StatusConflict {
			return nil, ErrMeasurementDeferred
		}
		return nil, errors.New("exit-local connection was not established")
	}
	detach()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	succeeded = true
	return &egressConn{Conn: local, reader: reader}, nil
}
