package clientadapter

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type candidateScopeKey struct{}

// WithCandidateScope calibrates an already selected source path. Exit-local
// probes omit this context and retain their explicit diagnostic identity.
func WithCandidateScope(ctx context.Context, scope string) context.Context {
	return context.WithValue(ctx, candidateScopeKey{}, scope)
}
func diagnosticSelector(diagnostic nativeDiagnostic) (*HTTPSelector, error) {
	body, err := json.Marshal(map[string]any{"experimental": map[string]any{"clash_api": map[string]any{"external_controller": "127.0.0.1:61800", "secret": diagnostic.secret}}})
	if err != nil {
		return nil, err
	}
	selector, err := NewHTTPSelector(string(body))
	if err == nil {
		selector.SetDialer(diagnostic.dial)
	}
	return selector, err
}
func selectedForURL(snapshot clientmodel.Selection, target string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return ""
	}
	port := uint64(443)
	if parsed.Port() != "" {
		port, err = strconv.ParseUint(parsed.Port(), 10, 16)
		if err != nil {
			return ""
		}
	}
	key, err := protocol.ConnectionTargetKey("tcp", parsed.Hostname(), uint16(port))
	if err != nil {
		return ""
	}
	if id := snapshot.Targets[key]; id != "" {
		return id
	}
	return snapshot.CandidateID
}

// ProbeCandidateBusiness uses the existing authenticated local diagnostic
// entry. Its certified rules select one candidate and enforce the same Service
// exclusions. It does not change a production selector or close connections.
func ProbeCandidateBusiness(ctx context.Context, candidate, target string) ProbeResult {
	diagnostic, ok := ctx.Value(nativeDiagnosticKey{}).(nativeDiagnostic)
	if !ok {
		return ProbeResult{Deferred: true, Action: "https_request", Description: "candidate diagnostic unavailable"}
	}
	scope, _ := ctx.Value(candidateScopeKey{}).(string)
	result, err := runMeasurement(ctx, measurementIdentity(ctx, "candidate", diagnostic.secret, scope, candidate, target), 32<<10, func(pending context.Context) (ProbeResult, error) {
		return probeCandidateBusiness(pending, candidate, target, &tls.Config{MinVersion: tls.VersionTLS12}), nil
	})
	if err != nil {
		result = ProbeResult{Deferred: errors.Is(err, ErrMeasurementDeferred) || errors.Is(err, context.Canceled), Action: "https_request", Description: "candidate measurement deferred"}
	}
	return result
}

func probeCandidateBusiness(ctx context.Context, candidate, target string, tlsConfig *tls.Config) ProbeResult {
	diagnostic, ok := ctx.Value(nativeDiagnosticKey{}).(nativeDiagnostic)
	if !ok || control.ValidateDigest(candidate) != nil || control.ValidateHTTPSURL(target) != nil {
		return ProbeResult{Action: "https_request", Description: "candidate diagnostic unavailable"}
	}
	scope, _ := ctx.Value(candidateScopeKey{}).(string)
	if !clientmodel.ValidSelectorScope(scope) {
		return ProbeResult{Deferred: true, Action: "https_request"}
	}
	var selector *HTTPSelector
	var before clientmodel.Selection
	if scope != "" {
		if !clientmodel.ValidSelectorScope(scope) {
			return ProbeResult{Deferred: true, Action: "https_request"}
		}
		var err error
		selector, err = diagnosticSelector(diagnostic)
		if err == nil {
			before, err = selector.ReadSelection(ctx, scope)
		}
		if err != nil || selectedForURL(before, target) != candidate {
			return ProbeResult{Deferred: true, Action: "https_request"}
		}
	}
	started := time.Now()
	pending, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialNativeConnect(ctx, diagnostic, "/loom/probe", scope, before.Revision, network, address)
	}
	var confirm func() bool
	if selector != nil {
		confirm = func() bool {
			after, err := selector.ReadSelection(ctx, before.Scope)
			return err == nil && after.Revision == before.Revision && SameSelection(after, before)
		}
	}
	return probeHTTPS(pending, target, tlsConfig, dial, started, confirm)
}

// The application request is identical for source calibration and exit-local
// measurement. Only the already-authorized physical socket source differs.
func probeHTTPS(ctx context.Context, target string, tlsConfig *tls.Config, dial func(context.Context, string, string) (net.Conn, error), started time.Time, confirm func() bool) ProbeResult {
	// net/http detaches its dialing context from the request. This measurement
	// owns those attempts until they exit, including cancellation and a late
	// successful dial, so its shared budget cannot be released early.
	pending, cancel := context.WithCancel(ctx)
	var mu sync.Mutex
	var active sync.WaitGroup
	var owned []net.Conn
	closing := false
	begin := func() bool {
		mu.Lock()
		defer mu.Unlock()
		if closing || pending.Err() != nil {
			return false
		}
		active.Add(1)
		return true
	}
	ownedDial := func(_ context.Context, network, address string) (net.Conn, error) {
		if !begin() {
			return nil, context.Canceled
		}
		defer active.Done()
		connection, err := dial(pending, network, address)
		if connection != nil {
			mu.Lock()
			stopped := closing || pending.Err() != nil
			if !stopped {
				owned = append(owned, connection)
			}
			mu.Unlock()
			if stopped || err != nil {
				connection.Close()
				if stopped {
					return nil, context.Canceled
				}
			}
		}
		if err != nil {
			return nil, err
		}
		connection = &probeOwnedConn{Conn: connection, begin: begin, done: active.Done}
		config := tlsConfig.Clone()
		if config.ServerName == "" {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				connection.Close()
				return nil, err
			}
			config.ServerName = host
		}
		secure := tls.Client(connection, config)
		if err := secure.HandshakeContext(pending); err != nil {
			connection.Close()
			return nil, err
		}
		return secure, nil
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: tlsConfig, DialTLSContext: ownedDial,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("measurement requires HTTPS")
		}}
	defer func() {
		mu.Lock()
		closing = true
		connections := append([]net.Conn(nil), owned...)
		mu.Unlock()
		cancel()
		transport.CloseIdleConnections()
		for _, connection := range connections {
			connection.Close()
		}
		active.Wait()
	}()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return ProbeResult{Action: "https_request", Description: "candidate target invalid"}
	}
	response, err := client.Do(request)
	if confirm != nil && !confirm() {
		if response != nil {
			response.Body.Close()
		}
		return ProbeResult{Deferred: true, Action: "https_request"}
	}
	result := ProbeResult{Action: "https_request", Target: target, Metric: time.Since(started), Description: "candidate HTTPS failed"}
	if err != nil {
		result.Deferred = errors.Is(err, ErrMeasurementDeferred) || errors.Is(err, context.Canceled)
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
