package clientadapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"loom/internal/control"
	"loom/protocol"
)

// These are declared echo outcomes, not a change to local authorization.
var (
	ErrEchoDenied      = errors.New("native echo denied")
	ErrEchoUnavailable = errors.New("native echo unavailable")
)

type nativeDiagnosticKey struct{}
type echoDiagnosticLogKey struct{}
type echoDiagnosticIDKey struct{}
type nativeDiagnostic struct {
	secret string
	dial   func(context.Context, string, string) (net.Conn, error)
}

// WithEchoDiagnosticLog supplies a best-effort Debug sink for an actual echo
// flight. It carries no measurement, identity or authorization state.
func WithEchoDiagnosticLog(ctx context.Context, sink func(string)) context.Context {
	return context.WithValue(ctx, echoDiagnosticLogKey{}, sink)
}

func emitEchoDiagnostic(ctx context.Context, id, phase string, elapsed time.Duration, cause error) {
	sink, _ := ctx.Value(echoDiagnosticLogKey{}).(func(string))
	if sink == nil {
		return
	}
	outcome := "success"
	var timeout net.Error
	switch {
	case phase == "request-start":
		outcome = "started"
	case errors.Is(cause, context.Canceled):
		outcome = "canceled"
	case errors.Is(cause, context.DeadlineExceeded), errors.As(cause, &timeout) && timeout.Timeout():
		outcome = "timeout"
	case errors.Is(cause, ErrEchoDenied):
		outcome = "denied"
	case errors.Is(cause, ErrEchoUnavailable):
		outcome = "unavailable"
	case errors.Is(cause, ErrMeasurementDeferred), errors.Is(cause, ErrResourcesNotReady):
		outcome = "local-pending"
	case errors.Is(cause, ErrSelectionSuperseded):
		outcome = "superseded"
	case cause != nil:
		outcome = "failed"
	}
	// The sink is diagnostic-only, including a host callback which panics.
	defer func() { _ = recover() }()
	sink(fmt.Sprintf("echo_id=%s phase=%s elapsed_ns=%d outcome=%s", id, phase, max(0, elapsed.Nanoseconds()), outcome))
}

func newEchoRequest(operation protocol.Operation, policy string) (protocol.Request, error) {
	request := protocol.Request{Operation: operation, PolicyID: policy}
	_, err := rand.Read(request.Nonce[:])
	return request, err
}

func NativeDiagnosticSelector(ctx context.Context) (*HTTPSelector, error) {
	diagnostic, ok := ctx.Value(nativeDiagnosticKey{}).(nativeDiagnostic)
	if !ok {
		return nil, errors.New("native diagnostic context is unavailable")
	}
	return diagnosticSelector(diagnostic)
}

// WithNativeDiagnostic selects the current process's protected local entry,
// including its network namespace. It never instantiates a second WG session.
func WithNativeDiagnostic(ctx context.Context, config string, dial func(context.Context, string, string) (net.Conn, error)) (context.Context, error) {
	var document struct {
		Experimental struct {
			API struct {
				Secret  string `json:"secret"`
				Address string `json:"external_controller"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	if json.Unmarshal([]byte(config), &document) != nil || document.Experimental.API.Secret == "" || document.Experimental.API.Address != "127.0.0.1:61800" {
		return nil, errors.New("native diagnostic requires the running local API identity")
	}
	return NativeDiagnosticContext(ctx, document.Experimental.API.Secret, dial)
}

func NativeDiagnosticContext(ctx context.Context, secret string, dial func(context.Context, string, string) (net.Conn, error)) (context.Context, error) {
	if secret == "" {
		return nil, errors.New("native diagnostic secret is missing")
	}
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	return context.WithValue(ctx, nativeDiagnosticKey{}, nativeDiagnostic{secret: secret, dial: dial}), nil
}

type diagnosticDialer struct {
	nativeDiagnostic
	ctx context.Context
}

func (d diagnosticDialer) Dial(network, address string) (net.Conn, error) {
	connection, err := d.dial(d.ctx, network, address)
	if err != nil {
		return nil, err
	}
	return measurementConnection(d.ctx, connection), nil
}
func (d diagnosticDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	connection, err := d.dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return measurementConnection(ctx, connection), nil
}

// ProbeWireGuard measures a bounded native transport echo through the running
// WG sender. Authentication/admission and measured RTT remain distinct results.
func ProbeWireGuard(ctx context.Context, network string, resource control.TransportResource) (*time.Duration, error) {
	return measureWireGuardEcho(ctx, network, resource, resource.ID, protocol.TransportEcho, "", "")
}
func ProbeWireGuardAdmission(ctx context.Context, probe control.ResourceProbe) (*time.Duration, error) {
	return measureWireGuardEcho(ctx, probe.NetworkID, probe.Resource, probe.DiagnosticID, protocol.AdmissionEcho, probe.PolicyID, probe.SpecDigest)
}
func measureWireGuardEcho(ctx context.Context, network string, resource control.TransportResource, principal string, operation protocol.Operation, policy, specification string) (*time.Duration, error) {
	diagnostic, ok := ctx.Value(nativeDiagnosticKey{}).(nativeDiagnostic)
	if !ok {
		return nil, errors.New("no running native diagnostic entry")
	}
	body, err := control.CanonicalEncode(resource)
	if err != nil {
		return nil, err
	}
	return runMeasurement(ctx, measurementIdentity(ctx, "native-wg-echo", network, diagnostic.secret, string(body), principal, strconv.Itoa(int(operation)), policy, specification), 8<<10, func(pending context.Context) (rtt *time.Duration, resultErr error) {
		request, err := newEchoRequest(operation, policy)
		if err != nil {
			return nil, err
		}
		id := protocol.EchoDiagnosticID(request.Nonce)
		pending = context.WithValue(pending, echoDiagnosticIDKey{}, id)
		started := time.Now()
		var events []func()
		record := func(phase string, elapsed time.Duration, cause error) {
			events = append(events, func() { emitEchoDiagnostic(pending, id, phase, elapsed, cause) })
		}
		record("request-start", 0, nil)
		defer func() {
			markMeasurementCompletion(pending)
			record("request-finish", time.Since(started), errors.Join(resultErr, pending.Err()))
			for _, emit := range events {
				emit()
			}
		}()
		address, err := control.WireGuardAccessAddress(resource, "")
		if err != nil {
			return nil, err
		}
		connectStarted := time.Now()
		conn, err := dialNativeConnect(pending, diagnostic, "/loom/probe", "", "", "tcp", net.JoinHostPort(address.String(), "53"))
		record("local-connect", time.Since(connectStarted), err)
		if err != nil {
			return nil, fmt.Errorf("WG stage=local-connect elapsed=%s: %w", time.Since(connectStarted), err)
		}
		defer conn.Close()
		stop := context.AfterFunc(pending, func() { conn.Close() })
		defer stop()
		if deadline, ok := pending.Deadline(); ok {
			if err = conn.SetDeadline(deadline); err != nil {
				return nil, err
			}
		}
		return echoRoundTrip(conn, request, []byte(protocol.WireGuardPreface), record)
	})
}

// echoRoundTrip uses the same exchange for WG and Hy2. An accepted response
// with an incomparable processing duration proves admission but supplies no RTT.
func echoRoundTrip(stream io.ReadWriter, request protocol.Request, prefix []byte, record func(string, time.Duration, error)) (*time.Duration, error) {
	body, err := request.Marshal(1)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	stageStarted := started
	var durations [4]time.Duration
	var causes [4]error
	attempted := 0
	defer func() {
		if record == nil {
			return
		}
		phases := [...]string{"preface-write", "request-write", "response-read", "response-validate"}
		for index := 0; index < attempted; index++ {
			record(phases[index], durations[index], causes[index])
		}
	}()
	attempted = 1
	if len(prefix) > 0 {
		_, err = io.Copy(stream, bytes.NewReader(prefix))
		durations[0], causes[0] = time.Since(stageStarted), err
		if err != nil {
			return nil, fmt.Errorf("native echo stage=preface-write elapsed=%s: %w", time.Since(stageStarted), err)
		}
	}
	stageStarted = time.Now()
	attempted = 2
	err = protocol.WriteFrame(stream, body)
	durations[1], causes[1] = time.Since(stageStarted), err
	if err != nil {
		return nil, fmt.Errorf("native echo stage=request-write elapsed=%s: %w", time.Since(stageStarted), err)
	}
	stageStarted = time.Now()
	attempted = 3
	raw, err := protocol.ReadFrame(stream, 128)
	durations[2], causes[2] = time.Since(stageStarted), err
	if err != nil {
		return nil, fmt.Errorf("native echo stage=response-read elapsed=%s: %w", time.Since(stageStarted), err)
	}
	elapsed := time.Since(started)
	stageStarted = time.Now()
	attempted = 4
	response, err := executionEchoResponse(raw, request)
	durations[3], causes[3] = time.Since(stageStarted), err
	if err != nil {
		return nil, fmt.Errorf("native echo stage=response-validate elapsed=%s: %w", time.Since(stageStarted), err)
	}
	if response.ProcessingNanos > uint64(elapsed) {
		return nil, nil
	}
	duration := elapsed - time.Duration(response.ProcessingNanos)
	return &duration, nil
}
func executionEchoResponse(body []byte, request protocol.Request) (protocol.Response, error) {
	response, err := protocol.UnmarshalResponse(body, request.Nonce)
	if err != nil {
		return protocol.Response{}, err
	}
	if response.Address.IsValid() {
		return protocol.Response{}, errors.New("native echo returned an unexpected address")
	}
	switch response.Status {
	case protocol.Denied:
		return protocol.Response{}, ErrEchoDenied
	case protocol.Unavailable:
		return protocol.Response{}, ErrEchoUnavailable
	}
	return response, nil
}
