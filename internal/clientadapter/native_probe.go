package clientadapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"loom/internal/control"
	"loom/protocol"
)

type nativeDiagnosticKey struct{}
type nativeDiagnostic struct {
	secret string
	dial   func(context.Context, string, string) (net.Conn, error)
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
	return runMeasurement(ctx, measurementIdentity(ctx, "native-wg-echo", network, diagnostic.secret, string(body), principal, strconv.Itoa(int(operation)), policy, specification), 8<<10, func(pending context.Context) (*time.Duration, error) {
		address, err := control.WireGuardAccessAddress(resource, "")
		if err != nil {
			return nil, err
		}
		conn, err := dialNativeConnect(pending, diagnostic, "/loom/probe", "", "", "tcp", net.JoinHostPort(address.String(), "53"))
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		stop := context.AfterFunc(pending, func() { conn.Close() })
		defer stop()
		if deadline, ok := pending.Deadline(); ok {
			if err = conn.SetDeadline(deadline); err != nil {
				return nil, err
			}
		}
		return echoRoundTrip(conn, operation, []byte(protocol.WireGuardPreface), policy)
	})
}

// echoRoundTrip uses the same exchange for WG and Hy2. An accepted response
// with an incomparable processing duration proves admission but supplies no RTT.
func echoRoundTrip(stream io.ReadWriter, operation protocol.Operation, prefix []byte, policy string) (*time.Duration, error) {
	request := protocol.Request{Operation: operation, PolicyID: policy}
	if _, err := rand.Read(request.Nonce[:]); err != nil {
		return nil, err
	}
	body, err := request.Marshal(1)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	if len(prefix) > 0 {
		if _, err = io.Copy(stream, bytes.NewReader(prefix)); err != nil {
			return nil, err
		}
	}
	if err = protocol.WriteFrame(stream, body); err != nil {
		return nil, err
	}
	raw, err := protocol.ReadFrame(stream, 128)
	if err != nil {
		return nil, err
	}
	elapsed := time.Since(started)
	response, err := executionEchoResponse(raw, request)
	if err != nil {
		return nil, err
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
	if response.Status != protocol.Accepted || response.Address.IsValid() {
		return protocol.Response{}, errors.New("native echo was not admitted")
	}
	return response, nil
}
