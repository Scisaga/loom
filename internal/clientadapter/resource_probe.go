package clientadapter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	"loom/internal/control"
	"loom/internal/netx"
	"loom/protocol"
)

type firstHopMeasurement struct {
	transfer    *control.HY2Transfer
	roundTripMS *int64
}

// AuthenticateHY2 performs a real TLS and Hy2 login, with no forwarding request.
// The caller owns the underlay socket and supplies the certificate-check time.
func AuthenticateHY2(ctx context.Context, resource control.TransportResource, socket net.PacketConn, peer net.Addr, credential string, at time.Time, policy string) (firstHopMeasurement, error) {
	operation := protocol.AdmissionEcho
	if policy == "" {
		operation = protocol.TransportEcho
	}
	request, err := newEchoRequest(operation, policy)
	if err != nil {
		return firstHopMeasurement{}, err
	}
	return authenticateHY2(ctx, resource, socket, peer, credential, at, request, nil)
}

func authenticateHY2(ctx context.Context, resource control.TransportResource, socket net.PacketConn, peer net.Addr, credential string, at time.Time, request protocol.Request, record func(string, time.Duration, error)) (measuredResult firstHopMeasurement, resultErr error) {
	authStarted := time.Now()
	authRecorded := false
	defer func() {
		if !authRecorded && record != nil {
			record("hy2-authenticate", time.Since(authStarted), resultErr)
		}
	}()
	certificates, err := control.HY2TrustPEM(resource)
	if err != nil || control.ValidatePublicKey(credential) != nil {
		return firstHopMeasurement{}, errors.New("Hy2 authentication inputs are invalid")
	}
	roots := x509.NewCertPool()
	for _, certificate := range certificates {
		if !roots.AppendCertsFromPEM([]byte(certificate)) {
			return firstHopMeasurement{}, errors.New("Hy2 trust is invalid")
		}
	}
	measured := &hy2ProbePacket{PacketConn: socket}
	var authenticated quic.EarlyConnection
	udp := &quic.Transport{Conn: measured}
	defer udp.Close()
	transport := &http3.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots,
		ServerName: *resource.Authentication.ServerName, Time: func() time.Time { return at }},
		Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, config *quic.Config) (quic.EarlyConnection, error) {
			connection, err := udp.DialEarly(ctx, peer, tlsConfig, config)
			if err == nil {
				authenticated = connection
			}
			return connection, err
		}}
	defer transport.Close()
	login, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
	if err != nil {
		return firstHopMeasurement{}, err
	}
	login.Header.Set("Hysteria-Auth", credential)
	login.Header.Set("Hysteria-CC-RX", "0")
	response, err := transport.RoundTrip(login)
	if err != nil {
		return firstHopMeasurement{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != 233 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return firstHopMeasurement{}, errors.New("Hy2 transport did not complete authenticated login")
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if err != nil || ctx.Err() != nil {
		if err == nil {
			err = ctx.Err()
		}
		return firstHopMeasurement{}, err
	}
	if authenticated == nil {
		return firstHopMeasurement{}, errors.New("Hy2 login did not retain its authenticated transport")
	}
	authRecorded = true
	if record != nil {
		record("hy2-authenticate", time.Since(authStarted), nil)
	}
	streamStarted := time.Now()
	stream, err := authenticated.OpenStreamSync(ctx)
	if record != nil {
		record("execution-stream-open", time.Since(streamStarted), err)
	}
	if err != nil {
		return firstHopMeasurement{}, err
	}
	defer stream.Close()
	defer stream.CancelRead(0)
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(0); stream.CancelWrite(0) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err = stream.SetDeadline(deadline); err != nil {
			return firstHopMeasurement{}, err
		}
	}
	// A frame-type prefix identifies Hy2's own native execution stream.
	rtt, err := echoRoundTrip(stream, request, quicvarint.Append(nil, protocol.Hy2FrameType), record)
	if err != nil {
		return firstHopMeasurement{}, err
	}
	result := firstHopMeasurement{transfer: measured.transfer()}
	if rtt != nil {
		result.roundTripMS = new(rtt.Milliseconds())
	}
	return result, nil
}

type hy2ProbePacket struct {
	net.PacketConn
	lock    sync.Mutex
	started time.Time
	rx, tx  control.U64
}

func (packet *hy2ProbePacket) ReadFrom(body []byte) (int, net.Addr, error) {
	n, peer, err := packet.PacketConn.ReadFrom(body)
	packet.lock.Lock()
	packet.rx += control.U64(n)
	packet.lock.Unlock()
	return n, peer, err
}

func (packet *hy2ProbePacket) WriteTo(body []byte, peer net.Addr) (int, error) {
	packet.lock.Lock()
	if packet.started.IsZero() {
		packet.started = time.Now()
	}
	packet.lock.Unlock()
	n, err := packet.PacketConn.WriteTo(body, peer)
	packet.lock.Lock()
	packet.tx += control.U64(n)
	packet.lock.Unlock()
	return n, err
}

func (packet *hy2ProbePacket) transfer() *control.HY2Transfer {
	packet.lock.Lock()
	defer packet.lock.Unlock()
	if packet.started.IsZero() || packet.rx == 0 || packet.tx == 0 {
		return nil
	}
	value := control.HY2Transfer{DurationNS: time.Since(packet.started).Nanoseconds(), RXBytes: packet.rx, TXBytes: packet.tx}
	if value.DurationNS <= 0 {
		return nil
	}
	return &value
}

// A connected platform UDP socket already filters the exact remote peer. Hide
// UDP WriteTo/OOB methods: WriteTo on a connected socket is invalid, and bypassing
// the platform dialer would lose Android protection or an isolated underlay.
type connectedProbePacket struct{ net.Conn }

func (packet connectedProbePacket) ReadFrom(body []byte) (int, net.Addr, error) {
	n, err := packet.Read(body)
	return n, packet.RemoteAddr(), err
}
func (packet connectedProbePacket) WriteTo(body []byte, peer net.Addr) (int, error) {
	if peer.Network() != packet.RemoteAddr().Network() || peer.String() != packet.RemoteAddr().String() {
		return 0, errors.New("Hy2 probe cannot change its underlay peer")
	}
	return packet.Write(body)
}

func probeFirstHop(ctx context.Context, probe control.ResourceProbe, dns []string, at time.Time) (firstHopMeasurement, error) {
	if probe.Resource.Kind == "wireguard" {
		rtt, err := ProbeWireGuardAdmission(ctx, probe)
		result := firstHopMeasurement{}
		if rtt != nil {
			result.roundTripMS = new(rtt.Milliseconds())
		}
		return result, err
	}
	return runMeasurement(ctx, measurementIdentity(ctx, "hy2-first-hop", probe.NetworkID, probe.SpecDigest, probe.Credential), 64<<10, func(pending context.Context) (firstHopMeasurement, error) {
		return probeHY2FirstHop(pending, probe, dns, at)
	})
}

func probeHY2FirstHop(ctx context.Context, probe control.ResourceProbe, dns []string, at time.Time) (measured firstHopMeasurement, resultErr error) {
	operation := protocol.AdmissionEcho
	if probe.PolicyID == "" {
		operation = protocol.TransportEcho
	}
	request, err := newEchoRequest(operation, probe.PolicyID)
	if err != nil {
		return firstHopMeasurement{}, err
	}
	id := protocol.EchoDiagnosticID(request.Nonce)
	started := time.Now()
	var events []func()
	record := func(phase string, elapsed time.Duration, cause error) {
		events = append(events, func() { emitEchoDiagnostic(ctx, id, phase, elapsed, cause) })
	}
	record("request-start", 0, nil)
	events = append(events, func() { emitEchoBinding(ctx, id, probe.Resource.ID, probe.SpecDigest, operation, probe.PolicyID) })
	defer func() {
		markMeasurementCompletion(ctx)
		record("request-finish", time.Since(started), errors.Join(resultErr, ctx.Err()))
		for _, emit := range events {
			emit()
		}
	}()
	originalDial := control.EndpointDialer(ctx)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := originalDial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return measurementConnection(ctx, connection), nil
	}
	resolveStarted := time.Now()
	addresses, err := netx.ResolveCertifiedIPs(ctx, probe.Resource.DialHost, dns, dial)
	record("underlay-resolve", time.Since(resolveStarted), err)
	if err != nil {
		return firstHopMeasurement{}, err
	}
	var failures []error
	for index, address := range addresses {
		if ctx.Err() != nil {
			return firstHopMeasurement{}, errors.Join(append(failures, ctx.Err())...)
		}
		started := time.Now()
		connection, err := dial(ctx, "udp", net.JoinHostPort(address.String(), strconv.Itoa(probe.Resource.DialPort)))
		record("underlay-dial", time.Since(started), err)
		if err != nil {
			failures = append(failures, fmt.Errorf("Hy2 stage=underlay-dial attempt=%d elapsed=%s: %w", index+1, time.Since(started), err))
			continue
		}
		started = time.Now()
		transfer, err := authenticateHY2(ctx, probe.Resource, connectedProbePacket{connection}, connection.RemoteAddr(), probe.Credential, at, request, record)
		elapsed := time.Since(started)
		closeStarted := time.Now()
		closeErr := connection.Close()
		record("socket-close", time.Since(closeStarted), closeErr)
		if closeErr != nil {
			closeErr = fmt.Errorf("Hy2 stage=socket-close attempt=%d elapsed=%s: %w", index+1, time.Since(closeStarted), closeErr)
		}
		if err == nil {
			return transfer, closeErr
		}
		failures = append(failures, fmt.Errorf("Hy2 stage=authenticate attempt=%d elapsed=%s: %w", index+1, elapsed, err), closeErr)
	}
	return firstHopMeasurement{}, errors.Join(errors.New("public first hop authentication failed"), errors.Join(failures...), ctx.Err())
}

// RetainResourceObservations compares the complete execution specification.
// It preserves original times and failures, and never manufactures a sample.
func RetainResourceObservations(probes []control.ResourceProbe, previous []control.Observation, generation string) []control.Observation {
	result := []control.Observation{}
	for _, probe := range probes {
		for _, value := range previous {
			if value.Validate() == nil && value.Level == "resource" && value.NetworkGeneration == generation &&
				value.ResourceID == probe.Resource.ID && value.SpecDigest == probe.SpecDigest && value.Target == probe.Target() && value.Action == probe.Action() {
				result = append(result, value)
				break
			}
		}
	}
	return result
}

// ObserveFirstHops returns the resource subset of the shared continuous node
// scheduler. Repeat periods and validity are independent; no second scheduler
// owns first-hop refreshes.
func ObserveFirstHops(ctx context.Context, view control.DeviceExecution, selected []string, previous []control.Observation, generation string, now func() time.Time, progress func([]control.Observation) error, recovery ...*TCPRecoveryInput) ([]control.Observation, error) {
	values, err := ObserveNodeMeasurements(ctx, view, selected, previous, generation, now, DefaultMeasurementTiming, func(batch []control.Observation) error {
		resources := []control.Observation{}
		for _, value := range batch {
			if value.Level == "resource" {
				resources = append(resources, value)
			}
		}
		if len(resources) != 0 && progress != nil {
			return progress(resources)
		}
		return nil
	}, recovery...)
	if err != nil {
		return nil, err
	}
	result := []control.Observation{}
	for _, value := range values {
		if value.Level == "resource" {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool { return measurementSampleKey(result[i]) < measurementSampleKey(result[j]) })
	return result, nil
}
