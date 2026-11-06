package clientadapter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
	if err != nil {
		return firstHopMeasurement{}, err
	}
	request.Header.Set("Hysteria-Auth", credential)
	request.Header.Set("Hysteria-CC-RX", "0")
	response, err := transport.RoundTrip(request)
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
	stream, err := authenticated.OpenStreamSync(ctx)
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
	operation := protocol.AdmissionEcho
	if policy == "" {
		operation = protocol.TransportEcho
	}
	rtt, err := echoRoundTrip(stream, operation, quicvarint.Append(nil, protocol.Hy2FrameType), policy)
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

func probeHY2FirstHop(ctx context.Context, probe control.ResourceProbe, dns []string, at time.Time) (firstHopMeasurement, error) {
	originalDial := control.EndpointDialer(ctx)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := originalDial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return measurementConnection(ctx, connection), nil
	}
	addresses, err := netx.ResolveCertifiedIPs(ctx, probe.Resource.DialHost, dns, dial)
	if err != nil {
		return firstHopMeasurement{}, err
	}
	for _, address := range addresses {
		if ctx.Err() != nil {
			return firstHopMeasurement{}, ctx.Err()
		}
		connection, err := dial(ctx, "udp", net.JoinHostPort(address.String(), strconv.Itoa(probe.Resource.DialPort)))
		if err != nil {
			continue
		}
		transfer, err := AuthenticateHY2(ctx, probe.Resource, connectedProbePacket{connection}, connection.RemoteAddr(), probe.Credential, at, probe.PolicyID)
		closeErr := connection.Close()
		if err == nil {
			return transfer, closeErr
		}
	}
	return firstHopMeasurement{}, errors.New("public first hop authentication failed")
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
