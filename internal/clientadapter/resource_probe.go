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
	"loom/internal/control"
	"loom/internal/netx"
)

// AuthenticateHY2 performs a real TLS and Hy2 login, with no forwarding request.
// The caller owns the underlay socket and supplies the certificate-check time.
func AuthenticateHY2(ctx context.Context, resource control.TransportResource, socket net.PacketConn, peer net.Addr, credential string, at time.Time) error {
	certificates, err := control.HY2TrustPEM(resource)
	if err != nil || control.ValidatePublicKey(credential) != nil {
		return errors.New("Hy2 authentication inputs are invalid")
	}
	roots := x509.NewCertPool()
	for _, certificate := range certificates {
		if !roots.AppendCertsFromPEM([]byte(certificate)) {
			return errors.New("Hy2 trust is invalid")
		}
	}
	udp := &quic.Transport{Conn: socket}
	defer udp.Close()
	transport := &http3.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots,
		ServerName: *resource.Authentication.ServerName, Time: func() time.Time { return at }},
		Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, config *quic.Config) (quic.EarlyConnection, error) {
			return udp.DialEarly(ctx, peer, tlsConfig, config)
		}}
	defer transport.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Hysteria-Auth", credential)
	request.Header.Set("Hysteria-CC-RX", "0")
	response, err := transport.RoundTrip(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 233 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return errors.New("Hy2 transport did not complete authenticated login")
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return err
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

func probeFirstHop(ctx context.Context, probe control.ResourceProbe, dns []string, at time.Time) error {
	if probe.Resource.Kind == "wireguard" {
		return ProbeWireGuard(ctx, probe.NetworkID, probe.Resource)
	}
	dial := control.EndpointDialer(ctx)
	addresses, err := netx.ResolveCertifiedIPs(ctx, probe.Resource.DialHost, dns, dial)
	if err != nil {
		return err
	}
	for _, address := range addresses {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		connection, err := dial(ctx, "udp", net.JoinHostPort(address.String(), strconv.Itoa(probe.Resource.DialPort)))
		if err != nil {
			continue
		}
		err = AuthenticateHY2(ctx, probe.Resource, connectedProbePacket{connection}, connection.RemoteAddr(), probe.Credential, at)
		closeErr := connection.Close()
		if err == nil {
			return closeErr
		}
	}
	return errors.New("public first hop authentication failed")
}

// RetainResourceObservations compares the complete execution specification.
// It preserves original times and failures, and never manufactures a sample.
func RetainResourceObservations(probes []control.ResourceProbe, previous []control.Observation, generation string) []control.Observation {
	result := []control.Observation{}
	for _, probe := range probes {
		for _, value := range previous {
			if value.Validate() == nil && value.Level == "resource" && value.NetworkGeneration == generation &&
				value.ResourceID == probe.Resource.ID && value.SpecDigest == probe.SpecDigest && value.Target == probe.Target() {
				result = append(result, value)
				break
			}
		}
	}
	return result
}

// ObserveFirstHops runs after selections have been applied and read back. Only
// resources needed by those selections are sampled, independently and once per
// original validity window. Its results never enter Service selection state.
func ObserveFirstHops(ctx context.Context, view control.DeviceView, selected []string, previous []control.Observation, generation string, now func() time.Time) ([]control.Observation, error) {
	return observeFirstHops(ctx, view, selected, previous, generation, now, probeFirstHop)
}

func observeFirstHops(ctx context.Context, view control.DeviceView, selected []string, previous []control.Observation, generation string, now func() time.Time,
	probe func(context.Context, control.ResourceProbe, []string, time.Time) error) ([]control.Observation, error) {
	probes, err := control.FirstHopProbes(view)
	if err != nil || control.ValidateID(generation) != nil || now == nil {
		return nil, errors.New("resource observation inputs are invalid")
	}
	needed := map[string]bool{}
	for _, candidate := range selected {
		found := false
		for _, route := range view.Routes {
			if route.ID == candidate {
				found, needed[route.FirstResourceID] = true, true
			}
		}
		if !found {
			return nil, errors.New("resource probe selection is outside the current view")
		}
	}
	at := now()
	cached := map[string]control.Observation{}
	for _, value := range RetainResourceObservations(probes, previous, generation) {
		if value.ObservedAt <= at.UnixMilli() && at.UnixMilli() < value.ValidUntil {
			cached[value.ResourceID] = value
		}
	}
	var lock sync.Mutex
	var pending sync.WaitGroup
	for _, execution := range probes {
		lock.Lock()
		_, found := cached[execution.Resource.ID]
		lock.Unlock()
		if found || !needed[execution.Resource.ID] {
			continue
		}
		pending.Add(1)
		go func() {
			defer pending.Done()
			if ctx.Err() != nil {
				return
			}
			attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			started := time.Now()
			probeErr := probe(attempt, execution, view.DNSServers, at)
			duration := time.Since(started).Milliseconds()
			if ctx.Err() != nil {
				return
			}
			result, lifetime := "available", 10*time.Minute
			if probeErr != nil {
				result, lifetime = "unavailable", 30*time.Second
			}
			value := control.Observation{Level: "resource", ResourceID: execution.Resource.ID, Target: execution.Target(), Action: execution.Action(),
				SpecDigest: execution.SpecDigest, NetworkGeneration: generation, Result: result, ObservedAt: at.UnixMilli(), ValidUntil: at.Add(lifetime).UnixMilli(), DurationMS: &duration}
			lock.Lock()
			cached[execution.Resource.ID] = value
			lock.Unlock()
		}()
	}
	pending.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	result := make([]control.Observation, 0, len(cached))
	for _, value := range cached {
		if err := value.Validate(); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ResourceID < result[j].ResourceID })
	return result, nil
}
