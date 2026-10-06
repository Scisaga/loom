package linuxclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"golang.org/x/sys/unix"
	"loom/internal/control"
)

// This socket belongs to the already authenticated WG execution. It cannot
// escape onto another interface or acquire host routes, DNS or capture rights.
func linkProbeSocket(ctx context.Context, source control.TransportResource) (net.PacketConn, error) {
	address, err := control.WGResourceAddress(source)
	if err != nil {
		return nil, err
	}
	listener := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var bindErr error
		err := raw.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, source.ListenerID)
		})
		return errors.Join(err, bindErr)
	}}
	return listener.ListenPacket(ctx, "udp", net.JoinHostPort(address.String(), "0"))
}

func probeLink(ctx context.Context, source, target control.TransportResource, destination, password string, now time.Time) error {
	certificates, err := control.HY2TrustPEM(target)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	for _, certificate := range certificates {
		if !roots.AppendCertsFromPEM([]byte(certificate)) {
			return errors.New("Link probe trust is invalid")
		}
	}
	address, err := netip.ParseAddrPort(destination)
	if err != nil {
		return err
	}
	socket, err := linkProbeSocket(ctx, source)
	if err != nil {
		return err
	}
	defer socket.Close()
	udp := &quic.Transport{Conn: socket}
	defer udp.Close()
	transport := &http3.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots,
		ServerName: *target.Authentication.ServerName, Time: func() time.Time { return now }},
		Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, config *quic.Config) (quic.EarlyConnection, error) {
			return udp.DialEarly(ctx, net.UDPAddrFromAddrPort(address), tlsConfig, config)
		}}
	defer transport.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Hysteria-Auth", password)
	request.Header.Set("Hysteria-CC-RX", "0")
	response, err := transport.RoundTrip(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 233 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return errors.New("Link probe did not complete authenticated Hy2 transport")
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return err
}

// Samples are rebuilt on each refresh. They never enter the Service selection
// cache, acquire an authority store or substitute for an HTTPS business probe.
func observeLinks(ctx context.Context, view control.DeviceView, wg wireGuardExecution, generation string, interval time.Duration, now func() time.Time) ([]control.Observation, error) {
	resources := map[string]control.TransportResource{}
	for _, resource := range view.Resources {
		resources[resource.ID] = resource
	}
	result := []control.Observation{}
	for _, permission := range view.LinkProbeCredentials {
		for _, link := range view.Links {
			if link.ID != permission.LinkID || link.FromNodeID != view.DeviceID {
				continue
			}
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			source, target := resources[link.FromResourceID], resources[link.ProbeTarget.ResourceID]
			from, err := control.WGResourceAddress(source)
			to, toErr := netip.ParseAddr(link.ProbeTarget.Host)
			owned := false
			for _, actual := range wg.WireGuard {
				owned = owned || err == nil && toErr == nil && actual.Interface == source.ListenerID && actual.LocalAddress == netip.PrefixFrom(from, from.BitLen()).String() && actual.AllowedIP == netip.PrefixFrom(to, to.BitLen()).String()
			}
			if !owned {
				return nil, errors.New("Link probe has no matching WireGuard execution")
			}
			digest, err := control.LinkSpecDigest(view, link.ID)
			if err != nil {
				return nil, err
			}
			at := now()
			targetAddress := net.JoinHostPort(link.ProbeTarget.Host, strconv.Itoa(link.ProbeTarget.Port))
			pending, cancel := context.WithTimeout(ctx, 3*time.Second)
			started := time.Now()
			probeErr := probeLink(pending, source, target, targetAddress, permission.Credential, at)
			duration := time.Since(started).Milliseconds()
			cancel()
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			state := "available"
			if probeErr != nil {
				state = "unavailable"
			}
			value := control.Observation{Level: "link", ResourceID: link.ResourceID, LinkID: link.ID, Target: targetAddress,
				Action: link.ProbeTarget.Action, SpecDigest: digest, NetworkGeneration: generation, Result: state,
				ObservedAt: at.UnixMilli(), ValidUntil: at.Add(interval).UnixMilli(), DurationMS: &duration}
			if err := value.Validate(); err != nil {
				return nil, err
			}
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ResourceID != result[j].ResourceID {
			return result[i].ResourceID < result[j].ResourceID
		}
		return result[i].LinkID < result[j].LinkID
	})
	return result, nil
}
