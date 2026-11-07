package clientadapter

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
	"loom/protocol"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"golang.org/x/net/dns/dnsmessage"
)

func resourceProbeFixture(t *testing.T, kinds ...string) (control.DeviceView, tls.Certificate, time.Time) {
	t.Helper()
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"demo.example"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(public)
	digest := "sha256:" + strings.Repeat("1", 64)
	authorization := control.DeviceAuthorization{ID: "demo-access", Name: "Demo access", Platform: "linux", DevicePublicKey: key,
		Responsibilities: []string{"access"}, PolicyIDs: []string{}, DistributionURLs: []string{}, RuntimeKey: key,
		TransactionID: "demo-join", InviteMaterialID: digest, BindingMaterialID: digest}
	owner := authorization
	owner.ID, owner.Responsibilities = "demo-exit", []string{"internet_egress"}
	p := control.Projection{NetworkID: "demo-network", NetworkIntent: control.EmptyNetworkIntent()}
	for _, id := range []string{"demo-a", "demo-b", "demo-c"} {
		any := control.PolicyScope{Mode: "any", NodeIDs: []string{}}
		p.NetworkIntent.Services = append(p.NetworkIntent.Services, control.Service{ID: id, Name: "Demo service", Kind: "internet", RestrictToProbeTargets: new(false)})
		p.NetworkIntent.Policies = append(p.NetworkIntent.Policies, control.NetworkPolicy{ID: id, ServiceID: id, Name: "Demo policy", Action: "allow", EntryScope: any, RelayScope: any, ExitScope: new(any), AllowDirect: new(true), LocalEgressDevices: new([]string{})})
		authorization.PolicyIDs = append(authorization.PolicyIDs, id)
	}
	trust, name := []string{base64.RawURLEncoding.EncodeToString(der)}, "demo.example"
	for _, id := range []string{"demo-resource-a", "demo-resource-b"} {
		p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, control.TransportResource{ID: id, Kind: "hysteria2", OwnerNodeID: owner.ID, ListenerID: id,
			DialHost: "192.0.2.10", DialPort: 443, Authentication: control.ResourceAuthentication{ServerName: &name, CACertificates: &trust}})
	}
	if len(kinds) == 1 && kinds[0] == "wireguard" {
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		public := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
		p.NetworkIntent.Resources = []control.TransportResource{{ID: "demo-resource-a", Kind: "wireguard", OwnerNodeID: owner.ID, ListenerID: "demo-wg", AccessEnabled: true,
			DialHost: "192.0.2.10", DialPort: 51820, Authentication: control.ResourceAuthentication{PublicKey: &public, LocalAddresses: new([]string{"192.0.2.10/32"})}}}
	}
	p.DeviceAuthorizations = []control.DeviceAuthorization{authorization, owner}
	for i := range p.DeviceAuthorizations {
		value := &p.DeviceAuthorizations[i]
		public, err := control.DerivedWireGuardPublicKey(p.NetworkID, *value)
		if err != nil {
			t.Fatal(err)
		}
		for _, resource := range p.NetworkIntent.Resources {
			if resource.Kind == "wireguard" && resource.OwnerNodeID == value.ID {
				public = *resource.Authentication.PublicKey
			}
		}
		value.WireGuardPublicKey = public
	}
	view, err := control.ProjectDeviceView(p, authorization.ID)
	if err != nil {
		t.Fatal(err)
	}
	return view, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}, at
}

func TestAdmissionSpecsSeparatePolicyBindingsAndRetainOnlyMatchingDependencies(t *testing.T) {
	view, _, at := resourceProbeFixture(t)
	probes, err := control.FirstHopProbes(testDeviceExecution(view))
	if err != nil || len(probes) != 2 {
		t.Fatal("each actual Policy credential needs its own admission proof", err)
	}
	original := []control.Observation{}
	for _, probe := range probes {
		original = append(original, control.Observation{Level: "resource", ResourceID: probe.Resource.ID,
			Target: probe.Target(), Action: probe.Action(), SpecDigest: probe.SpecDigest,
			NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli()})
	}
	retained := RetainResourceObservations(probes, original, "demo-underlay")
	if !reflect.DeepEqual(retained, original) {
		t.Fatal("reuse changed original samples")
	}
	if len(RetainResourceObservations(probes, original, "demo-other-underlay")) != 0 {
		t.Fatal("old network samples survived")
	}
	probes[0].SpecDigest = "sha256:" + strings.Repeat("2", 64)
	unchanged := RetainResourceObservations(probes, original, "demo-underlay")
	if len(unchanged) != len(original)-1 || !reflect.DeepEqual(unchanged, original[1:]) {
		t.Fatal("changed resource kept its old sample or invalidated another resource")
	}
}

func TestHY2FirstHopRetainsUnderlayCauseAndCancellation(t *testing.T) {
	view, _, at := resourceProbeFixture(t)
	probes, err := control.FirstHopProbes(testDeviceExecution(view))
	if err != nil || len(probes) == 0 {
		t.Fatal("fixture has no first-hop probe", err)
	}
	for _, mode := range []string{"dial failure", "deadline", "cancel during last dial"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New("demo-underlay-failure")
			if mode == "deadline" {
				cause = context.DeadlineExceeded
			} else if mode == "cancel during last dial" {
				cause = context.Canceled
			}
			calls := 0
			ctx = control.WithEndpointDialer(ctx, func(_ context.Context, network, address string) (net.Conn, error) {
				calls++
				if network != "udp" || address != "192.0.2.10:443" {
					t.Fatal("probe changed its underlay target")
				}
				if mode == "cancel during last dial" {
					cancel()
				}
				return nil, cause
			})
			measured, err := probeHY2FirstHop(ctx, probes[0], nil, at)
			if !errors.Is(err, cause) || calls != 1 || measured.roundTripMS != nil || measured.transfer != nil {
				t.Fatal("failed Hy2 attempt lost its original cause, retried or produced a metric", err, calls)
			}
		})
	}
}

func TestHY2FirstHopRetainsEveryFailedAddressWithoutExtraAttempts(t *testing.T) {
	view, _, at := resourceProbeFixture(t)
	probes, err := control.FirstHopProbes(testDeviceExecution(view))
	if err != nil || len(probes) == 0 {
		t.Fatal("fixture has no first-hop probe", err)
	}
	probe := probes[0]
	probe.Resource.DialHost = "demo-first-hop.example"
	causes := map[string]error{"192.0.2.10:443": errors.New("demo-first-address"), "192.0.2.11:443": errors.New("demo-second-address")}
	var attempts atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = control.WithEndpointDialer(ctx, func(_ context.Context, network, address string) (net.Conn, error) {
		if cause, ok := causes[address]; ok && network == "udp" {
			attempts.Add(1)
			return nil, cause
		}
		if network != "udp" || address != "192.0.2.53:53" {
			return nil, errors.New("unexpected synthetic resolver dial")
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(time.Second))
			var raw [2048]byte
			n, err := server.Read(raw[:])
			var query dnsmessage.Message
			if err != nil || query.Unpack(raw[:n]) != nil || len(query.Questions) != 1 {
				return
			}
			query.Response = true
			if query.Questions[0].Type == dnsmessage.TypeA {
				for _, address := range [][4]byte{{192, 0, 2, 10}, {192, 0, 2, 11}} {
					query.Answers = append(query.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: address}})
				}
			}
			body, err := query.Pack()
			if err == nil {
				_, _ = server.Write(body)
			}
		}()
		return client, nil
	})
	measured, err := probeHY2FirstHop(ctx, probe, []string{"192.0.2.53"}, at)
	for _, cause := range causes {
		if !errors.Is(err, cause) {
			t.Fatal("failed-address aggregation lost an original cause", err)
		}
	}
	if attempts.Load() != 2 || measured.transfer != nil || measured.roundTripMS != nil {
		t.Fatal("failed addresses retried or produced metrics", attempts.Load())
	}
}

func TestFirstHopUsesProtectedDialerAndVerifiedQUICAuthentication(t *testing.T) {
	view, certificate, at := resourceProbeFixture(t)
	probes, _ := control.FirstHopProbes(testDeviceExecution(view))
	probe := probes[0]
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var requests atomic.Int32
	var echoStatus atomic.Uint32
	server := &http3.Server{StreamHijacker: func(kind http3.FrameType, _ quic.ConnectionTracingID, stream quic.Stream, err error) (bool, error) {
		if kind != protocol.Hy2FrameType || err != nil {
			return false, nil
		}
		go func() {
			defer stream.Close()
			body, err := protocol.ReadFrame(stream, 1024)
			if err != nil {
				return
			}
			request, err := protocol.UnmarshalRequest(body, 1)
			if err != nil || request.Operation != protocol.AdmissionEcho {
				return
			}
			response, _ := (protocol.Response{Nonce: request.Nonce, Status: protocol.Status(echoStatus.Load())}).Marshal()
			_ = protocol.WriteFrame(stream, response)
		}()
		return true, nil
	}, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/auth" || r.Header.Get("Hysteria-Auth") != probe.Credential {
			w.WriteHeader(404)
			return
		}
		requests.Add(1)
		w.WriteHeader(233)
	})}
	defer server.Close()
	go server.Serve(listener)
	var sockets atomic.Int32
	ctx := control.WithEndpointDialer(context.Background(), func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "192.0.2.10:443" {
			return nil, errors.New("unexpected underlay target")
		}
		sockets.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, listener.LocalAddr().String())
	})
	for _, test := range []struct {
		name   string
		change func(*control.ResourceProbe)
		good   bool
		status protocol.Status
		cause  error
	}{
		{name: "actual TLS and login", good: true},
		{name: "declared admission denial", status: protocol.Denied, cause: ErrEchoDenied},
		{name: "declared remote unavailability", status: protocol.Unavailable, cause: ErrEchoUnavailable},
		{name: "wrong credential", change: func(p *control.ResourceProbe) {
			p.Credential = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
		}},
		{name: "wrong TLS name", change: func(p *control.ResourceProbe) { name := "wrong.example"; p.Resource.Authentication.ServerName = &name }},
	} {
		t.Run(test.name, func(t *testing.T) {
			echoStatus.Store(uint32(test.status))
			value := probe
			if test.change != nil {
				test.change(&value)
			}
			var clock atomic.Int64
			clock.Store(at.UnixMilli())
			logged := WithEchoDiagnosticLog(ctx, func(string) { clock.Store(at.Add(time.Hour).UnixMilli()) })
			logged, captured := captureMeasurementTime(logged, func() time.Time { return time.UnixMilli(clock.Load()) })
			attempt, cancel := context.WithTimeout(logged, time.Second)
			defer cancel()
			measured, err := probeFirstHop(attempt, value, nil, at)
			transfer := measured.transfer
			if (err == nil) != test.good {
				t.Fatalf("actual authenticated outcome: %v", err)
			}
			if !captured.timing.completed.Equal(at) {
				t.Fatal("Hy2 diagnostic flush renewed the original completion time", captured.timing.completed)
			}
			if test.cause != nil && !errors.Is(err, test.cause) {
				t.Fatal("Hy2 address attempts lost the receiver's declared echo result", err)
			}
			if test.good && (transfer == nil || transfer.RXBytes == 0 || transfer.TXBytes == 0 || transfer.DurationNS <= 0) || !test.good && transfer != nil {
				t.Fatal("authentication bytes were missing or a failed login manufactured throughput")
			}
			if test.good && measured.roundTripMS == nil || !test.good && measured.roundTripMS != nil {
				t.Fatal("RTT was missing from an authenticated login or exposed from a failed one")
			}
		})
	}
	if sockets.Load() != 5 || requests.Load() != 3 {
		t.Fatal("authentication bypassed platform socket or TLS/credential verification")
	}
}
