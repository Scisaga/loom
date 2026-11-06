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
			response, _ := (protocol.Response{Nonce: request.Nonce, Status: protocol.Accepted}).Marshal()
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
	}{
		{name: "actual TLS and login", good: true},
		{name: "wrong credential", change: func(p *control.ResourceProbe) {
			p.Credential = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
		}},
		{name: "wrong TLS name", change: func(p *control.ResourceProbe) { name := "wrong.example"; p.Resource.Authentication.ServerName = &name }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := probe
			if test.change != nil {
				test.change(&value)
			}
			attempt, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			measured, err := probeFirstHop(attempt, value, nil, at)
			transfer := measured.transfer
			if (err == nil) != test.good {
				t.Fatalf("actual authenticated outcome: %v", err)
			}
			if test.good && (transfer == nil || transfer.RXBytes == 0 || transfer.TXBytes == 0 || transfer.DurationNS <= 0) || !test.good && transfer != nil {
				t.Fatal("authentication bytes were missing or a failed login manufactured throughput")
			}
			if test.good && measured.roundTripMS == nil || !test.good && measured.roundTripMS != nil {
				t.Fatal("RTT was missing from an authenticated login or exposed from a failed one")
			}
		})
	}
	if sockets.Load() != 3 || requests.Load() != 1 {
		t.Fatal("authentication bypassed platform socket or TLS/credential verification")
	}
}
