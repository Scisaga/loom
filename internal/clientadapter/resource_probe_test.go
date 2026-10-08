package clientadapter

import (
	"bytes"
	"context"
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

	"github.com/sagernet/quic-go/http3"
	"loom/internal/control"
)

func resourceProbeFixture(t *testing.T) (control.DeviceView, tls.Certificate, time.Time) {
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
		p.NetworkIntent.Services = append(p.NetworkIntent.Services, control.Service{ID: id, Name: "Demo service", Kind: "internet", Matchers: []control.ServiceMatcher{{Kind: "dns_exact", Value: id + ".example"}}})
		p.NetworkIntent.Policies = append(p.NetworkIntent.Policies, control.NetworkPolicy{ID: id, ServiceID: id, Name: "Demo policy", Action: "allow", EntryScope: any, RelayScope: any, ExitScope: any, AllowDirect: true, LocalEgressDevices: []string{}})
		authorization.PolicyIDs = append(authorization.PolicyIDs, id)
	}
	trust, name := []string{base64.RawURLEncoding.EncodeToString(der)}, "demo.example"
	for _, id := range []string{"demo-resource-a", "demo-resource-b"} {
		p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, control.TransportResource{ID: id, Kind: "hysteria2", OwnerNodeID: owner.ID, ListenerID: id,
			DialHost: "192.0.2.10", DialPort: 443, Authentication: control.ResourceAuthentication{ServerName: &name, CACertificates: &trust}})
	}
	p.DeviceAuthorizations = []control.DeviceAuthorization{authorization, owner}
	view, err := control.ProjectDeviceView(p, authorization.ID)
	if err != nil {
		t.Fatal(err)
	}
	return view, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}, at
}

func TestFirstHopSamplesDeduplicateParallelizeAndKeepOriginalWindows(t *testing.T) {
	view, _, at := resourceProbeFixture(t)
	selected, direct := []string{}, []string{}
	for _, route := range view.Routes {
		if route.FinalExit == "direct" {
			direct = append(direct, route.ID)
		} else if route.ServiceID == "demo-c" && route.FirstResourceID == "demo-resource-b" || route.ServiceID != "demo-c" && route.FirstResourceID == "demo-resource-a" {
			selected = append(selected, route.ID)
		}
	}
	if len(selected) != 3 {
		t.Fatal("fixture lost its shared resource")
	}
	var calls atomic.Int32
	started, release := make(chan struct{}, 2), make(chan struct{})
	probe := func(ctx context.Context, resource control.ResourceProbe, _ []string, _ time.Time) error {
		calls.Add(1)
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		if resource.Resource.ID == "demo-resource-b" {
			return errors.New("demo authentication rejected")
		}
		return nil
	}
	type outcome struct {
		values []control.Observation
		err    error
	}
	finished := make(chan outcome, 1)
	go func() {
		values, err := observeFirstHops(context.Background(), view, selected, nil, "demo-underlay", func() time.Time { return at }, probe)
		finished <- outcome{values, err}
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("independent resources did not start in parallel")
		}
	}
	close(release)
	first := <-finished
	if first.err != nil || len(first.values) != 2 || calls.Load() != 2 || first.values[0].Result != "available" || first.values[1].Result != "unavailable" {
		t.Fatal("shared resource sampled twice or scope results were mixed", first.err)
	}
	if first.values[0].ValidUntil != at.Add(10*time.Minute).UnixMilli() || first.values[1].ValidUntil != at.Add(30*time.Second).UnixMilli() {
		t.Fatal("new samples have wrong retry windows")
	}
	noProbe := func(context.Context, control.ResourceProbe, []string, time.Time) error {
		t.Error("valid or unneeded resource was sampled")
		return nil
	}
	retained, err := observeFirstHops(context.Background(), view, selected, first.values, "demo-underlay", func() time.Time { return at.Add(29 * time.Second) }, noProbe)
	if err != nil || !reflect.DeepEqual(first.values, retained) {
		t.Fatal("reuse changed original time or failure", err)
	}
	if values, err := observeFirstHops(context.Background(), view, direct, nil, "demo-underlay", func() time.Time { return at }, noProbe); err != nil || len(values) != 0 {
		t.Fatal("Direct acquired transport observations", err)
	}
	var retries atomic.Int32
	retry := func(_ context.Context, resource control.ResourceProbe, _ []string, _ time.Time) error {
		if resource.Resource.ID != "demo-resource-b" {
			t.Error("unexpired success was retried")
		}
		retries.Add(1)
		return nil
	}
	next, err := observeFirstHops(context.Background(), view, selected, retained, "demo-underlay", func() time.Time { return at.Add(30 * time.Second) }, retry)
	if err != nil || retries.Load() != 1 || next[1].Result != "available" || !reflect.DeepEqual(next[0], first.values[0]) {
		t.Fatal("expired failure could not recover without replacing good sample", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if values, err := observeFirstHops(ctx, view, selected, nil, "demo-underlay", func() time.Time { return at }, noProbe); err == nil || len(values) != 0 {
		t.Fatal("cancelled operation manufactured samples")
	}
	probes, _ := control.FirstHopProbes(view)
	if len(RetainResourceObservations(probes, first.values, "demo-other-network")) != 0 {
		t.Fatal("old network cache survived")
	}
	probes[0].SpecDigest = "sha256:" + strings.Repeat("2", 64)
	unchanged := RetainResourceObservations(probes, first.values, "demo-underlay")
	if err != nil || len(unchanged) != 1 || !reflect.DeepEqual(unchanged[0], first.values[1]) {
		t.Fatal("one changed resource invalidated an unrelated sample or kept its old result", err)
	}
}

func TestFirstHopUsesProtectedDialerAndVerifiedQUICAuthentication(t *testing.T) {
	view, certificate, at := resourceProbeFixture(t)
	probes, _ := control.FirstHopProbes(view)
	probe := probes[0]
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var requests atomic.Int32
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			err := probeFirstHop(attempt, value, nil, at)
			if (err == nil) != test.good {
				t.Fatalf("actual authenticated outcome: %v", err)
			}
		})
	}
	if sockets.Load() != 3 || requests.Load() != 1 {
		t.Fatal("authentication bypassed platform socket or TLS/credential verification")
	}
}
