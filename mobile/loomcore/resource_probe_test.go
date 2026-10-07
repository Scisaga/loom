package loomcore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
	"loom/internal/clientadapter"
	"loom/internal/control"
)

func TestAndroidFirstHopProtectedAuthenticationCacheAndOriginalReport(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"demo.example"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	_, port, _ := net.SplitHostPort(socket.LocalAddr().String())
	portNumber, _ := strconv.Atoi(port)
	name, trust := "demo.example", []string{base64.RawURLEncoding.EncodeToString(der)}
	configure := func(p *control.Projection) {
		owner := p.DeviceAuthorizations[0]
		owner.ID, owner.Responsibilities, owner.PolicyIDs = "demo-exit", []string{"internet_egress"}, []string{}
		p.DeviceAuthorizations = append(p.DeviceAuthorizations, owner)
		p.NetworkIntent.Resources = []control.TransportResource{{ID: "demo-resource", Kind: "hysteria2", OwnerNodeID: owner.ID,
			ListenerID: "demo-resource", DialHost: "127.0.0.1", DialPort: portNumber,
			Authentication: control.ResourceAuthentication{ServerName: &name, CACertificates: &trust}}}
	}
	state, body := androidFixture(t, 7, false, configure)
	probes, err := control.FirstHopProbes(state.LKG.View)
	if err != nil || len(probes) != 1 {
		t.Fatal("fixture must have one authorized first hop", err)
	}
	var requests atomic.Int32
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if r.Method != "POST" || r.URL.Path != "/auth" || r.Header.Get("Hysteria-Auth") != probes[0].Credential {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Hysteria-UDP", "true")
			w.WriteHeader(233)
		})}
	go func() { _ = server.Serve(socket) }()
	defer server.Close()
	protector := &testAndroidProtector{allow: true}
	SetAndroidSocketProtector(protector)
	defer SetAndroidSocketProtector(nil)
	var route control.RouteCandidate
	for _, candidate := range state.LKG.View.Routes {
		if candidate.FirstResourceID == "demo-resource" {
			route = candidate
		}
	}
	selections, _ := json.Marshal([]androidSelection{{Scope: route.Scope, CandidateID: route.ID}})
	cache, err := ObserveAndroidFirstHops(body, selections, nil, "demo-underlay")
	if err != nil || protector.calls == 0 || requests.Load() != 1 {
		t.Fatal("Android did not authenticate through its protected socket", err)
	}
	samples, err := clientadapter.DecodeResourceObservations(cache, *state.LKG, "demo-underlay")
	if err != nil || len(samples) != 1 || samples[0].Result != "available" {
		t.Fatal("Android lost the original authenticated resource result", err)
	}
	unchanged, err := ObserveAndroidFirstHops(body, selections, cache, "demo-underlay")
	if err != nil || !bytes.Equal(cache, unchanged) || requests.Load() != 1 {
		t.Fatal("valid sample was probed or retimed", err)
	}
	_, refreshed := androidFixture(t, 8, false, configure, func(p *control.Projection) { p.DeviceAuthorizations[0].Name = "Demo renamed" })
	unchanged, err = ObserveAndroidFirstHops(refreshed, selections, cache, "demo-underlay")
	if err != nil || !bytes.Equal(cache, unchanged) || requests.Load() != 1 {
		t.Fatal("unrelated accepted View invalidated original execution inputs", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	service, _ := json.Marshal([]androidObservation{{CandidateID: route.ID, NetworkGeneration: "demo-underlay", Scope: route.Scope,
		Result: "unavailable", Action: "https_request", Target: "https://demo.example:8443/health", ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)}})
	runtime, _ := json.Marshal(control.RuntimeReadback{State: "running", AppliedViewDigest: state.LKG.ViewDigest})
	state.ReportSequence = 1
	report, err := androidReport(state, cache, service, selections, runtime, []byte("[]"), "demo-underlay", now.Format(time.RFC3339))
	if err != nil || report.Verify(state.PublicKey) != nil || len(report.Observations) != 2 ||
		report.Observations[0].Level != "resource" || report.Observations[0].Result != "available" ||
		report.Observations[0].ObservedAt != samples[0].ObservedAt || report.Observations[1].Result != "unavailable" {
		t.Fatal("resource authentication changed the independent signed Service failure", err)
	}
	protector.allow = false
	failed, err := ObserveAndroidFirstHops(body, selections, cache, "demo-other-underlay")
	failedSamples, decodeErr := clientadapter.DecodeResourceObservations(failed, *state.LKG, "demo-other-underlay")
	if err != nil || decodeErr != nil || len(failedSamples) != 1 || failedSamples[0].Result != "unavailable" || requests.Load() != 1 {
		t.Fatal("network change reused health or bypassed failed socket protection", err, decodeErr)
	}
	calls := protector.calls
	unchanged, err = ObserveAndroidFirstHops(body, selections, failed, "demo-other-underlay")
	if err != nil || !bytes.Equal(failed, unchanged) || protector.calls != calls {
		t.Fatal("negative sample was discarded before its original deadline", err)
	}
	protector.allow = true
	later := time.UnixMilli(failedSamples[0].ValidUntil).Add(time.Second)
	recovered, err := observeAndroidFirstHops(androidNetworkContext(), state, selections, failed, "demo-other-underlay", func() time.Time { return later })
	recoveredSamples, decodeErr := clientadapter.DecodeResourceObservations(recovered, *state.LKG, "demo-other-underlay")
	if err != nil || decodeErr != nil || len(recoveredSamples) != 1 || recoveredSamples[0].Result != "available" || requests.Load() != 2 {
		t.Fatal("expired failure did not recover through a new real authentication", err, decodeErr)
	}
	_, revoked := androidFixture(t, 9, true, configure)
	empty, err := ObserveAndroidFirstHops(revoked, []byte("[]"), cache, "demo-underlay")
	revokedState, _ := decodeState(revoked)
	remaining, decodeErr := clientadapter.DecodeResourceObservations(empty, *revokedState.LKG, "demo-underlay")
	if err != nil || decodeErr != nil || len(remaining) != 0 || requests.Load() != 2 {
		t.Fatal("withdrawn resource remained reportable or was probed", err, decodeErr)
	}
	if _, err := ObserveAndroidFirstHops(body, selections, append(append([]byte{}, cache...), ' '), "demo-underlay"); err == nil {
		t.Fatal("corrupt cache was accepted")
	}
	duplicate, _ := json.Marshal([]androidSelection{{Scope: route.Scope, CandidateID: route.ID}, {Scope: route.Scope, CandidateID: route.ID}})
	if _, err := ObserveAndroidFirstHops(body, duplicate, nil, "demo-underlay"); err == nil || requests.Load() != 2 {
		t.Fatal("ambiguous selector readback was sampled")
	}
}
