package loomcore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
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
		p.NetworkIntent.Policies[0].AllowDirect = new(false)
		owner := p.DeviceAuthorizations[0]
		owner.ID, owner.Responsibilities, owner.PolicyIDs = "demo-exit", []string{"internet_egress"}, []string{}
		p.DeviceAuthorizations = append(p.DeviceAuthorizations, owner)
		p.NetworkIntent.Resources = []control.TransportResource{{ID: "demo-resource", Kind: "hysteria2", OwnerNodeID: owner.ID,
			ListenerID: "demo-resource", DialHost: "127.0.0.1", DialPort: portNumber,
			Authentication: control.ResourceAuthentication{ServerName: &name, CACertificates: &trust}}}
	}
	state, body := androidFixture(t, 7, false, configure)
	probes, err := control.FirstHopProbes(testDeviceExecution(state.LKG.View))
	if err != nil || len(probes) != 1 {
		t.Fatal("fixture must have one authorized first hop", err)
	}
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
	}, TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}},
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
	for _, candidate := range testDeviceExecution(state.LKG.View).Routes {
		if candidate.FirstResourceID == "demo-resource" {
			route = candidate
		}
	}
	selections, _ := json.Marshal([]androidSelection{{Scope: control.AccessSelectorScope, CandidateID: route.ID}})
	cache, err := observeAndroidFirstHopsForTest(body, selections, nil, "demo-underlay")
	if err != nil || protector.calls.Load() == 0 || requests.Load() != 1 {
		t.Fatal("Android did not authenticate through its protected socket", err)
	}
	samples, err := clientadapter.DecodeResourceObservations(cache, *state.LKG, "demo-underlay", testPolicyIDs(state.LKG.View))
	if err != nil || len(samples) != 1 || samples[0].Result != "available" {
		t.Fatal("Android lost the original authenticated resource result", err)
	}
	unchanged, err := observeAndroidFirstHopsForTest(body, selections, cache, "demo-underlay")
	if err != nil || !bytes.Equal(cache, unchanged) || requests.Load() != 1 {
		t.Fatal("valid sample was probed or retimed", err)
	}
	_, refreshed := androidFixture(t, 8, false, configure, func(p *control.Projection) { p.DeviceAuthorizations[0].Name = "Demo renamed" })
	unchanged, err = observeAndroidFirstHopsForTest(refreshed, selections, cache, "demo-underlay")
	if err != nil || !bytes.Equal(cache, unchanged) || requests.Load() != 1 {
		t.Fatal("unrelated accepted View invalidated original execution inputs", err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	service, _ := json.Marshal([]androidObservation{{CandidateID: route.ID, NetworkGeneration: "demo-underlay", Scope: control.AccessSelectorScope,
		Result: "unavailable", Action: "https_request", Target: "https://demo.example:8443/health", ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)}})
	runtime, _ := json.Marshal(control.RuntimeReadback{State: "running", AppliedViewDigest: state.LKG.ViewDigest})
	state.ReportSequence = 1
	report, err := androidReport(state, nil, cache, service, selections, runtime, []byte("[]"), nil, "demo-underlay", now.Format(androidReportTimeLayout))
	if err != nil || report.Verify(state.PublicKey) != nil || len(report.Observations) != 2 ||
		report.Observations[0].Level != "resource" || report.Observations[0].Result != "available" ||
		report.Observations[0].ObservedAt != samples[0].ObservedAt || report.Observations[1].Result != "unavailable" {
		t.Fatal("resource authentication changed the independent signed Service failure", err)
	}
	// Resource samples use millisecond time even when the Service cache uses seconds.
	// The bridge must preserve a sample from earlier in the same report second.
	reportAt := time.Date(2030, 1, 1, 0, 1, 0, 120_000_000, time.UTC)
	for _, offset := range []int64{-1, 0, 1} {
		sample := samples[0]
		sample.ObservedAt = reportAt.UnixMilli() + offset
		sample.ValidUntil = sample.ObservedAt + time.Minute.Milliseconds()
		input, err := clientadapter.EncodeResourceObservations(*state.LKG, []control.Observation{sample}, testPolicyIDs(state.LKG.View))
		if err != nil {
			t.Fatal(err)
		}
		value, err := androidReport(state, nil, input, []byte("[]"), selections, runtime, []byte("[]"), nil, "demo-underlay", reportAt.Format(androidReportTimeLayout))
		want := 1
		if offset > 0 {
			want = 0
		}
		if err != nil || len(value.Observations) != want || value.ReportedAt != reportAt.UnixMilli() || want == 1 && value.Observations[0].ObservedAt != sample.ObservedAt {
			t.Fatal("resource millisecond boundary was rounded, retimed or treated as future", offset, err)
		}
	}
	protector.allow = false
	failed, err := observeAndroidFirstHopsForTest(body, selections, cache, "demo-other-underlay")
	failedSamples, decodeErr := clientadapter.DecodeResourceObservations(failed, *state.LKG, "demo-other-underlay", testPolicyIDs(state.LKG.View))
	if err != nil || decodeErr != nil || len(failedSamples) != 1 || failedSamples[0].Result != "unavailable" || requests.Load() != 1 {
		t.Fatal("network change reused health or bypassed failed socket protection", err, decodeErr)
	}
	profileBody, err := androidDeviceProfile(state)
	var profile androidProfile
	if err != nil || json.Unmarshal(profileBody, &profile) != nil {
		t.Fatal("accepted Android profile did not project first-hop references", err)
	}
	resources, err := AndroidCachedResourceObservations(failed, profile.ResourceCacheIdentity, "demo-other-underlay")
	if err != nil {
		t.Fatal(err)
	}
	routesBody, _ := json.Marshal(profile.Routes)
	targetsBody, _ := json.Marshal(profile.BusinessProbeTargets)
	preference, _ := testPolicyPreference()
	current, _ := json.Marshal(map[string]clientmodel.Selection{control.AccessSelectorScope: {CandidateID: route.ID, Targets: map[string]string{}}})
	evaluate := func(at time.Time, raw []byte) runtimeApplication {
		t.Helper()
		body, err := evaluateTestRoutes(routesBody, nil, preference, current, "demo-other-underlay", at.UnixMilli(), targetsBody, raw, nil, nil, nil, 0, nil)
		var result runtimeApplication
		if err != nil || json.Unmarshal(body, &result) != nil {
			t.Fatal("Android pure bridge could not consume its existing cache", err)
		}
		return result
	}
	afterFailure := evaluate(time.UnixMilli(failedSamples[0].ObservedAt), resources)
	if len(afterFailure.BlockedScopes) != 0 || len(afterFailure.Selections) != 1 || afterFailure.Selections[0].Candidate != route.ID || afterFailure.Selections[0].State != "unknown" {
		t.Fatal("failed protected diagnostic blocked the only qualified attempt or invented Service health")
	}
	expired := evaluate(time.UnixMilli(failedSamples[0].ValidUntil), resources)
	if len(expired.Selections) != 1 || expired.Selections[0].Candidate != route.ID || expired.Selections[0].State != "unknown" {
		t.Fatal("expired authentication failure prevented a new necessary attempt or invented Service health")
	}
	calls := protector.calls.Load()
	unchanged, err = observeAndroidFirstHopsForTest(body, selections, failed, "demo-other-underlay")
	if err != nil || !bytes.Equal(failed, unchanged) || protector.calls.Load() != calls {
		t.Fatal("negative sample was discarded before its original deadline", err)
	}
	protector.allow = true
	later := time.UnixMilli(failedSamples[0].ValidUntil).Add(time.Second)
	recovered, err := observeAndroidFirstHops(androidNetworkContext(), state, selections, failed, nil, "demo-other-underlay", func() time.Time { return later }, nil, nil, nil, nil, nil)
	recoveredSamples, decodeErr := clientadapter.DecodeResourceObservations(recovered, *state.LKG, "demo-other-underlay", testPolicyIDs(state.LKG.View))
	if err != nil || decodeErr != nil || len(recoveredSamples) != 1 || recoveredSamples[0].Result != "available" || requests.Load() != 2 {
		t.Fatal("expired failure did not recover through a new real authentication", err, decodeErr)
	}
	_, revoked := androidFixture(t, 9, true, configure)
	empty, err := observeAndroidFirstHopsForTest(revoked, []byte("[]"), cache, "demo-underlay")
	revokedState, _ := decodeState(revoked)
	remaining, decodeErr := clientadapter.DecodeResourceObservations(empty, *revokedState.LKG, "demo-underlay", testPolicyIDs(revokedState.LKG.View))
	if err != nil || decodeErr != nil || len(remaining) != 0 || requests.Load() != 2 {
		t.Fatal("withdrawn resource remained reportable or was probed", err, decodeErr)
	}
	if _, err := observeAndroidFirstHopsForTest(body, selections, append(append([]byte{}, cache...), ' '), "demo-underlay"); err == nil {
		t.Fatal("corrupt cache was accepted")
	}
	duplicate, _ := json.Marshal([]androidSelection{{Scope: control.AccessSelectorScope, CandidateID: route.ID}, {Scope: control.AccessSelectorScope, CandidateID: route.ID}})
	if _, err := observeAndroidFirstHopsForTest(body, duplicate, nil, "demo-underlay"); err == nil || requests.Load() != 2 {
		t.Fatal("ambiguous selector readback was sampled")
	}
	// A second authenticated resource is silent. The successful protected
	// exchange must be delivered before it finishes, and a rejected completion
	// must cancel the actual outstanding work without inventing a failure.
	quiet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer quiet.Close()
	quietStarted := make(chan struct{})
	go func() {
		var packet [2048]byte
		if _, _, err := quiet.ReadFrom(packet[:]); err == nil {
			close(quietStarted)
		}
	}()
	_, quietPort, _ := net.SplitHostPort(quiet.LocalAddr().String())
	quietNumber, _ := strconv.Atoi(quietPort)
	withQuiet, quietBody := androidFixture(t, 10, false, configure, func(p *control.Projection) {
		resource := p.NetworkIntent.Resources[0]
		resource.ID, resource.ListenerID, resource.DialPort = "demo-slow", "demo-slow", quietNumber
		p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, resource)
	})
	replaced := errors.New("demo runtime inputs replaced")
	var delivered []control.Observation
	request, err := NewAndroidFirstHopRequest(quietBody, selections, nil, nil, nil, nil, nil, "demo-progressive-underlay", androidMeasurementObserverFunc(func(delta []byte) error {
		select {
		case <-quietStarted:
		case <-time.After(3 * time.Second):
			return errors.New("silent concurrent exchange never started")
		}
		identity, _ := clientadapter.ResourceCacheIdentity(*withQuiet.LKG)
		merged, err := MergeAndroidResourceObservations(nil, delta, identity, "demo-progressive-underlay")
		if err != nil {
			return err
		}
		delivered, err = clientadapter.DecodeResourceObservations(merged, *withQuiet.LKG, "demo-progressive-underlay", testPolicyIDs(withQuiet.LKG.View))
		if err != nil {
			return err
		}
		return replaced
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = request.Run()
	if !errors.Is(err, replaced) || len(delivered) != 1 || delivered[0].ResourceID != "demo-resource" || delivered[0].Result != "available" {
		t.Fatal("Android did not deliver the fast original before cancelling silent work", err)
	}
	beforeCancel := requests.Load()
	request, err = NewAndroidFirstHopRequest(body, selections, nil, nil, nil, nil, nil, "demo-cancelled-underlay", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Cancel()
	if _, err := request.Run(); err == nil || requests.Load() != beforeCancel {
		t.Fatal("cancelled Android request started actual network work")
	}
}

type androidMeasurementObserverFunc func([]byte) error

func (observer androidMeasurementObserverFunc) Completed(body []byte) error  { return observer(body) }
func (observer androidMeasurementObserverFunc) Calibrated(body []byte) error { return nil }

func TestAndroidFirstHopRequestOwnsDeferredInputs(t *testing.T) {
	state, stateBody := androidFixture(t, 7, false)
	execution, err := control.ProjectDeviceCandidates(state.LKG.View, testPolicyIDs(state.LKG.View))
	if err != nil || len(execution.Routes) == 0 {
		t.Fatal("fixture requires an authorized Direct candidate", err)
	}
	identity, err := clientadapter.ResourceCacheIdentity(*state.LKG)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := clientadapter.EncodeResourceObservationCache(identity, []control.Observation{})
	if err != nil {
		t.Fatal(err)
	}
	generation := "demo-owned-underlay"
	at := time.Now().UTC().Truncate(time.Millisecond)
	native := clientmodel.Observation{CandidateID: execution.Routes[0].ID, Target: "demo.example:443", Scope: control.AccessSelectorScope,
		NetworkGeneration: generation, Result: "available", Action: "tcp_connect", ObservedAt: at.Format(time.RFC3339Nano),
		ValidUntil: at.Add(clientadapter.DefaultMeasurementTiming.SuccessValidity).Format(time.RFC3339Nano), MetricMillis: 1}
	if err := native.Validate(); err != nil {
		t.Fatal(err)
	}
	nativeBody, err := json.Marshal([]clientmodel.Observation{native})
	if err != nil {
		t.Fatal(err)
	}
	// A real native row exercises current/native/link decoding. The unbound
	// memory permits no calibration, and the Direct-only fixture performs no I/O.
	inputs := [][]byte{[]byte("[]"), previous, []byte(`{"access":{}}`), []byte("{}"), nativeBody, []byte("[]")}
	for index, name := range []string{"selections", "previous", "memory", "current", "native", "links"} {
		t.Run(name, func(t *testing.T) {
			owned := make([][]byte, len(inputs))
			for i := range inputs {
				owned[i] = bytes.Clone(inputs[i])
			}
			request, err := NewAndroidFirstHopRequest(stateBody, owned[0], owned[1], owned[2], owned[3], owned[4], owned[5], generation, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer request.Cancel()
			// JNI's transient input buffer ceases to belong to Go when the
			// constructor returns. Reuse it before the separate Run invocation.
			for i := range owned[index] {
				owned[index][i] = 'P'
			}
			body, err := request.Run()
			if err != nil {
				t.Fatal("request retained a borrowed constructor input", err)
			}
			values, err := clientadapter.ReadResourceObservationCache(body, identity, generation)
			if err != nil || len(values) != 0 {
				t.Fatal("request did not retain its original empty sample cache", err)
			}
		})
	}
}

func observeAndroidFirstHopsForTest(state, selections, previous []byte, generation string) ([]byte, error) {
	request, err := NewAndroidFirstHopRequest(state, selections, previous, nil, nil, nil, nil, generation, nil)
	if err != nil {
		return nil, err
	}
	return request.Run()
}

func TestAndroidFirstHopPriorityUsesExistingMemoryWithinTheActualPolicy(t *testing.T) {
	execution := control.DeviceExecution{Routes: []control.RouteCandidate{
		{ID: "demo-current", Scope: "service:demo-service", PolicyID: "demo-policy"},
		{ID: "demo-better", Scope: "service:demo-service", PolicyID: "demo-policy"},
		{ID: "demo-other", Scope: "service:demo-service", PolicyID: "demo-other-policy"},
	}}
	body, _ := json.Marshal([]androidSelection{{Scope: "access", CandidateID: "demo-current"}})
	for _, pending := range []string{"demo-better", "demo-other", "demo-absent"} {
		memory := map[string]clientmodel.SelectionMemory{"access": {PolicyID: "demo-policy", NetworkGeneration: "demo-network", Decisions: map[string]clientmodel.SelectionDecision{
			"": {Current: "demo-current", Pending: pending, Confirmations: 1},
		}}}
		encoded, _ := json.Marshal(memory)
		got, err := androidSelectedCandidates(execution, body, encoded, "demo-network")
		want := []string{"demo-current"}
		if pending == "demo-better" {
			want = []string{"demo-better", "demo-current"}
		}
		if err != nil || !slices.Equal(got, want) {
			t.Fatal("the Android bridge promoted an unauthorized comparison", got, want, err)
		}
	}
}
