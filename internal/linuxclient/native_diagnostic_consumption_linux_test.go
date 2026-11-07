package linuxclient

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"
	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"
)

// This is the normal daemon's sampler, reducer, cache, selection, and signed
// report path. Its only network fault is an owned UDP relay in the private
// namespace. The two business windows share the exact original failure sample;
// releasing the fault never creates a replacement Observation.
func TestOfficialLinuxNativeDiagnosticFailureConsumedByDaemon(t *testing.T) {
	native, cli := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE"), os.Getenv("LOOM_MEMBER_CLI")
	if native == "" {
		t.Skip("requires the reviewed native executable in a dedicated namespace")
	}
	if cli == "" {
		t.Fatal("explicit acceptance also requires the freshly built official CLI")
	}
	for _, kind := range []string{"user", "net", "mnt"} {
		current, e := os.Stat("/proc/self/ns/" + kind)
		initial, ie := os.Stat("/proc/1/ns/" + kind)
		if e != nil || ie != nil || os.SameFile(current, initial) {
			t.Fatal("daemon acceptance requires all three isolated namespaces")
		}
	}
	actual, err := os.ReadFile(native)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(actual)) != "0ca72e165b2638c7d617b5eb2967001127ccd35187f2713652bace321571274f" {
		t.Fatal("this acceptance requires the exact reviewed native bytes")
	}
	business := isolatedPublicFixtureAddress(t)
	nativeForwardDNS(t, business.As4())
	evidence := t.TempDir()
	if out := flag.Lookup("test.outputdir"); out != nil && out.Value.String() != "" {
		evidence = filepath.Join(out.Value.String(), "daemon-consumption-evidence")
		if err = os.Mkdir(evidence, 0700); err != nil {
			t.Fatal(err)
		}
	}
	put := func(name string, value any) {
		t.Helper()
		if err := writeNativeForwardEvidence(filepath.Join(evidence, name+".json"), value); err != nil {
			t.Fatal("private evidence write failed", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	p, keys, inputsPath, at := nativeProjectionFixture(t, 3*time.Minute)
	p.NetworkIntent.Resources = slices.DeleteFunc(p.NetworkIntent.Resources, func(r control.TransportResource) bool {
		return r.OwnerNodeID != "demo-entry" || r.Kind != "wireguard"
	})
	p.NetworkIntent.DNSRecords = []control.DNSRecord{}
	p.NetworkIntent.Policies[0].ExitScope = new(control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-entry"}})
	var inputs ResourceInputs
	if err = readStrict(inputsPath, 1<<20, &inputs); err != nil {
		t.Fatal(err)
	}
	inputs.Listeners = slices.DeleteFunc(inputs.Listeners, func(v ResourceListenerInput) bool { return v.ResourceID != p.NetworkIntent.Resources[0].ID })
	port, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	privatePort := port.LocalAddr().(*net.UDPAddr).Port
	port.Close()
	udp := newDiagnosticBusinessUDP(t, ctx, privatePort)
	p.NetworkIntent.Resources[0].DialHost, p.NetworkIntent.Resources[0].DialPort = "127.0.0.1", udp.port
	inputs.Listeners[0].ListenPort = privatePort
	if err = atomicJSON(inputsPath, inputs); err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "demo-sender.key")
	if err = os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key.Bytes())), 0600); err != nil {
		t.Fatal(err)
	}
	devices := []control.DevicePut{
		{ID: "demo-device", Name: "Demo access", Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-policy"}, DistributionURLs: []string{}, DNSServers: []string{"127.0.0.1"}, WireGuardPublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())},
		{ID: "demo-entry", Name: "Demo fixed exit", Responsibilities: []string{"forward", "internet_egress"}, PolicyIDs: []string{}, DistributionURLs: []string{}, DNSServers: []string{"127.0.0.1"}, WireGuardPublicKey: *p.NetworkIntent.Resources[0].Authentication.PublicKey},
	}
	authority, stores, states := startNativeForwardControlDevices(t, ctx, cli, evidence, p.NetworkIntent, devices)
	store, identity := stores["demo-device"], states["demo-device"]
	lkg := *store.LKG()
	// Load the receiver's exact authenticated projection only while its owner is
	// stopped; online evidence below uses the normal management readback.
	authority.stop(t)
	state, err := control.OpenAuthority(authority.root)
	if err != nil {
		t.Fatal(err)
	}
	p = state.Snapshot()
	authority.start(t)
	execution, err := control.ProjectDeviceCandidates(lkg.View, []string{"demo-policy"})
	if err != nil || len(execution.Routes) != 1 || execution.Routes[0].FinalExit != "demo-entry" {
		t.Fatal("one exact qualified fixed-exit candidate required", err)
	}
	probes, err := control.FirstHopProbes(execution)
	if err != nil || len(probes) != 1 {
		t.Fatal("one exact admission specification required", err)
	}
	route, probe := execution.Routes[0], probes[0]
	put("bindings", map[string]any{"candidate": route, "resource_id": probe.Resource.ID, "spec_digest": probe.SpecDigest, "operation": "admission_echo", "policy_id": probe.PolicyID, "native_sha256": fmt.Sprintf("%x", sha256.Sum256(actual)), "default_measurement_timing_unchanged": clientadapter.DefaultMeasurementTiming})
	startDiagnosticBusinessReceiver(t, ctx, p, inputsPath, native, keys["demo-entry"], at, evidence)
	root := t.TempDir()
	log, err := os.OpenFile(filepath.Join(evidence, "runtime.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	options := Options{DeviceState: identity, LocalState: filepath.Join(root, "observations.json"), Config: filepath.Join(root, "runtime.json"), Status: filepath.Join(root, "status.json"), SingBox: native, WireGuardPrivateKey: keyPath, Capture: "mixed", TraceProbes: true, Log: log}
	// This existing callback only waits before the first normal sampler. It
	// always returns the real clock and supplies no observation or cache value.
	options.Now = func() time.Time {
		if status, e := ReadStatus(options.Status); e == nil && status.Runtime == "running" && len(status.ResourceObservations) == 0 && len(status.Selections) == 1 {
			once.Do(func() { close(entered) })
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return time.Now()
	}
	runCtx, stopRun := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- Run(runCtx, options) }()
	var stopOnce sync.Once
	joined := false
	stop := func() {
		stopOnce.Do(func() {
			stopRun()
			select {
			case err := <-done:
				joined = true
				if err != nil {
					t.Error("normal daemon did not stop/join", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("normal daemon failed to join")
			}
		})
	}
	defer stop()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("normal daemon did not reach its real initial sampler boundary")
	}
	selector, err := NewHTTPSelector(string(mustNativeForwardConfig(t, options.Config)))
	if err != nil {
		t.Fatal(err)
	}
	api, err := nativeForwardReadAPI(options.Config)
	if err != nil {
		t.Fatal(err)
	}
	selection := func() clientmodel.Selection {
		t.Helper()
		v, e := selector.ReadSelection(ctx, "access")
		if e != nil || v.CandidateID != route.ID || v.PolicyID != route.PolicyID || v.Choices[route.ID].FinalExit != route.FinalExit {
			t.Fatal("actual selector escaped its Policy/candidate/fixed exit", e)
		}
		return v
	}
	certificate, trust := nativeScopesTLS(t)
	target, body, closeTarget := diagnosticBusinessHTTPS(t, business.String(), certificate, "demo-consumption")
	defer closeTarget()
	dial, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	caller := dial.(proxy.ContextDialer)
	old, err := diagnosticBusinessTLS(ctx, caller, target, trust)
	if err != nil {
		t.Fatal("initial ordinary TLS failed", err)
	}
	defer old.Close()
	if _, err = diagnosticBusinessBody(old, "demo-consumption", body); err != nil {
		t.Fatal(err)
	}
	oldPort := strings.Split(target, ":")[1]
	var oldID string
	oldTracker := func() nativeForwardConnection {
		t.Helper()
		values, e := api.connections(ctx)
		if e != nil {
			t.Fatal(e)
		}
		values = slices.DeleteFunc(values, func(v nativeForwardConnection) bool {
			return v.Metadata.DestinationPort != oldPort || oldID != "" && v.ID != oldID
		})
		if len(values) != 1 {
			t.Fatal("one actual original tracker required")
		}
		return values[0]
	}
	initialTracker := oldTracker()
	oldID = initialTracker.ID
	discardedBefore := udp.dropped.Load()
	udp.drop.Store(true)
	defer udp.drop.Store(false)
	startedFault := time.Now().UnixMilli()
	close(release)
	wait := func(label string, check func() bool) {
		t.Helper()
		deadline := time.Now().Add(25 * time.Second)
		for !check() {
			if ctx.Err() != nil || time.Now().After(deadline) {
				t.Fatal("normal daemon evidence missing", label)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	var failed control.Observation
	var failureStatus Status
	var failureCache LocalState
	wait("normal failed observation consumed and persisted", func() bool {
		status, e := ReadStatus(options.Status)
		if e != nil || status.Runtime != "running" || len(status.Selections) != 1 || status.Selections[0].CandidateID != route.ID {
			return false
		}
		for _, sample := range status.ResourceObservations {
			if sample.ResourceID == probe.Resource.ID && sample.SpecDigest == probe.SpecDigest && sample.Result == "unavailable" && sample.ObservedAt >= startedFault {
				cache, e := loadLocalState(options.LocalState, status.NetworkGeneration, lkg.ViewDigest)
				if e == nil && slices.ContainsFunc(cache.ResourceObservations, func(v control.Observation) bool { return reflect.DeepEqual(v, sample) }) {
					failed, failureStatus, failureCache = sample, status, cache
					return true
				}
			}
		}
		return false
	})
	var failureSnapshot control.WebSnapshot
	var reportReference control.DeviceEvidence
	wait("real signed failure report accepted by control", func() bool {
		snapshot, e := authority.snapshot(ctx)
		if e != nil {
			return false
		}
		for _, device := range snapshot.Devices {
			if device.ID != "demo-device" || device.Evidence == nil {
				continue
			}
			for _, sample := range device.Evidence.Measurements {
				if reflect.DeepEqual(sample.Observation, failed) {
					failureSnapshot, reportReference = snapshot, *device.Evidence
					return true
				}
			}
		}
		return false
	})
	diagnosticDiscarded := udp.dropped.Load() - discardedBefore
	if diagnosticDiscarded == 0 {
		t.Fatal("failed formal sampler has no actual owned underlay packet discard")
	}
	put("failure-consumed", map[string]any{"actual_sample": failed, "daemon_status": failureStatus, "daemon_cache": failureCache, "selection_result": failureStatus.Selections, "actual_selector": selection(), "normal_control_readback": failureSnapshot, "report_reference": reportReference, "actual_UDP_packets_discarded_before_business_failure": diagnosticDiscarded})
	// Failure business and successful business are separate bounded windows.
	// The first fails under the actual UDP fault; the second starts after its
	// precise release while the same unmodified failure sample remains valid.
	failedStart := time.Now().UnixMilli()
	failureCtx, cancelFailure := context.WithTimeout(ctx, 10*time.Second)
	failedConnection, businessErr := caller.DialContext(failureCtx, "tcp", target)
	if failedConnection != nil {
		failedConnection.Close()
	}
	cancelFailure()
	if businessErr == nil {
		t.Fatal("actual UDP fault fabricated a business connection")
	}
	feedback := func(result string, since int64) []clientadapter.NativeTCPObservation {
		t.Helper()
		raw, e := selector.ReadNativeObservations(ctx)
		if e != nil {
			t.Fatal(e)
		}
		values, e := clientadapter.DecodeNativeObservations(raw)
		if e != nil {
			t.Fatal(e)
		}
		put(fmt.Sprintf("native-TCP-readback-%s-%d", result, since), values)
		return slices.DeleteFunc(values, func(v clientadapter.NativeTCPObservation) bool {
			return v.CandidateID != route.ID || v.PolicyID != route.PolicyID || v.Target != target || v.Result != result || v.StartedAt < since
		})
	}
	// The local internal-TCP deadline is a real failed request, but has no
	// authenticated downstream result. Keep its actual activity unknown; never
	// turn a bare deadline into a definite unavailable target/path sample.
	failedFeedback := feedback("unknown", failedStart)
	if len(failedFeedback) == 0 {
		t.Fatal("real failed business has no corresponding native TCP result")
	}
	put("diagnostic-failure-business-failure", map[string]any{"window_started_at": failedStart, "window_finished_at": time.Now().UnixMilli(), "diagnostic_sample": failed, "business_error_type": fmt.Sprintf("%T", businessErr), "native_TCP_feedback": failedFeedback, "actual_selector": selection(), "cause": "owned encrypted WG UDP discard; internal TCP deadline, unknown downstream outcome; no execution Echo frame sent"})
	udp.drop.Store(false)
	successStart := time.Now().UnixMilli()
	recovered, err := diagnosticBusinessTLS(ctx, caller, target, trust)
	if err != nil {
		t.Fatal("release of owned fault did not restore normal TLS", err)
	}
	got, err := diagnosticBusinessBody(recovered, "demo-consumption", body)
	recovered.Close()
	if err != nil || time.Now().UnixMilli() >= failed.ValidUntil {
		t.Fatal("normal complete TLS did not occur within the original failure lifetime", err)
	}
	successStatus, err := ReadStatus(options.Status)
	if err != nil || !slices.ContainsFunc(successStatus.ResourceObservations, func(v control.Observation) bool { return reflect.DeepEqual(v, failed) }) {
		t.Fatal("successful business was not paired with the same cached failure", err)
	}
	successFeedback := feedback("available", successStart)
	if len(successFeedback) == 0 {
		t.Fatal("real successful business has no corresponding native TCP result")
	}
	if _, err = diagnosticBusinessBody(old, "demo-consumption", body); err != nil || !reflect.DeepEqual(initialTracker, oldTracker()) {
		t.Fatal("original legal connection or pinned chain did not recover", err)
	}
	put("diagnostic-failure-business-success", map[string]any{"window_started_at": successStart, "window_finished_at": time.Now().UnixMilli(), "same_original_diagnostic_sample": failed, "daemon_status": successStatus, "actual_selector": selection(), "native_TCP_feedback": successFeedback, "TLS_certificate_and_hostname_verified": true, "complete_body_sha256": fmt.Sprintf("%x", sha256.Sum256(got)), "original_tracker_and_chain_preserved": true})
	wait("normal fresh diagnostic recovery", func() bool {
		status, e := ReadStatus(options.Status)
		if e != nil {
			return false
		}
		for _, sample := range status.ResourceObservations {
			if sample.ResourceID == failed.ResourceID && sample.SpecDigest == failed.SpecDigest && sample.Result == "available" && sample.ObservedAt > failed.ObservedAt {
				put("normal-sampler-recovery", map[string]any{"status": status, "actual_selector": selection()})
				return true
			}
		}
		return false
	})
	stop()
	if !joined {
		t.Fatal("offline audit requires a joined report producer")
	}
	authority.stop(t)
	beforeDatabase, err := os.ReadFile(filepath.Join(authority.root, "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	reports := authority.offlineReports(t, "daemon-consumption-originals")
	afterDatabase, err := os.ReadFile(filepath.Join(authority.root, "observations.db"))
	if err != nil || sha256.Sum256(beforeDatabase) != sha256.Sum256(afterDatabase) {
		t.Fatal("offline audit changed the original database", err)
	}
	matched := []control.DeviceReport{}
	for _, report := range reports {
		if report.DeviceID == "demo-device" && slices.ContainsFunc(report.Observations, func(v control.Observation) bool { return reflect.DeepEqual(v, failed) }) {
			matched = append(matched, report)
		}
	}
	if len(matched) == 0 {
		t.Fatal("formally consumed failure has no exact signed original")
	}
	trace, err := os.ReadFile(filepath.Join(evidence, "runtime.log"))
	if err != nil {
		t.Fatal(err)
	}
	var echoID, nativeID string
	resourceHash := fmt.Sprintf("%x", sha256.Sum256([]byte(failed.ResourceID)))
	generationHash := fmt.Sprintf("%x", sha256.Sum256([]byte(failed.NetworkGeneration)))
	policyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(probe.PolicyID)))
	for _, line := range strings.Split(string(trace), "\n") {
		if strings.Contains(line, " binding resource_id_sha256="+resourceHash+" spec_digest="+failed.SpecDigest+" operation=admission_echo network_generation_sha256="+generationHash+" policy_id_sha256="+policyHash) {
			for _, part := range strings.Fields(line) {
				if strings.HasPrefix(part, "echo_id=") {
					echoID = strings.TrimPrefix(part, "echo_id=")
					break
				}
			}
			break // The first bound flight is the isolated failed sampler.
		}
	}
	for _, line := range strings.Split(string(trace), "\n") {
		if echoID != "" && strings.Contains(line, "echo_id="+echoID+" phase=local-connect-begin") {
			for _, part := range strings.Fields(line) {
				if strings.HasPrefix(part, "native_id=") {
					nativeID = strings.TrimPrefix(part, "native_id=")
				}
			}
		}
	}
	flight := []string{}
	for _, line := range strings.Split(string(trace), "\n") {
		if echoID != "" && strings.Contains(line, "echo_id="+echoID+" ") || nativeID != "" && strings.HasPrefix(line, "DEBUG native_id="+nativeID+" ") {
			flight = append(flight, line)
		}
	}
	if echoID == "" || nativeID == "" || !slices.ContainsFunc(flight, func(v string) bool {
		return strings.Contains(v, "phase=request-finish") && strings.Contains(v, "outcome=timeout")
	}) || slices.ContainsFunc(flight, func(v string) bool { return strings.Contains(v, "phase=request-write") }) {
		t.Fatal("failed formal sampler lost its exact request/native correlation or phase boundary")
	}
	put("final-summary", map[string]any{"echo_id": echoID, "native_id": nativeID, "resource_id": failed.ResourceID, "spec_digest": failed.SpecDigest, "operation": protocol.AdmissionEcho, "network_generation": failed.NetworkGeneration, "policy_id": route.PolicyID, "failed_Observation": failed, "same_flight_trace": flight, "signed_originals_containing_same_sample": matched, "formal_daemon_cache_selection_and_reports": true, "real_business_failure_and_success_windows": true, "normal_sampling_recovery": true, "database_sha256_before_after": fmt.Sprintf("%x", sha256.Sum256(beforeDatabase)), "producer_and_control_joined_before_offline_audit": true, "no_Observation_or_selector_injected": true, "only_owned_namespace_UDP_fault": true})
}
