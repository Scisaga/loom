package linuxclient

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/proxy"
	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"
)

// The normal Run owns authorization, descriptions and selection. The optional
// caller supplies a reviewed native binary and a separate user/net/mount ns.
// No Observation is invented, no selector is written by this test, and no
// management endpoint impersonates a report-accepting control.
func TestOfficialLinuxNativeDiagnosticBusinessMatrix(t *testing.T) {
	native := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if native == "" {
		t.Skip("requires the reviewed native executable in a dedicated namespace")
	}
	for _, kind := range []string{"user", "net", "mnt"} {
		current, e := os.Stat("/proc/self/ns/" + kind)
		initial, ie := os.Stat("/proc/1/ns/" + kind)
		if e != nil || ie != nil || os.SameFile(current, initial) {
			t.Fatal("diagnostic/business acceptance requires all three isolated namespaces")
		}
	}
	actual, err := os.ReadFile(native)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(actual)) != "0ca72e165b2638c7d617b5eb2967001127ccd35187f2713652bace321571274f" {
		t.Fatal("this acceptance requires the exact reviewed native bytes")
	}
	// This existing guard proves only lo and no external route before generating
	// the operator-approved synthetic ordinary-internet address.
	business := isolatedPublicFixtureAddress(t)
	if err = exec.Command("ip", "address", "add", "192.0.2.1/32", "dev", "lo").Run(); err != nil {
		t.Fatal(err)
	}
	nativeForwardDNS(t, business.As4())
	evidence := t.TempDir()
	if out := flag.Lookup("test.outputdir"); out != nil && out.Value.String() != "" {
		evidence = filepath.Join(out.Value.String(), "diagnostic-business-evidence")
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
	p.DeviceAuthorizations[1].Responsibilities = []string{"forward", "internet_egress"}
	p.NetworkIntent.Policies[0].ExitScope = new(control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-entry"}})
	p.NetworkIntent.Resources = slices.DeleteFunc(p.NetworkIntent.Resources, func(r control.TransportResource) bool {
		return r.OwnerNodeID != "demo-entry" || r.Kind != "wireguard"
	})
	for i := range p.DeviceAuthorizations {
		p.DeviceAuthorizations[i].DNSServers = []string{"127.0.0.1"}
	}
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
	store, identity, makeView := linuxAcceptanceProjectionFixture(t, func(v *control.Projection) {
		source := v.DeviceAuthorizations[0]
		source.WireGuardPublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
		source.DNSServers = []string{"127.0.0.1"}
		v.DeviceAuthorizations = append([]control.DeviceAuthorization{source}, p.DeviceAuthorizations[1:]...)
		v.NetworkIntent = p.NetworkIntent
		p.Config, p.EndpointGenerations, p.DeviceAuthorizations = v.Config, v.EndpointGenerations, v.DeviceAuthorizations
	})
	lkg := makeView(7, true)
	execution, err := control.ProjectDeviceCandidates(lkg.View, []string{"demo-policy"})
	if err != nil || len(execution.Routes) != 1 || execution.Routes[0].FinalExit != "demo-entry" {
		t.Fatal("one exact qualified candidate and final exit required", err)
	}
	probes, err := control.FirstHopProbes(execution)
	if err != nil || len(probes) != 1 || probes[0].PolicyID != "demo-policy" {
		t.Fatal("one exact admission specification required", err)
	}
	route, probe := execution.Routes[0], probes[0]
	if err = store.SaveLKG(lkg); err != nil {
		t.Fatal(err)
	}
	if err = store.SetPreference(clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}); err != nil {
		t.Fatal(err)
	}
	viewOriginal, err := control.CanonicalEncode(lkg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(evidence, "signed-view-original.json"), viewOriginal, 0600); err != nil {
		t.Fatal(err)
	}
	put("bindings", map[string]any{"candidate": route, "resource_id": probe.Resource.ID, "spec_digest": probe.SpecDigest, "generation": "demo-underlay", "native_sha256": fmt.Sprintf("%x", sha256.Sum256(actual)), "default_measurement_timing_unchanged": clientadapter.DefaultMeasurementTiming})
	startDiagnosticBusinessReceiver(t, ctx, p, inputsPath, native, keys["demo-entry"], at, evidence)
	management, err := net.Listen("tcp", "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer management.Close()
	go func() {
		for {
			c, err := management.Accept()
			if err != nil {
				return
			}
			go func() { <-ctx.Done(); c.Close() }()
		}
	}()
	root := t.TempDir()
	log, err := os.OpenFile(filepath.Join(evidence, "runtime.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var hold sync.Once
	options := Options{DeviceState: identity, LocalState: filepath.Join(root, "observations.json"), Config: filepath.Join(root, "runtime.json"), Status: filepath.Join(root, "status.json"), SingBox: native, WireGuardPrivateKey: keyPath, Capture: "mixed", RefreshPoll: time.Hour, TraceProbes: true, Log: log, Generation: func() (string, error) { return "demo-underlay", nil }}
	// Block the existing sampler callback only after Run actually published a
	// legal running selection with no diagnostic result. Never invent a clock.
	options.Now = func() time.Time {
		if status, e := ReadStatus(options.Status); e == nil && status.Runtime == "running" && len(status.ResourceObservations) == 0 && len(status.Selections) == 1 && status.Selections[0].CandidateID == route.ID {
			hold.Do(func() { close(entered) })
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return time.Now()
	}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, options) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error("normal Run did not join", err)
		}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("Run did not expose its real unmeasured legal-selection window")
	}
	config := string(mustNativeForwardConfig(t, options.Config))
	selector, err := NewHTTPSelector(config)
	if err != nil {
		t.Fatal(err)
	}
	api, err := nativeForwardReadAPI(options.Config)
	if err != nil {
		t.Fatal(err)
	}
	readSelection := func() clientmodel.Selection {
		t.Helper()
		v, e := selector.ReadSelection(ctx, "access")
		if e != nil || v.CandidateID != route.ID || v.PolicyID != route.PolicyID || v.Choices[route.ID].FinalExit != route.FinalExit {
			t.Fatal("normal selection escaped its exact candidate/Policy/exit", e)
		}
		return v
	}
	readSelection()
	certificate, trust := nativeScopesTLS(t)
	baseTarget, baseBody, closeBase := diagnosticBusinessHTTPS(t, business.String(), certificate, "demo-persistent")
	defer closeBase()
	dial, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	caller := dial.(proxy.ContextDialer)
	old, err := diagnosticBusinessTLS(ctx, caller, baseTarget, trust)
	if err != nil {
		t.Fatal("initial ordinary TLS failed", err)
	}
	defer old.Close()
	if _, err = diagnosticBusinessBody(old, "demo-persistent", baseBody); err != nil {
		t.Fatal(err)
	}
	oldPort := strings.Split(baseTarget, ":")[1]
	oldConnection := func() nativeForwardConnection {
		t.Helper()
		all, e := api.connections(ctx)
		if e != nil {
			t.Fatal(e)
		}
		all = slices.DeleteFunc(all, func(v nativeForwardConnection) bool { return v.Metadata.DestinationPort != oldPort })
		if len(all) != 1 {
			t.Fatal("one actual persistent tracker required")
		}
		return all[0]
	}
	beforeOld := oldConnection()
	rows := []map[string]any{}
	ordinary := func(label string, success bool) map[string]any {
		t.Helper()
		row := map[string]any{"case": label, "candidate_id": route.ID, "policy_id": route.PolicyID, "final_exit": route.FinalExit, "selector_before": readSelection(), "request_started_at": time.Now().UnixMilli()}
		var target, body string
		if success {
			var closeTarget func()
			target, body, closeTarget = diagnosticBusinessHTTPS(t, business.String(), certificate, label)
			defer closeTarget()
		} else {
			closed, e := net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
			if e != nil {
				t.Fatal(e)
			}
			_, port, _ := net.SplitHostPort(closed.Addr().String())
			target = net.JoinHostPort("demo-forward.example", port)
			closed.Close()
		}
		pending, stop := context.WithTimeout(ctx, 5*time.Second)
		c, e := diagnosticBusinessTLS(pending, caller, target, trust)
		var got []byte
		if e == nil {
			got, e = diagnosticBusinessBody(c, label, body)
			c.Close()
		}
		stop()
		row["request_finished_at"], row["ordinary_target"], row["ordinary_success"], row["actual_tls"], row["complete_body_sha256"], row["ordinary_error_type"] = time.Now().UnixMilli(), target, e == nil, e == nil, fmt.Sprintf("%x", sha256.Sum256(got)), fmt.Sprintf("%T", e)
		if (e == nil) != success {
			put(label+"-failed", row)
			t.Fatal("real ordinary request disagreed with the case", label, e)
		}
		raw, e := selector.ReadNativeObservations(ctx)
		if e != nil {
			t.Fatal(e)
		}
		observations, e := clientadapter.DecodeNativeObservations(raw)
		if e != nil {
			t.Fatal(e)
		}
		matched := []clientadapter.NativeTCPObservation{}
		for _, o := range observations {
			if o.CandidateID == route.ID && o.PolicyID == route.PolicyID && o.Target == target && o.StartedAt >= row["request_started_at"].(int64) {
				matched = append(matched, o)
			}
		}
		want := "unavailable"
		if success {
			want = "available"
		}
		if !slices.ContainsFunc(matched, func(o clientadapter.NativeTCPObservation) bool { return o.Result == want }) {
			put(label+"-missing-feedback", map[string]any{"row": row, "native": observations})
			t.Fatal("actual business result absent from native feedback", label)
		}
		row["native_TCP_feedback"], row["selector_after"] = matched, readSelection()
		if _, e = diagnosticBusinessBody(old, "demo-persistent", baseBody); e != nil {
			t.Fatal("unrelated existing TLS was interrupted", e)
		}
		if after := oldConnection(); !reflect.DeepEqual(beforeOld, after) {
			t.Fatal("diagnostic/failed request changed the original tracker or chain")
		}
		row["original_tracker_and_chain_preserved"] = true
		return row
	}
	for _, good := range []bool{true, false} {
		label := "unknown-failure"
		if good {
			label = "unknown-success"
		}
		status, e := ReadStatus(options.Status)
		if e != nil || len(status.ResourceObservations) != 0 {
			t.Fatal("unknown must be the actual Run's unmeasured window", e)
		}
		row := ordinary(label, good)
		after, e := ReadStatus(options.Status)
		if e != nil || len(after.ResourceObservations) != 0 {
			t.Fatal("a measurement escaped the startup barrier", e)
		}
		row["diagnostic_result"], row["unknown_reason"], row["actual_Run_status_before"], row["actual_Run_status_after"] = "unknown", "first normal sampler has not executed; no Observation created", status, after
		put(label, row)
		rows = append(rows, row)
	}
	close(release)
	deadline := time.Now().Add(12 * time.Second)
	for {
		status, e := ReadStatus(options.Status)
		if e == nil && slices.ContainsFunc(status.ResourceObservations, func(v control.Observation) bool {
			return v.ResourceID == probe.Resource.ID && v.SpecDigest == probe.SpecDigest && v.Result == "available"
		}) {
			put("normal-sampler-resumed", status)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("released normal sampler did not produce its real observation")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, test := range []struct {
		label, mode, diagnostic string
		business                bool
	}{
		{"success-success", "pass", "success", true}, {"timeout-success", "hold", "timeout", true},
		{"failure-failure", "close", "failure", false}, {"success-failure", "pass", "success", false},
	} {
		gate := newDiagnosticBusinessGate(t, ctx, evidence, test.label, test.mode)
		var mu sync.Mutex
		lines := []string{}
		probeCtx := clientadapter.WithEchoDiagnosticLog(ctx, func(line string) { mu.Lock(); lines = append(lines, line); mu.Unlock() })
		probeCtx, err = clientadapter.WithNativeDiagnostic(probeCtx, config, func(c context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "127.0.0.1:61800" {
				return nil, errors.New("diagnostic attempted an unexpected local entry")
			}
			return (&net.Dialer{}).DialContext(c, "tcp", gate.address)
		})
		if err != nil {
			t.Fatal(err)
		}
		budget, e := clientadapter.NewMeasurementBudget(clientadapter.MeasurementLimits{Window: time.Minute, Requests: 8, Concurrent: 2, Bytes: 1 << 20, Timeout: time.Second}, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		probeCtx = clientadapter.WithMeasurementBudget(probeCtx, budget)
		observed, e := clientadapter.ObserveFirstHops(probeCtx, execution, []string{route.ID}, nil, "demo-underlay", time.Now, nil)
		if e != nil || len(observed) != 1 {
			t.Fatal("actual admission flight did not produce one result", e)
		}
		<-gate.done
		if gate.err != nil {
			t.Fatal("diagnostic gate failed", gate.err)
		}
		mu.Lock()
		captured := append([]string{}, lines...)
		mu.Unlock()
		outcome := "failed"
		if test.diagnostic == "success" {
			outcome = "success"
		}
		if test.diagnostic == "timeout" {
			outcome = "timeout"
		}
		if !slices.ContainsFunc(captured, func(v string) bool {
			return strings.Contains(v, "phase=request-finish") && strings.HasSuffix(v, "outcome="+outcome)
		}) {
			t.Fatal("original diagnostic outcome was not observed", captured)
		}
		if (observed[0].Result == "available") != (test.diagnostic == "success") || observed[0].ResourceID != probe.Resource.ID || observed[0].SpecDigest != probe.SpecDigest {
			t.Fatal("diagnostic result escaped its exact resource/specification")
		}
		row := ordinary(test.label, test.business)
		if row["request_finished_at"].(int64) >= observed[0].ValidUntil {
			t.Fatal("business completed outside its paired diagnostic validity")
		}
		row["diagnostic_result"], row["actual_Observation"], row["diagnostic_trace"], row["gate"] = test.diagnostic, observed[0], captured, gate.proof
		put(test.label, row)
		rows = append(rows, row)
	}
	put("six-row-summary", map[string]any{"rows": rows, "all_six_real_pairs_passed": len(rows) == 6, "formal_Run_owned_selection": true, "normal_sampler_recovered": true, "protocol_authority_or_clock_fabricated": false, "phone_or_remote_result_claimed": false})
	// A second finite network fault owns only this test proxy's exact UDP
	// mapping. Unlike the diagnostic-delivery gate above, real encrypted WG
	// packets are now discarded, and a new ordinary connection really fails.
	var stageMu sync.Mutex
	stageTrace := []string{}
	stageCtx := clientadapter.WithEchoDiagnosticLog(ctx, func(line string) { stageMu.Lock(); stageTrace = append(stageTrace, line); stageMu.Unlock() })
	stageCtx, err = clientadapter.WithNativeDiagnostic(stageCtx, config, nil)
	if err != nil {
		t.Fatal(err)
	}
	dropBefore := udp.dropped.Load()
	udp.drop.Store(true)
	defer udp.drop.Store(false)
	probeDeadline, endProbe := context.WithTimeout(stageCtx, 1200*time.Millisecond)
	rtt, probeErr := clientadapter.ProbeWireGuardAdmission(probeDeadline, probe)
	endProbe()
	var timeout net.Error
	if rtt != nil || probeErr == nil || !errors.Is(probeErr, context.DeadlineExceeded) && !(errors.As(probeErr, &timeout) && timeout.Timeout()) || udp.dropped.Load() <= dropBefore {
		t.Fatal("actual discarded WG underlay did not produce its real timeout", probeErr)
	}
	failedCtx, endFailure := context.WithTimeout(ctx, 10*time.Second)
	failed, businessErr := caller.DialContext(failedCtx, "tcp", baseTarget)
	if failed != nil {
		failed.Close()
	}
	endFailure()
	if businessErr == nil {
		t.Fatal("dropped WG underlay fabricated an ordinary connection")
	}
	udp.drop.Store(false)
	stageMu.Lock()
	capturedStage := append([]string{}, stageTrace...)
	stageMu.Unlock()
	nativeTrace, err := os.ReadFile(filepath.Join(evidence, "runtime.log"))
	if err != nil {
		t.Fatal(err)
	}
	var flightID string
	for _, line := range capturedStage {
		if strings.Contains(line, "phase=request-start") {
			flightID = strings.TrimPrefix(strings.Fields(line)[0], "echo_id=")
		}
	}
	nativeID := ""
	for _, line := range strings.Split(string(nativeTrace), "\n") {
		if strings.Contains(line, "echo_id="+flightID+" phase=local-connect-begin") {
			for _, part := range strings.Fields(line) {
				if strings.HasPrefix(part, "native_id=") {
					nativeID = part
				}
			}
		}
	}
	if flightID == "" || nativeID == "" {
		t.Fatal("actual failed flight lost its native correlation")
	}
	pairedNative := []string{}
	for _, line := range strings.Split(string(nativeTrace), "\n") {
		if strings.HasPrefix(line, "DEBUG "+nativeID+" ") {
			pairedNative = append(pairedNative, line)
		}
	}
	if !slices.ContainsFunc(pairedNative, func(line string) bool {
		return strings.Contains(line, "WG stage=peer-prepare event=end") && strings.Contains(line, "error_type=<nil>")
	}) || !slices.ContainsFunc(pairedNative, func(line string) bool {
		return strings.Contains(line, "WG stage=inner-dial event=end") && !strings.Contains(line, "error_type=<nil>")
	}) {
		t.Fatal("actual drop did not expose successful preparation and failed inner TCP")
	}
	if slices.ContainsFunc(capturedStage, func(line string) bool { return strings.Contains(line, "phase=request-write") }) {
		t.Fatal("an unestablished tunnel reported an execution request")
	}
	recoveryCtx, endRecovery := context.WithTimeout(ctx, 6*time.Second)
	recovered, err := diagnosticBusinessTLS(recoveryCtx, caller, baseTarget, trust)
	if err == nil {
		_, err = diagnosticBusinessBody(recovered, "demo-persistent", baseBody)
		recovered.Close()
	}
	endRecovery()
	if err != nil {
		t.Fatal("removing only the actual UDP drop did not restore ordinary TLS", err)
	}
	put("underlay-drop-stage", map[string]any{"diagnostic_trace": capturedStage, "same_flight_native_trace": pairedNative, "actual_UDP_packets_discarded": udp.dropped.Load() - dropBefore, "ordinary_connect_error_type": fmt.Sprintf("%T", businessErr), "same_candidate_and_policy": readSelection(), "ordinary_TLS_recovered_without_facts_or_reselection": true, "execution_request_not_sent": true})

	// Hold only the new target's SYN in this private namespace. The real WG
	// receiving node must already have accepted its inner TCP before waiting
	// for the downstream TCP confirmation. Merely withholding TLS data would
	// not exercise this boundary.
	confirmTarget, confirmBody, closeConfirm := diagnosticBusinessHTTPS(t, business.String(), certificate, "demo-confirm-deadline")
	defer closeConfirm()
	beforeConfirmLog, err := os.Stat(filepath.Join(evidence, "runtime.log"))
	if err != nil {
		t.Fatal(err)
	}
	_, confirmPort, _ := net.SplitHostPort(confirmTarget)
	removeDrop := diagnosticBusinessSYNDrop(t, business.String(), confirmPort, evidence)
	confirmCtx, endConfirm := context.WithTimeout(ctx, 11*time.Second)
	confirmation := make(chan error, 1)
	startedConfirm := time.Now()
	go func() {
		c, e := caller.DialContext(confirmCtx, "tcp", confirmTarget)
		if c != nil {
			c.Close()
		}
		confirmation <- e
	}()
	synSeen := false
	for time.Since(startedConfirm) < 3*time.Second {
		b, e := os.ReadFile("/proc/net/tcp")
		if e != nil {
			t.Fatal(e)
		}
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 3 && fields[3] == "02" && strings.HasSuffix(fields[2], ":"+fmt.Sprintf("%04X", mustDiagnosticPort(t, confirmPort))) {
				synSeen = true
			}
		}
		if synSeen {
			if err = os.WriteFile(filepath.Join(evidence, "execution-confirm-real-SYN_SENT.txt"), b, 0600); err != nil {
				t.Fatal(err)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err = diagnosticBusinessBody(old, "demo-persistent", baseBody); err != nil {
		t.Fatal("exact target TCP drop affected the unrelated original TLS stream", err)
	}
	confirmErr := <-confirmation
	callerDeadlineWasNotCause := confirmCtx.Err() == nil
	endConfirm()
	duration := time.Since(startedConfirm)
	if !synSeen || confirmErr == nil || duration < 7*time.Second || duration >= 11*time.Second {
		t.Fatal("actual native execution confirmation did not reach its own deadline", synSeen, duration, confirmErr)
	}
	removeDrop()
	nativeTrace, err = os.ReadFile(filepath.Join(evidence, "runtime.log"))
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(nativeTrace)) < beforeConfirmLog.Size() {
		t.Fatal("original trace was truncated")
	}
	confirmLines := strings.Split(string(nativeTrace[beforeConfirmLog.Size():]), "\n")
	confirmNativeID := ""
	confirmEnds := 0
	for _, line := range confirmLines {
		if strings.Contains(line, "WG stage=execution-confirm event=end") && strings.Contains(line, "canceled=true") {
			var id string
			var elapsed time.Duration
			for _, part := range strings.Fields(line) {
				if strings.HasPrefix(part, "native_id=") {
					id = part
				}
				if strings.HasPrefix(part, "elapsed=") {
					elapsed, _ = time.ParseDuration(strings.TrimPrefix(part, "elapsed="))
				}
			}
			if elapsed >= 7*time.Second && elapsed < 10*time.Second && id != "" {
				confirmNativeID = id
				confirmEnds++
			}
		}
	}
	confirmNative := []string{}
	for _, line := range confirmLines {
		if confirmNativeID != "" && strings.HasPrefix(line, "DEBUG "+confirmNativeID+" ") {
			confirmNative = append(confirmNative, line)
		}
	}
	confirmationCause := confirmEnds == 1 && callerDeadlineWasNotCause
	for _, stage := range []string{"peer-prepare", "inner-dial"} {
		confirmationCause = confirmationCause && slices.ContainsFunc(confirmNative, func(line string) bool {
			return strings.Contains(line, "WG stage="+stage+" event=end") && strings.Contains(line, "error_type=<nil>")
		})
	}
	confirmationCause = confirmationCause && slices.ContainsFunc(confirmNative, func(line string) bool { return strings.Contains(line, "WG stage=execution-confirm event=begin") })
	put("execution-confirm-deadline", map[string]any{"actual_downstream_SYN_SENT": synSeen, "actual_native_confirm_timeout_after_successful_peer_and_inner_TCP": confirmationCause, "same_confirmation_native_trace": confirmNative, "caller_deadline_not_cause": callerDeadlineWasNotCause, "elapsed_ns": duration.Nanoseconds(), "ordinary_error_type": fmt.Sprintf("%T", confirmErr), "native_Debug_confirm_retained_by_current_safe_reader": true, "target": confirmTarget, "candidate_id": route.ID, "policy_id": route.PolicyID})
	if !confirmationCause {
		t.Fatal("confirmation timeout has no actual native execution-confirm cause; do not infer it from caller timeout")
	}
	recovered, err = diagnosticBusinessTLS(ctx, caller, confirmTarget, trust)
	if err == nil {
		_, err = diagnosticBusinessBody(recovered, "demo-confirm-deadline", confirmBody)
		recovered.Close()
	}
	if err != nil {
		t.Fatal("removing only the owned SYN drop did not restore the same target", err)
	}
	put("stage-deadlines-summary", map[string]any{"real_underlay_drop_timeout": true, "real_execution_confirmation_timeout": true, "same_native_candidate_policy": true, "product_deadlines_unchanged": true, "ordinary_TLS_restored_without_authority_change": true})
}

func mustDiagnosticPort(t *testing.T, port string) int {
	t.Helper()
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		t.Fatal("invalid fixture port")
	}
	return n
}

// The existing receiver projection is unchanged except for a bounded test
// dialer input. Its default five-second target dial would otherwise return a
// refusal before the source's unchanged eight-second confirmation deadline.
func startDiagnosticBusinessReceiver(t *testing.T, ctx context.Context, p control.Projection, inputs, native, key string, at time.Time, evidence string) {
	t.Helper()
	view, err := control.ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	executions, err := prepareResourceExecutions(view, inputs, at)
	if err != nil {
		t.Fatal(err)
	}
	config, err := nodeRuntimeConfig(view, "demo-local-secret", nil, "mixed", executions)
	if err != nil {
		t.Fatal(err)
	}
	config, err = appendNativeWireGuard(config, view, fixtureWGReceiver(t, view, executions), nil, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(evidence, "receiver-original-projection.json"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	var experimental map[string]json.RawMessage
	var inbound, outbound []map[string]any
	if json.Unmarshal([]byte(config), &document) != nil || json.Unmarshal(document["experimental"], &experimental) != nil || json.Unmarshal(document["inbounds"], &inbound) != nil || json.Unmarshal(document["outbounds"], &outbound) != nil {
		t.Fatal("invalid real receiver projection")
	}
	delete(experimental, "clash_api")
	inbound = slices.DeleteFunc(inbound, func(v map[string]any) bool { return v["tag"] == control.LinkProbeInbound })
	changed := 0
	for _, v := range outbound {
		if v["tag"] == control.InternetEgressOutboundTag && v["type"] == "direct" {
			if v["connect_timeout"] != nil {
				t.Fatal("unexpected preexisting timeout input")
			}
			v["connect_timeout"] = "12s"
			changed++
		}
	}
	if changed != 1 {
		t.Fatal("one exact final egress dialer input required")
	}
	document["experimental"], _ = json.Marshal(experimental)
	document["inbounds"], _ = json.Marshal(inbound)
	document["outbounds"], _ = json.Marshal(outbound)
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err = preflightRuntimeConfig(native, string(body)); err != nil {
		t.Fatal("test-only target timeout input failed official native check", err)
	}
	path := filepath.Join(evidence, "receiver-running-config.json")
	if err = writeConfig(path, string(body)); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(evidence, "receiver-runtime.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(native, "run", "-c", path)
	command.Dir = t.TempDir()
	command.Stdout, command.Stderr = log, log
	if err = command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		if err := stopProcess(command, done); err != nil {
			t.Error("actual receiver did not stop/join", err)
		}
		log.Close()
	})
	if err = waitTransportResources(ctx, view, executions, command.Process.Pid, time.Now, done); err != nil {
		t.Fatal("actual WG receiving socket not ready", err)
	}
}

func diagnosticBusinessSYNDrop(t *testing.T, address, port, evidence string) func() {
	t.Helper()
	command := func(args ...string) []byte {
		t.Helper()
		b, e := exec.Command("tc", args...).CombinedOutput()
		if e != nil {
			t.Fatal("private exact TCP drop command failed", e)
		}
		return b
	}
	before := command("-j", "qdisc", "show", "dev", "lo")
	var original []map[string]any
	if json.Unmarshal(before, &original) != nil || len(original) != 1 || original[0]["kind"] != "noqueue" {
		t.Fatal("fresh isolated loopback qdisc required")
	}
	command("qdisc", "add", "dev", "lo", "root", "handle", "7391:", "prio", "bands", "3", "priomap", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0")
	command("qdisc", "add", "dev", "lo", "parent", "7391:2", "handle", "7392:", "netem", "loss", "100%")
	command("filter", "add", "dev", "lo", "protocol", "ip", "parent", "7391:", "prio", "1", "u32", "match", "ip", "dst", address+"/32", "match", "ip", "protocol", "6", "0xff", "match", "ip", "dport", port, "0xffff", "flowid", "7391:2")
	owned := command("-j", "qdisc", "show", "dev", "lo")
	ownedFilters := command("-j", "filter", "show", "dev", "lo", "parent", "7391:")
	if err := os.WriteFile(filepath.Join(evidence, "execution-confirm-owned-qdisc.json"), owned, 0600); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	remove := func() {
		once.Do(func() {
			actual := command("-j", "qdisc", "show", "dev", "lo")
			filters := command("-j", "filter", "show", "dev", "lo", "parent", "7391:")
			if !reflect.DeepEqual(actual, owned) || !reflect.DeepEqual(filters, ownedFilters) {
				t.Fatal("owned private qdisc/filter changed; refusing broad deletion")
			}
			stats := command("-s", "-j", "qdisc", "show", "dev", "lo")
			_ = os.WriteFile(filepath.Join(evidence, "execution-confirm-qdisc-before-remove.json"), stats, 0600)
			command("qdisc", "del", "dev", "lo", "root", "handle", "7391:")
			after := command("-j", "qdisc", "show", "dev", "lo")
			var restored []map[string]any
			if json.Unmarshal(after, &restored) != nil || !reflect.DeepEqual(original, restored) {
				t.Error("private loopback qdisc did not return to its exact baseline")
			}
			_ = os.WriteFile(filepath.Join(evidence, "execution-confirm-qdisc-after.json"), after, 0600)
		})
	}
	t.Cleanup(remove)
	return remove
}

func diagnosticBusinessTLS(ctx context.Context, dial proxy.ContextDialer, target string, trust *x509.CertPool) (*tls.Conn, error) {
	c, err := dial.DialContext(ctx, "tcp", target)
	if err != nil {
		if c != nil {
			c.Close()
		}
		return nil, err
	}
	t := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: trust, ServerName: "demo-forward.example"})
	if err = t.HandshakeContext(ctx); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

func diagnosticBusinessBody(c net.Conn, label, expected string) ([]byte, error) {
	if err := c.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(c, "GET /%s HTTP/1.1\r\nHost: demo-forward.example\r\nConnection: keep-alive\r\n\r\n", label); err != nil {
		return nil, err
	}
	r, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err == nil && (r.StatusCode != 200 || string(b) != expected) {
		err = errors.New("ordinary complete body differs")
	}
	return b, err
}

func diagnosticBusinessHTTPS(t *testing.T, address string, certificate tls.Certificate, label string) (string, string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat(label+"-complete-ordinary-body\n", 512)
	s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+label {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Serve(tls.NewListener(l, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}))
	}()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return net.JoinHostPort("demo-forward.example", port), body, func() { s.Close(); <-done }
}

type diagnosticBusinessGate struct {
	address string
	done    chan struct{}
	err     error
	proof   map[string]any
}

// Only this measurement's socket reaches this one-shot gate. Its CONNECT,
// request and response all come from the running native and real WG receiver.
// It may hold/close delivery, but never invents an Echo confirmation or error.
func newDiagnosticBusinessGate(t *testing.T, ctx context.Context, evidence, label, mode string) *diagnosticBusinessGate {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &diagnosticBusinessGate{address: l.Addr().String(), done: make(chan struct{})}
	go func() {
		defer close(g.done)
		defer l.Close()
		g.err = func() error {
			c, err := l.Accept()
			if err != nil {
				return err
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			request, err := http.ReadRequest(bufio.NewReader(c))
			if err != nil {
				return err
			}
			if request.Method != "CONNECT" || request.URL.Path != "/loom/probe" {
				return errors.New("gate received another API operation")
			}
			up, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:61800")
			if err != nil {
				return err
			}
			defer up.Close()
			_ = up.SetDeadline(time.Now().Add(4 * time.Second))
			if err = request.Write(up); err != nil {
				return err
			}
			reader := bufio.NewReader(up)
			response, err := http.ReadResponse(reader, request)
			if err != nil {
				return err
			}
			if response.StatusCode != 200 {
				return fmt.Errorf("actual native CONNECT rejected: %d", response.StatusCode)
			}
			if _, err = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				return err
			}
			preface := make([]byte, len(protocol.WireGuardPreface))
			if _, err = io.ReadFull(c, preface); err != nil {
				return err
			}
			if string(preface) != protocol.WireGuardPreface {
				return errors.New("actual WG preface missing")
			}
			body, err := protocol.ReadFrame(c, 1024)
			if err != nil {
				return err
			}
			value, err := protocol.UnmarshalRequest(body, 1)
			if err != nil || value.Operation != protocol.AdmissionEcho || value.PolicyID != "demo-policy" {
				return errors.New("actual admission request differs")
			}
			if _, err = up.Write(preface); err != nil {
				return err
			}
			if err = protocol.WriteFrame(up, body); err != nil {
				return err
			}
			raw, err := protocol.ReadFrame(reader, 128)
			if err != nil {
				return err
			}
			accepted, err := protocol.UnmarshalResponse(raw, value.Nonce)
			if err != nil || accepted.Status != protocol.Accepted {
				return errors.New("actual receiver did not accept the original admission")
			}
			g.proof = map[string]any{"actual_native_CONNECT": true, "actual_WG_receiver_accepted": true, "echo_id": protocol.EchoDiagnosticID(value.Nonce), "response_sha256": fmt.Sprintf("%x", sha256.Sum256(raw)), "mode": mode, "response_fabricated": false}
			if err = atomicJSON(filepath.Join(evidence, label+"-gate.json"), g.proof); err != nil {
				return err
			}
			if mode == "pass" {
				return protocol.WriteFrame(c, raw)
			}
			if mode == "close" {
				return nil
			}
			if mode != "hold" {
				return errors.New("unknown diagnostic gate mode")
			}
			var extra [1]byte
			_, err = c.Read(extra[:])
			if !errors.Is(err, io.EOF) {
				return fmt.Errorf("held diagnostic socket did not close at its real deadline: %w", err)
			}
			g.proof["actual_deadline_peer_EOF"] = true
			return atomicJSON(filepath.Join(evidence, label+"-gate.json"), g.proof)
		}()
	}()
	t.Cleanup(func() {
		l.Close()
		select {
		case <-g.done:
		case <-time.After(6 * time.Second):
			t.Error("one-shot diagnostic gate did not join")
		}
	})
	return g
}

type diagnosticBusinessUDP struct {
	port    int
	drop    atomic.Bool
	dropped atomic.Uint64
}

func newDiagnosticBusinessUDP(t *testing.T, ctx context.Context, targetPort int) *diagnosticBusinessUDP {
	t.Helper()
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &diagnosticBusinessUDP{port: l.LocalAddr().(*net.UDPAddr).Port}
	var mu sync.Mutex
	peers := map[string]*net.UDPConn{}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		b := make([]byte, 65535)
		for {
			n, from, e := l.ReadFromUDP(b)
			if e != nil {
				return
			}
			if r.drop.Load() {
				r.dropped.Add(1)
				continue
			}
			mu.Lock()
			up := peers[from.String()]
			if up == nil {
				up, e = net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: targetPort})
				if e == nil {
					peers[from.String()] = up
					workers.Add(1)
					go func(up *net.UDPConn, peer *net.UDPAddr) {
						defer workers.Done()
						reply := make([]byte, 65535)
						for {
							n, _, e := up.ReadFromUDP(reply)
							if e != nil {
								return
							}
							if r.drop.Load() {
								r.dropped.Add(1)
								continue
							}
							_, _ = l.WriteToUDP(reply[:n], peer)
						}
					}(up, from)
				}
			}
			mu.Unlock()
			if e != nil {
				return
			}
			_, _ = up.Write(b[:n])
		}
	}()
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		for _, up := range peers {
			up.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	_ = ctx
	return r
}
