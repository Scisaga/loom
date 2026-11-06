package linuxclient

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

// The normal composed access/forward entry starts at its own Link. Its one
// access candidate stays fixed while the forward selector compares two actual
// resources belonging to the same next hop. Only relay packet delay changes;
// neither the test nor its control authority supplies samples or selector writes.
func TestOfficialLinuxNativeForwardMeasuredRTTReversalKeepsExistingTCP(t *testing.T) {
	executable := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the reviewed native executable in a dedicated namespace")
	}
	cli := os.Getenv("LOOM_MEMBER_CLI")
	if cli == "" {
		t.Fatal("explicit native acceptance also requires the freshly built official CLI")
	}
	current, err := os.Stat("/proc/self/ns/mnt")
	initial, initialErr := os.Stat("/proc/1/ns/mnt")
	if err != nil || initialErr != nil || os.SameFile(current, initial) {
		t.Fatal("forward measurement requires a separate mount namespace")
	}
	business := isolatedPublicFixtureAddress(t)
	// Preserve the real active/idle cadence, two fresh confirmation pairs and
	// minimum switch interval. The bound includes one idle discovery, four
	// active rounds and four normal round deadlines; waits observe results.
	timing := clientadapter.DefaultMeasurementTiming
	// The additional control restart has a ten-second stop, ten-second start
	// and the next normal fifteen-second report tick, plus five seconds work.
	limit := timing.IdlePeriod + 4*timing.ActivePeriod + 4*timing.RoundTimeout + 40*time.Second
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	root := t.TempDir()
	evidence := root
	// The opt-in runner supplies its private output directory. Final readbacks
	// must survive t.TempDir cleanup, which can beat a filesystem observer.
	if output := flag.Lookup("test.outputdir"); output != nil && output.Value.String() != "" {
		evidence = filepath.Join(output.Value.String(), "native-forward-evidence")
		if err := os.MkdirAll(evidence, 0700); err != nil {
			t.Fatal("could not create private forward evidence")
		}
		if info, err := os.Stat(evidence); err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			t.Fatal("forward evidence requires an owner-only output directory")
		}
	}
	nativeForwardDNS(t, business.As4())
	p, keys, input, at := nativeProjectionFixture(t, limit+time.Minute)
	var inputs ResourceInputs
	if err := readStrict(input, 1<<20, &inputs); err != nil {
		t.Fatal(err)
	}
	for _, resource := range p.NetworkIntent.Resources {
		if resource.Kind != "hysteria2" {
			continue
		}
		for _, listener := range inputs.Listeners {
			if listener.ResourceID == resource.ID {
				resource.ID, resource.OwnerNodeID, resource.ListenerID = "demo-exit-hy2", "demo-exit", "demo-exit-hy2"
				resource.LinkOnly = true
				listener.ResourceID = resource.ID
				p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, resource)
				inputs.Listeners = append(inputs.Listeners, listener)
				break
			}
		}
		break
	}
	p.NetworkIntent.Resources = slices.DeleteFunc(p.NetworkIntent.Resources, func(resource control.TransportResource) bool { return resource.OwnerNodeID != "demo-exit" })
	inputs.Listeners = slices.DeleteFunc(inputs.Listeners, func(listener ResourceListenerInput) bool {
		return !slices.ContainsFunc(p.NetworkIntent.Resources, func(resource control.TransportResource) bool { return resource.ID == listener.ResourceID })
	})
	if len(p.NetworkIntent.Resources) != 2 || len(inputs.Listeners) != 2 {
		t.Fatal("same next hop requires exactly one WG and one Hy2 resource")
	}
	delays := map[string]*atomic.Int64{}
	tags := map[string]string{}
	usedPorts := map[int]bool{}
	reserved := []net.PacketConn{}
	t.Cleanup(func() {
		for _, socket := range reserved {
			socket.Close()
		}
	})
	for i := range p.NetworkIntent.Resources {
		resource := &p.NetworkIntent.Resources[i]
		actual := 0
		for actual == 0 {
			port, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			candidate := port.LocalAddr().(*net.UDPAddr).Port
			if !usedPorts[candidate] {
				actual, usedPorts[candidate] = candidate, true
				reserved = append(reserved, port)
			} else {
				port.Close()
			}
		}
		for j := range inputs.Listeners {
			if inputs.Listeners[j].ResourceID != resource.ID {
				continue
			}
			if resource.Kind == "wireguard" {
				inputs.Listeners[j].ListenPort = actual
			} else {
				inputs.Listeners[j].Listen = net.JoinHostPort("127.0.0.1", strconv.Itoa(actual))
			}
		}
		delay := new(atomic.Int64)
		delay.Store(int64(time.Millisecond))
		if resource.Kind == "wireguard" {
			delay.Store(int64(20 * time.Millisecond))
		}
		delays[resource.Kind] = delay
		resource.DialHost = "127.0.0.1"
		resource.DialPort = nativeForwardUDPRelay(t, ctx, actual, delay)
		tags[resource.Kind], err = control.ForwardSegmentTag(resource.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	// Reserve every Q until every public P is bound: a later P must not
	// occupy an earlier receiver's socket before the real receiver starts.
	for _, socket := range reserved {
		socket.Close()
	}
	sort.Slice(p.NetworkIntent.Resources, func(i, j int) bool { return p.NetworkIntent.Resources[i].ID < p.NetworkIntent.Resources[j].ID })
	sort.Slice(inputs.Listeners, func(i, j int) bool { return inputs.Listeners[i].ResourceID < inputs.Listeners[j].ResourceID })
	if err := atomicJSON(input, inputs); err != nil {
		t.Fatal(err)
	}
	p.NetworkIntent.Policies[0].EntryScope = control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-device"}}
	p.NetworkIntent.DNSRecords = []control.DNSRecord{}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "sender.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(private.Bytes())), 0600); err != nil {
		t.Fatal(err)
	}
	var exitWGPublic string
	for _, resource := range p.NetworkIntent.Resources {
		if resource.Kind == "wireguard" {
			exitWGPublic = *resource.Authentication.PublicKey
		}
	}
	authority, store, identityPath := startNativeForwardControl(t, ctx, cli, evidence, p.NetworkIntent, base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), exitWGPublic)
	lkg := *store.LKG()
	initialIdentity, err := store.IdentityReadback()
	if err != nil {
		t.Fatal("could not inspect the admitted public identity", err)
	}
	if store.Preference().PolicyID != "demo-policy" {
		t.Fatal("first authenticated LKG did not initialize its unique Internet Policy")
	}
	// Read the receiver's exact persisted authorization only while its owner is
	// stopped. Once business starts, all control evidence uses the admin socket.
	authority.stop(t)
	actualAuthority, err := control.OpenAuthority(authority.root)
	if err != nil {
		t.Fatal(err)
	}
	p = actualAuthority.Snapshot()
	authority.start(t)
	execution, err := control.ProjectDeviceCandidates(lkg.View, []string{"demo-policy"})
	if err != nil || len(execution.Routes) != 1 || execution.Routes[0].EntryNodeID != "demo-device" || execution.Routes[0].FirstResourceID != "" || execution.Routes[0].FinalExit != "demo-exit" {
		t.Fatal("composed entry did not retain exactly one local forward candidate", err)
	}
	links := map[string]control.NetworkLink{}
	for _, link := range execution.Links {
		if link.FromNodeID == "demo-device" {
			if link.ToNodeID != "demo-exit" || !slices.ContainsFunc(execution.Resources, func(resource control.TransportResource) bool { return resource.ID == link.ResourceID }) {
				t.Fatal("forward resource escaped the same next hop")
			}
			links[link.ID] = link
		}
	}
	if len(links) != 2 {
		t.Fatal("expected two distinct actual outgoing Link references")
	}
	specs, err := control.LinkSpecifications(lkg.View)
	if err != nil {
		t.Fatal(err)
	}
	seenResources, seenSpecs := map[string]bool{}, map[string]bool{}
	for id, link := range links {
		if link.ResourceID == "" || specs[id] == "" || seenResources[link.ResourceID] || seenSpecs[specs[id]] {
			t.Fatal("the two outgoing Links did not retain distinct resource specifications")
		}
		seenResources[link.ResourceID], seenSpecs[specs[id]] = true, true
	}
	startNativeTCPFixtureNode(t, ctx, p, "demo-exit", input, executable, keys["demo-exit"], at, false)
	echo, err := net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			connection, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer connection.Close(); _, _ = io.Copy(connection, connection) }()
		}
	}()
	log, err := os.OpenFile(filepath.Join(root, "runtime.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	options := Options{DeviceState: identityPath, LocalState: filepath.Join(root, "observations.json"), Status: filepath.Join(root, "status.json"), Config: filepath.Join(root, "config.json"), SingBox: executable, WireGuardPrivateKey: keyPath, Capture: "mixed", Log: log}
	run := exec.CommandContext(ctx, cli, "client", "run", "-state", identityPath, "-capture", "mixed", "-sing-box", executable, "-wireguard-private-key", keyPath, "-runtime-config", options.Config, "-runtime-state", options.LocalState, "-status", options.Status)
	run.Stdout, run.Stderr = log, log
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- run.Wait() }()
	defer func() {
		_ = run.Process.Signal(os.Interrupt)
		select {
		case err := <-done:
			if err != nil {
				t.Error("normal forward supervisor did not clean up", err)
			}
		case <-time.After(10 * time.Second):
			cancel()
			<-done
			t.Error("normal forward supervisor did not stop")
		}
	}()
	var generation string
	var currentControl control.WebSnapshot
	var currentEvidence *control.DeviceEvidence
	samples := func() []control.Observation {
		snapshot, err := authority.snapshot(ctx)
		if err != nil {
			return nil
		}
		for _, device := range snapshot.Devices {
			value := device.Evidence
			if device.ID != "demo-device" || value == nil || value.Freshness != "current" || value.ViewDigest != lkg.ViewDigest || value.Runtime == nil || value.Runtime.State != "running" || value.Runtime.AppliedViewDigest != lkg.ViewDigest {
				continue
			}
			if generation == "" {
				generation = value.NetworkGeneration
			}
			if value.NetworkGeneration != generation || generation == "" {
				t.Fatal("normal report changed the source network generation")
			}
			currentControl, currentEvidence = snapshot, value
			result := []control.Observation{}
			for _, sample := range value.Measurements {
				if sample.Level == "link" {
					result = append(result, sample.Observation)
				}
			}
			return result
		}
		return nil
	}
	var api nativeForwardAPI
	var before nativeForwardSnapshot
	wait := func(stage string, check func() bool) {
		t.Helper()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for !check() {
			select {
			case <-ctx.Done():
				t.Fatal("normal forward runtime did not reach " + stage)
			case <-ticker.C:
			}
		}
	}
	wait("actual initial measured forwarding selection", func() bool {
		if api.secret == "" {
			api, _ = nativeForwardReadAPI(options.Config)
		}
		before, err = api.snapshot(ctx)
		values := samples()
		return err == nil && nativeForwardSamplePair(t, values, links, specs, generation, 0, "hysteria2", execution.Resources) && before.first() == tags["hysteria2"]
	})
	status, err := ReadStatus(options.Status)
	if err != nil || status.Runtime != "running" || status.NetworkGeneration != generation || len(status.Selections) != 1 || status.Selections[0].CandidateID != execution.Routes[0].ID {
		t.Fatal("actual access readback did not retain its sole local candidate")
	}
	access, err := NewHTTPSelector(string(mustNativeForwardConfig(t, options.Config)))
	if err != nil {
		t.Fatal(err)
	}
	accessBefore, err := access.ReadSelection(ctx, "access")
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	target := net.JoinHostPort("demo-forward.example", port)
	connect := func() (net.Conn, *bufio.Reader) {
		t.Helper()
		pending, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		connection, err := dialer.(proxy.ContextDialer).DialContext(pending, "tcp", target)
		if err != nil {
			t.Fatal("ordinary forward business connection failed", err)
		}
		return connection, bufio.NewReader(connection)
	}
	checkStream := func(connection net.Conn, reader *bufio.Reader) {
		t.Helper()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.WriteString(connection, "demo-forward-business\n"); err != nil {
			t.Fatal("ordinary existing forward stream failed", err)
		}
		if body, err := reader.ReadString('\n'); err != nil || body != "demo-forward-business\n" {
			t.Fatal("ordinary forward stream did not return its application bytes", err)
		}
	}
	old, oldReader := connect()
	defer old.Close()
	checkStream(old, oldReader)
	oldID := ""
	wait("old stream pinned to the measured Hy2 resource", func() bool {
		connections, err := api.connections(ctx)
		if err != nil {
			return false
		}
		for _, connection := range connections {
			if connection.Metadata.Host == "demo-forward.example" && connection.Metadata.DestinationPort == port && slices.Contains(connection.Chains, "forward:demo-policy") && slices.Contains(connection.Chains, tags["hysteria2"]) {
				oldID = connection.ID
				return true
			}
		}
		return false
	})
	if err := writeNativeForwardEvidence(filepath.Join(evidence, "forward-before.json"), map[string]any{"forward": before, "samples": samples(), "old_id": oldID, "access": accessBefore, "control": currentControl}); err != nil {
		t.Fatal(err)
	}
	flipped := time.Now().UnixMilli()
	delays["wireguard"].Store(int64(time.Millisecond))
	delays["hysteria2"].Store(int64(20 * time.Millisecond))
	lastKeep := time.Now()
	var after nativeForwardSnapshot
	wait("fresh measured RTT reversal and forward CAS readback", func() bool {
		if time.Since(lastKeep) >= time.Second {
			checkStream(old, oldReader)
			lastKeep = time.Now()
		}
		after, err = api.snapshot(ctx)
		values := samples()
		return err == nil && after.Revision != before.Revision && after.first() == tags["wireguard"] && nativeForwardSamplePair(t, values, links, specs, generation, flipped, "wireguard", execution.Resources)
	})
	checkStream(old, oldReader)
	next, nextReader := connect()
	defer next.Close()
	checkStream(next, nextReader)
	var finalConnections []nativeForwardConnection
	wait("new WG stream and unchanged old Hy2 tracker", func() bool {
		finalConnections, err = api.connections(ctx)
		if err != nil {
			return false
		}
		oldPinned, nextPinned := false, false
		for _, connection := range finalConnections {
			if connection.Metadata.Host != "demo-forward.example" || connection.Metadata.DestinationPort != port || !slices.Contains(connection.Chains, "forward:demo-policy") {
				continue
			}
			oldPinned = oldPinned || connection.ID == oldID && slices.Contains(connection.Chains, tags["hysteria2"]) && !slices.Contains(connection.Chains, tags["wireguard"])
			nextPinned = nextPinned || connection.ID != oldID && slices.Contains(connection.Chains, tags["wireguard"]) && !slices.Contains(connection.Chains, tags["hysteria2"])
		}
		return oldPinned && nextPinned
	})
	checkStream(old, oldReader)
	accessAfter, err := access.ReadSelection(ctx, "access")
	if err != nil || accessAfter.CandidateID != accessBefore.CandidateID || accessAfter.PolicyID != accessBefore.PolicyID || !reflect.DeepEqual(accessAfter.Targets, accessBefore.Targets) || store.LKG().ViewDigest != lkg.ViewDigest {
		t.Fatal("resource RTT reversal changed authorization or the sole access decision", err)
	}
	if err := writeNativeForwardEvidence(filepath.Join(evidence, "forward-after.json"), map[string]any{"forward": after, "samples": samples(), "flipped_at": flipped, "connections": finalConnections, "access": accessAfter, "control": currentControl}); err != nil {
		t.Fatal(err)
	}
	var beforeRestartSamples []control.Observation
	wait("complete current control samples before owner stop", func() bool {
		beforeRestartSamples = samples()
		return len(beforeRestartSamples) == len(links) && nativeForwardSamplePair(t, beforeRestartSamples, links, specs, generation, flipped, "wireguard", execution.Resources)
	})
	beforeRestart := *currentEvidence
	for id, link := range links {
		var history control.WebLinkHistory
		err := authority.get(ctx, "/api/control/ui/link-history?link="+url.QueryEscape(id), &history)
		if writeErr := writeNativeForwardEvidence(filepath.Join(evidence, "control-link-before-"+id+".json"), map[string]any{"history": history, "optional_round_trips_present": history.RoundTrips != nil}); writeErr != nil {
			t.Fatal(writeErr)
		}
		if err != nil || history.Schema != 3 || history.LinkID != id || history.FromNodeID != link.FromNodeID || history.ToNodeID != link.ToNodeID || history.ResourceID != link.ResourceID || history.SpecDigest != specs[id] {
			t.Fatal("formal Link history lost actual independent measurement references", err)
		}
		matched := false
		for _, sample := range beforeRestartSamples {
			if sample.LinkID != id {
				continue
			}
			for _, bucket := range history.Buckets {
				matched = matched || !bucket.Ambiguous && bucket.Observation != nil && reflect.DeepEqual(*bucket.Observation, sample)
			}
		}
		if !matched {
			t.Fatal("formal Link history did not preserve its current raw Observation")
		}
	}
	authority.stop(t)
	checkStream(old, oldReader)
	checkStream(next, nextReader)
	originals := authority.offlineReports(t, "control-offline-before-restart")
	var highest control.U64
	postFlip := map[string]map[int64]bool{}
	for _, report := range originals {
		if report.DeviceID == "demo-device" && report.ReportSequence > highest {
			highest = report.ReportSequence
		}
		if report.DeviceID != lkg.View.DeviceID || report.ViewDigest != lkg.ViewDigest || report.NetworkGeneration != generation {
			continue
		}
		for _, sample := range report.Observations {
			link, found := links[sample.LinkID]
			if !found || sample.ObservedAt <= flipped || sample.Result != "available" || sample.RoundTripMS == nil {
				continue
			}
			if sample.Level != "link" || sample.ResourceID != link.ResourceID || sample.SpecDigest != specs[link.ID] || sample.Action != link.ProbeTarget.Action || sample.Target != net.JoinHostPort(link.ProbeTarget.Host, strconv.Itoa(link.ProbeTarget.Port)) || sample.NetworkGeneration != generation || sample.Validate() != nil {
				t.Fatal("original post-reversal measurement lost its actual Link specification")
			}
			if postFlip[sample.ResourceID] == nil {
				postFlip[sample.ResourceID] = map[int64]bool{}
			}
			postFlip[sample.ResourceID][sample.ObservedAt] = true
		}
	}
	for _, link := range links {
		if len(postFlip[link.ResourceID]) < clientmodel.DefaultPerformanceRule.Confirmations {
			t.Fatal("control did not persist two distinct real post-reversal samples for each resource")
		}
	}
	if highest < beforeRestart.ReportSequence {
		t.Fatal("durable original report sequence fell behind formal current readback")
	}
	authority.start(t)
	checkStream(old, oldReader)
	checkStream(next, nextReader)
	var restoredSamples []control.Observation
	wait("restarted control's complete persisted samples", func() bool {
		restoredSamples = samples()
		return len(restoredSamples) == len(links) && nativeForwardSamplePair(t, restoredSamples, links, specs, generation, flipped, "wireguard", execution.Resources)
	})
	for _, original := range beforeRestartSamples {
		if !slices.ContainsFunc(restoredSamples, func(restored control.Observation) bool { return reflect.DeepEqual(restored, original) }) {
			t.Fatal("restarted control did not recover the same current sample before its next measurement")
		}
	}
	if err := writeNativeForwardEvidence(filepath.Join(evidence, "control-restored-before-next-report.json"), currentControl); err != nil {
		t.Fatal(err)
	}
	wait("restarted control current measurements and a later original report", func() bool {
		values := samples()
		return currentEvidence != nil && currentEvidence.ReportSequence > highest && nativeForwardSamplePair(t, values, links, specs, generation, flipped, "wireguard", execution.Resources)
	})
	checkStream(old, oldReader)
	checkStream(next, nextReader)
	restoredConnections, err := api.connections(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, previous := range finalConnections {
		if previous.Metadata.Host == "demo-forward.example" && previous.Metadata.DestinationPort == port && !slices.ContainsFunc(restoredConnections, func(current nativeForwardConnection) bool {
			return current.ID == previous.ID && reflect.DeepEqual(current.Chains, previous.Chains)
		}) {
			t.Fatal("control restart lost an existing connection's pinned tracker")
		}
	}
	reloaded, err := deviceclient.Load(identityPath)
	if err != nil || reloaded.LKG() == nil || !reflect.DeepEqual(*reloaded.LKG(), lkg) || !reloaded.Preference().Equal(store.Preference()) {
		t.Fatal("control restart changed the client's protected identity, LKG or choice", err)
	}
	restoredIdentity, err := reloaded.IdentityReadback()
	if err != nil || !reflect.DeepEqual(restoredIdentity, initialIdentity) {
		t.Fatal("control restart changed the public enrollment or trust identity", err)
	}
	if err := writeNativeForwardEvidence(filepath.Join(evidence, "control-after-restart.json"), map[string]any{"snapshot": currentControl, "previous_samples": beforeRestartSamples, "previous_highest_sequence": highest, "current_report_sequence": currentEvidence.ReportSequence, "connections": restoredConnections, "initial_identity": initialIdentity, "restored_identity": restoredIdentity, "complete_lkg_unchanged": true}); err != nil {
		t.Fatal(err)
	}
	authority.stop(t)
	afterOriginals := authority.offlineReports(t, "control-offline-after-restart")
	for _, original := range originals {
		body, err := control.CanonicalEncode(original)
		if err != nil || !slices.ContainsFunc(afterOriginals, func(candidate control.DeviceReport) bool {
			current, err := control.CanonicalEncode(candidate)
			return err == nil && string(current) == string(body)
		}) {
			t.Fatal("control restart changed or dropped a canonical signed report original")
		}
	}
}

func nativeForwardSamplePair(t *testing.T, samples []control.Observation, links map[string]control.NetworkLink, specs map[string]string, generation string, after int64, faster string, resources []control.TransportResource) bool {
	t.Helper()
	metrics := map[string]int64{}
	for _, sample := range samples {
		link, found := links[sample.LinkID]
		if !found || sample.ObservedAt <= after || sample.Result != "available" || sample.RoundTripMS == nil {
			continue
		}
		if sample.Level != "link" || sample.ResourceID != link.ResourceID || sample.SpecDigest != specs[link.ID] || sample.Action != link.ProbeTarget.Action || sample.Target != net.JoinHostPort(link.ProbeTarget.Host, strconv.Itoa(link.ProbeTarget.Port)) || sample.NetworkGeneration != generation || sample.Validate() != nil {
			t.Fatal("actual report sample lost its current Link/resource/specification binding")
		}
		for _, resource := range resources {
			if resource.ID == link.ResourceID {
				metrics[resource.Kind] = *sample.RoundTripMS
			}
		}
	}
	if len(metrics) != 2 {
		return false
	}
	slower := "wireguard"
	if faster == slower {
		slower = "hysteria2"
	}
	return metrics[faster]+clientmodel.DefaultPerformanceRule.MinimumImprovement.Milliseconds() < metrics[slower]
}

// UI readbacks are disposable JSON projections. Signed report originals use
// their unchanged canonical bytes in the separate offline inspection.
func writeNativeForwardEvidence(path string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return atomicJSONBytes(path, body)
}

func nativeForwardDNS(t *testing.T, address [4]byte) {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		var buffer [2048]byte
		for {
			n, peer, err := listener.ReadFrom(buffer[:])
			if err != nil {
				return
			}
			var message dnsmessage.Message
			if message.Unpack(buffer[:n]) != nil || len(message.Questions) != 1 {
				continue
			}
			question := message.Questions[0]
			message.Response, message.RecursionAvailable = true, true
			if question.Name.String() != "demo-forward.example." {
				message.RCode = dnsmessage.RCodeNameError
			} else if question.Type == dnsmessage.TypeA {
				message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: address}}}
			}
			if body, err := message.Pack(); err == nil {
				_, _ = listener.WriteTo(body, peer)
			}
		}
	}()
}

// Public dial P and receiver Q are distinct, stable namespace sockets. Every
// packet traverses the current real delay; changing delay never rebinds Q/P.
func nativeForwardUDPRelay(t *testing.T, ctx context.Context, targetPort int, delay *atomic.Int64) int {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	peers := map[string]*net.UDPConn{}
	stopped := false
	stop := make(chan struct{})
	var workers sync.WaitGroup
	pause := func() bool {
		timer := time.NewTimer(time.Duration(delay.Load()))
		defer timer.Stop()
		select {
		case <-timer.C:
			return true
		case <-ctx.Done():
		case <-stop:
		}
		return false
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		buffer := make([]byte, 65535)
		for {
			n, peer, err := listener.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			mu.Lock()
			if stopped {
				mu.Unlock()
				return
			}
			upstream := peers[peer.String()]
			if upstream == nil {
				upstream, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: targetPort})
				if err != nil {
					mu.Unlock()
					return
				}
				peers[peer.String()] = upstream
				workers.Add(1)
				go func(connection *net.UDPConn, destination *net.UDPAddr) {
					defer workers.Done()
					data := make([]byte, 65535)
					for {
						count, err := connection.Read(data)
						if err != nil || !pause() {
							return
						}
						_, _ = listener.WriteToUDP(data[:count], destination)
					}
				}(upstream, peer)
			}
			mu.Unlock()
			if !pause() {
				return
			}
			_, _ = upstream.Write(buffer[:n])
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		stopped = true
		close(stop)
		listener.Close()
		for _, connection := range peers {
			connection.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return listener.LocalAddr().(*net.UDPAddr).Port
}

type nativeForwardSnapshot struct {
	Revision string              `json:"revision"`
	Choices  map[string][]string `json:"exit_choices"`
}

func (value nativeForwardSnapshot) first() string {
	if len(value.Choices["demo-exit"]) == 0 {
		return ""
	}
	return value.Choices["demo-exit"][0]
}

type nativeForwardConnection struct {
	ID       string   `json:"id"`
	Chains   []string `json:"chains"`
	Metadata struct {
		Host            string `json:"host"`
		DestinationPort string `json:"destinationPort"`
	} `json:"metadata"`
}

type nativeForwardAPI struct{ address, secret string }

func mustNativeForwardConfig(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("could not consume the test-owned runtime configuration")
	}
	return body
}

func nativeForwardReadAPI(path string) (nativeForwardAPI, error) {
	var document struct {
		Experimental struct {
			API struct {
				Address string `json:"external_controller"`
				Secret  string `json:"secret"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	body, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(body, &document)
	}
	return nativeForwardAPI{document.Experimental.API.Address, document.Experimental.API.Secret}, err
}

func (api nativeForwardAPI) get(ctx context.Context, path string, value any) error {
	if api.address != "127.0.0.1:61800" || api.secret == "" {
		return fmt.Errorf("test-owned native API is not ready")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+api.address+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+api.secret)
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("test-owned native readback was rejected")
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(value)
}

func (api nativeForwardAPI) snapshot(ctx context.Context) (nativeForwardSnapshot, error) {
	var value nativeForwardSnapshot
	err := api.get(ctx, "/proxies/"+url.PathEscape("forward:demo-policy"), &value)
	if err == nil && (value.Revision == "" || len(value.Choices) != 1) {
		err = fmt.Errorf("forward readback omitted its fixed exit or revision")
	}
	return value, err
}

func (api nativeForwardAPI) connections(ctx context.Context) ([]nativeForwardConnection, error) {
	var value struct {
		Connections []nativeForwardConnection `json:"connections"`
	}
	err := api.get(ctx, "/connections", &value)
	return value.Connections, err
}
