package linuxclient

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

// The ordinary supervisor consumes one signed LKG and independently persisted
// Internet/LAN preferences. Both streams stay open while each Scope changes.
// This fixture does not claim a real control LAN allocation or a phone result.
func TestOfficialLinuxNativeInternetAndLANScopesKeepConcurrentConnections(t *testing.T) {
	executable := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the reviewed native executable in a dedicated namespace")
	}
	current, err := os.Stat("/proc/self/ns/mnt")
	initial, initialErr := os.Stat("/proc/1/ns/mnt")
	if err != nil || initialErr != nil || os.SameFile(current, initial) {
		t.Fatal("Scope business acceptance requires a separate mount namespace")
	}
	// This helper proves separate user/net namespaces, only loopback and no
	// external routes before generating or binding the synthetic public IP.
	business := isolatedPublicFixtureAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	for _, address := range []string{"192.0.2.1/32", "192.0.2.80/32"} {
		if err := exec.Command("ip", "address", "add", address, "dev", "lo").Run(); err != nil {
			t.Fatal("isolated Scope fixture address could not be bound", err)
		}
	}
	nativeForwardDNS(t, business.As4())
	root := t.TempDir()
	evidence := root
	if output := flag.Lookup("test.outputdir"); output != nil && output.Value.String() != "" {
		evidence = filepath.Join(output.Value.String(), "native-scopes-evidence")
		if err := os.MkdirAll(evidence, 0700); err != nil {
			t.Fatal(err)
		}
		if info, err := os.Stat(evidence); err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			t.Fatal("Scope evidence requires an owner-only directory")
		}
	}
	p, keys, input, at := nativeProjectionFixture(t, 2*time.Minute)
	// This test isolates Scope application, not transport competition. Each
	// Policy has one legal first-hop resource; dedicated measurement tests
	// exercise normal WG/Hy2 optimization and may legitimately change revision.
	p.NetworkIntent.Resources = slices.DeleteFunc(p.NetworkIntent.Resources, func(resource control.TransportResource) bool {
		return resource.OwnerNodeID == "demo-entry" && resource.Kind == "hysteria2"
	})
	p.DeviceAuthorizations[0].PolicyIDs = []string{"demo-lan-a", "demo-lan-b", "demo-policy", "demo-policy-b"}
	p.DeviceAuthorizations[2].Responsibilities = []string{"forward", "internet_egress"}
	for i := range p.DeviceAuthorizations {
		p.DeviceAuthorizations[i].DNSServers = []string{"127.0.0.1"}
	}
	virtual, err := control.AllocateLocalNetworkPrefix(p.NetworkID, "demo-lan", 0, "192.0.2.0/24", nil)
	if err != nil {
		t.Fatal(err)
	}
	lanHost := virtual.Addr().As4()
	lanHost[3] = 80
	lanTarget := netip.AddrFrom4(lanHost).String()
	p.NetworkIntent.Services = append([]control.Service{{ID: "demo-lan", Name: "Demo LAN", Kind: "local_network", RestrictToProbeTargets: new(false), LocalNetwork: &control.LocalNetwork{GatewayNodeID: "demo-exit", LocalPrefix: "192.0.2.0/24", VirtualPrefix: virtual.String(), Enabled: true}}}, p.NetworkIntent.Services...)
	lanPolicy := control.NetworkPolicy{ID: "demo-lan-a", Name: "Demo LAN A", ServiceID: "demo-lan", Action: "allow", EntryScope: control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-entry"}}, RelayScope: control.PolicyScope{Mode: "any", NodeIDs: []string{}}, MaxHops: 2}
	lanB := lanPolicy
	lanB.ID, lanB.Name = "demo-lan-b", "Demo LAN B"
	lanB.EntryScope = control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-exit"}}
	internetB := p.NetworkIntent.Policies[0]
	internetB.ID, internetB.Name = "demo-policy-b", "Demo Internet B"
	internetB.EntryScope = control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-exit"}}
	p.NetworkIntent.Policies = append([]control.NetworkPolicy{lanPolicy, lanB}, append(p.NetworkIntent.Policies, internetB)...)
	p.NetworkIntent.DNSRecords = []control.DNSRecord{{ID: "demo-lan-record", Name: "demo-lan.loom", Addresses: []string{lanTarget}, ServiceID: "demo-lan"}}
	var inputs ResourceInputs
	if err := readStrict(input, 1<<20, &inputs); err != nil {
		t.Fatal(err)
	}
	inputs.Listeners = slices.DeleteFunc(inputs.Listeners, func(listener ResourceListenerInput) bool {
		return !slices.ContainsFunc(p.NetworkIntent.Resources, func(resource control.TransportResource) bool { return resource.ID == listener.ResourceID })
	})
	reserved := []net.PacketConn{}
	for i := range p.NetworkIntent.Resources {
		resource := &p.NetworkIntent.Resources[i]
		if resource.ID == "demo-exit-wg" {
			resource.AccessEnabled = true
		}
		listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		reserved = append(reserved, listener)
		resource.DialHost, resource.DialPort = "127.0.0.1", listener.LocalAddr().(*net.UDPAddr).Port
		for j := range inputs.Listeners {
			if inputs.Listeners[j].ResourceID != resource.ID {
				continue
			}
			if resource.Kind == "wireguard" {
				inputs.Listeners[j].ListenPort = resource.DialPort
			} else {
				inputs.Listeners[j].Listen = net.JoinHostPort(resource.DialHost, strconv.Itoa(resource.DialPort))
			}
		}
	}
	for _, listener := range reserved {
		listener.Close()
	}
	if err := atomicJSON(input, inputs); err != nil {
		t.Fatal(err)
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "sender.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(private.Bytes())), 0600); err != nil {
		t.Fatal(err)
	}
	store, identityPath, makeView := linuxAcceptanceProjectionFixture(t, func(projection *control.Projection) {
		source := projection.DeviceAuthorizations[0]
		source.PolicyIDs = p.DeviceAuthorizations[0].PolicyIDs
		source.WireGuardPublicKey = base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
		source.DNSServers = []string{"127.0.0.1"}
		projection.DeviceAuthorizations = append([]control.DeviceAuthorization{source}, p.DeviceAuthorizations[1:]...)
		projection.NetworkIntent = p.NetworkIntent
		p.Config, p.EndpointGenerations, p.DeviceAuthorizations = projection.Config, projection.EndpointGenerations, projection.DeviceAuthorizations
	})
	lkg := makeView(7, true)
	for _, policy := range p.DeviceAuthorizations[0].PolicyIDs {
		execution, err := control.ProjectDeviceCandidates(lkg.View, []string{policy})
		if err != nil || len(execution.Routes) != 1 {
			t.Fatal("Scope isolation requires one legal first-hop resource per Policy", policy, err)
		}
	}
	if err := store.SaveLKG(lkg); err != nil {
		t.Fatal(err)
	}
	// Each formal preference operation selects one Policy. Multiple choices
	// leave both Scopes pending on first LKG, so initialize them separately.
	for _, policy := range []string{"demo-policy", "demo-lan-a"} {
		next, err := clientmodel.ChoosePolicy(store.Preference(), lkg.View, policy)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SetPreference(next); err != nil {
			t.Fatal(err)
		}
	}
	preference := store.Preference()
	for _, id := range []string{"demo-exit", "demo-entry"} {
		startNativeTCPFixtureNode(t, ctx, p, id, input, executable, keys[id], at, false)
	}
	// Keep the unavailable private management endpoint pending; the local
	// fixture signs the LKG but does not impersonate a report-accepting control.
	management, err := net.Listen("tcp", "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer management.Close()
	go func() {
		for {
			conn, err := management.Accept()
			if err != nil {
				return
			}
			go func() { <-ctx.Done(); conn.Close() }()
		}
	}()
	certificate, trust := nativeScopesTLS(t)
	body := strings.Repeat("demo-complete-ordinary-https-body\n", 2048)
	lanPayload := []byte(strings.Repeat("demo-simultaneous-lan\n", 256))
	var simultaneous atomic.Pointer[nativeScopesConcurrentRound]
	receiverArrived := func(scope string) {
		if round := simultaneous.Load(); round != nil {
			round.seen <- scope
			if round.arrived.Add(1) == 2 {
				close(round.release)
			}
			select {
			case <-round.release:
			case <-ctx.Done():
			}
		}
	}
	httpsListener, err := net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	https := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		receiverArrived("access")
		_, _ = io.WriteString(w, body)
	})}
	go https.Serve(tls.NewListener(httpsListener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}))
	defer https.Close()
	lanListener, err := net.Listen("tcp", "192.0.2.80:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lanListener.Close()
	go func() {
		for {
			conn, err := lanListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				request := make([]byte, len(lanPayload))
				for {
					if _, err := io.ReadFull(conn, request); err != nil {
						return
					}
					receiverArrived("local_network:demo-lan")
					if _, err := conn.Write(request); err != nil {
						return
					}
				}
			}()
		}
	}()
	log, err := os.OpenFile(filepath.Join(evidence, "runtime.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	reload := make(chan os.Signal, 1)
	options := Options{DeviceState: identityPath, LocalState: filepath.Join(root, "observations.json"), Status: filepath.Join(root, "status.json"), Config: filepath.Join(root, "config.json"), SingBox: executable, WireGuardPrivateKey: keyPath, Capture: "mixed", RefreshPoll: time.Hour, Reload: reload, TraceProbes: true, Log: log, Generation: func() (string, error) { return "demo-underlay", nil }}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, options) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error("Scope supervisor did not stop normally", err)
		}
	}()
	lanScope := "local_network:demo-lan"
	wait := func(label string, predicate func() bool) {
		t.Helper()
		for !predicate() {
			select {
			case <-ctx.Done():
				t.Fatal("Scope acceptance did not reach " + label)
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	wait("both independently confirmed selections", func() bool {
		status, err := ReadStatus(options.Status)
		return err == nil && status.Runtime == "running" && len(status.Selections) == 2 && slices.ContainsFunc(status.Selections, func(v SelectionStatus) bool { return v.Scope == "access" && v.PolicyID == preference.PolicyID }) && slices.ContainsFunc(status.Selections, func(v SelectionStatus) bool {
			return v.Scope == lanScope && v.PolicyID == preference.LANPolicyIDs["demo-lan"]
		})
	})
	selector, err := NewHTTPSelector(string(mustNativeForwardConfig(t, options.Config)))
	if err != nil {
		t.Fatal(err)
	}
	api, err := nativeForwardReadAPI(options.Config)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() map[string]clientmodel.Selection {
		t.Helper()
		values := map[string]clientmodel.Selection{}
		for _, scope := range []string{"access", lanScope} {
			value, err := selector.ReadSelection(ctx, scope)
			if err != nil || value.Revision == "" || value.CandidateID == "reject" {
				t.Fatal("Scope readback was not independently confirmed", scope, err)
			}
			values[scope] = value
		}
		return values
	}
	before := snapshot()
	recordSnapshots := func(stage string, expected, immediatelyBefore, after map[string]clientmodel.Selection) {
		t.Helper()
		value := struct {
			Expected map[string]clientmodel.Selection `json:"expected"`
			Before   map[string]clientmodel.Selection `json:"before"`
			After    map[string]clientmodel.Selection `json:"after"`
		}{expected, immediatelyBefore, after}
		if err := atomicJSON(filepath.Join(evidence, stage+"-snapshots.json"), value); err != nil {
			t.Fatal("Scope snapshot evidence was not preserved", err)
		}
	}
	recordSnapshots("initial", before, before, before)
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	dial := dialer.(proxy.ContextDialer)
	_, httpsPort, _ := net.SplitHostPort(httpsListener.Addr().String())
	_, lanPort, _ := net.SplitHostPort(lanListener.Addr().String())
	openInternet := func() net.Conn {
		t.Helper()
		conn, err := dial.DialContext(ctx, "tcp", net.JoinHostPort("demo-forward.example", httpsPort))
		if err != nil {
			t.Fatal("Internet ordinary TCP failed", err)
		}
		secured := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: trust, ServerName: "demo-forward.example"})
		if err := secured.HandshakeContext(ctx); err != nil {
			conn.Close()
			t.Fatal("ordinary HTTPS TLS/name verification failed", err)
		}
		t.Cleanup(func() { secured.Close() })
		return secured
	}
	openLAN := func() net.Conn {
		t.Helper()
		conn, err := dial.DialContext(ctx, "tcp", net.JoinHostPort(lanTarget, lanPort))
		if err != nil {
			t.Fatal("authorized LAN TCP failed", err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	internet, lan := openInternet(), openLAN()
	readHTTPS := func(conn net.Conn) error {
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err := io.WriteString(conn, "GET /ordinary-business HTTP/1.1\r\nHost: demo-forward.example\r\nConnection: keep-alive\r\n\r\n"); err != nil {
			return err
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
		if err != nil {
			return err
		}
		defer response.Body.Close()
		value, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != 200 || string(value) != body {
			return fmt.Errorf("ordinary HTTPS response was incomplete: %w", err)
		}
		return nil
	}
	readLAN := func(conn net.Conn) error {
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err := conn.Write(lanPayload); err != nil {
			return err
		}
		reply := make([]byte, len(lanPayload))
		if _, err := io.ReadFull(conn, reply); err != nil {
			return err
		}
		if string(reply) != string(lanPayload) {
			return fmt.Errorf("LAN reply changed")
		}
		return nil
	}
	// Both receiving applications wait for the other request before responding.
	// This proves overlap at the receivers, not merely simultaneous caller
	// scheduling. Repeat throughout both independent preference transitions.
	checkConcurrent := func() {
		t.Helper()
		round := &nativeScopesConcurrentRound{seen: make(chan string, 2), release: make(chan struct{})}
		simultaneous.Store(round)
		defer simultaneous.Store(nil)
		start, results := make(chan struct{}), make(chan error, 2)
		go func() { <-start; results <- readHTTPS(internet) }()
		go func() { <-start; results <- readLAN(lan) }()
		close(start)
		for range 2 {
			if err := <-results; err != nil {
				t.Fatal("simultaneous existing Scope business failed", err)
			}
		}
		first, second := <-round.seen, <-round.seen
		if first == second || round.arrived.Load() != 2 {
			t.Fatal("both receivers did not overlap in the same business round")
		}
	}
	checkConcurrent()
	connections := func() []nativeForwardConnection {
		t.Helper()
		values, err := api.connections(ctx)
		if err != nil {
			t.Fatal("actual connection readback failed", err)
		}
		return values
	}
	old := slices.DeleteFunc(connections(), func(value nativeForwardConnection) bool {
		return value.Metadata.DestinationPort != httpsPort && value.Metadata.DestinationPort != lanPort
	})
	if len(old) != 2 {
		t.Fatal("simultaneous business did not retain both actual trackers")
	}
	// These are scope-owned API boundary injections. The native factory and
	// Android RouteManager are not replaced or claimed to fail by this test.
	// The on-disk startup base deliberately omits lazy sender descriptions.
	// Rebuild those descriptions through the same pure renderer and fixed test
	// WG identity used by Run, preserving the running local API configuration.
	source, _, err := generationConfigs(lkg.View, api.secret, nil, "mixed", nil)
	if err != nil {
		t.Fatal("current Scope resource source could not be rendered", err)
	}
	source, err = appendNativeWireGuard(source, lkg.View, wireGuardExecution{}, nil, keyPath)
	if err != nil {
		t.Fatal("current Scope source lost the registered test WG identity", err)
	}
	config, err := clientadapter.WithRuntimeResourceDescriptions(string(mustNativeForwardConfig(t, options.Config)), source)
	if err != nil {
		t.Fatal("running Scope API could not retain its complete current descriptions", err)
	}
	if err := selector.SetResourceSource(config); err != nil {
		t.Fatal("normal Scope resource confirmation source was incomplete", err)
	}
	for _, scope := range []string{lanScope, "access"} {
		immediatelyBefore := snapshot()
		failedPreparation := newNativeScopeAPIGate(t, ctx, config, evidence, scope, "fail-resource-get")
		if ready, err := failedPreparation.selector.PrepareSelectionResources(ctx, before[scope]); ready || !errors.Is(err, clientadapter.ErrResourcesNotReady) {
			t.Fatal("a scope-owned preparation GET failure was not kept unconfirmed", scope, ready, err)
		}
		waitNativeScopeGate(t, ctx, failedPreparation.finished, "the preparation failure response")
		checkConcurrent()
		after := snapshot()
		recordSnapshots("api-prepare-failure-"+strings.ReplaceAll(scope, ":", "_"), before, immediatelyBefore, after)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("one scope-owned preparation API failure changed a confirmed selection", scope)
		}
	}
	hungPreparation := newNativeScopeAPIGate(t, ctx, config, evidence, lanScope, "hold-resource-get")
	beforeHungPreparation := snapshot()
	preparationContext, cancelPreparation := context.WithCancel(ctx)
	type preparationResult struct {
		ready bool
		err   error
	}
	preparation := make(chan preparationResult, 1)
	go func() {
		ready, err := hungPreparation.selector.PrepareSelectionResources(preparationContext, before[lanScope])
		preparation <- preparationResult{ready, err}
	}()
	waitNativeScopeGate(t, ctx, hungPreparation.entered, "the held LAN resource GET")
	checkConcurrent()
	afterHeldPreparation := snapshot()
	recordSnapshots("api-prepare-held", before, beforeHungPreparation, afterHeldPreparation)
	if !reflect.DeepEqual(before, afterHeldPreparation) {
		t.Fatal("a held LAN preparation request blocked or changed another Scope")
	}
	select {
	case result := <-preparation:
		t.Fatal("the LAN preparation unexpectedly completed while its API request was held", result.ready, result.err)
	default:
	}
	cancelPreparation()
	select {
	case result := <-preparation:
		if result.ready || !errors.Is(result.err, context.Canceled) {
			t.Fatal("owned preparation cancellation became remote network failure", result.ready, result.err)
		}
	case <-ctx.Done():
		t.Fatal("the owned LAN preparation ignored cancellation")
	}
	waitNativeScopeGate(t, ctx, hungPreparation.finished, "the cancelled resource GET")
	checkConcurrent()
	afterCancelledPreparation := snapshot()
	recordSnapshots("api-prepare-cancelled", before, afterHeldPreparation, afterCancelledPreparation)
	if !reflect.DeepEqual(before, afterCancelledPreparation) {
		t.Fatal("cancelled LAN preparation changed a confirmed selection")
	}
	if ready, err := selector.PrepareSelectionResources(ctx, before[lanScope]); !ready || err != nil {
		t.Fatal("normal LAN resource confirmation did not recover after API injection", ready, err)
	}
	matrices := []map[string]clientmodel.Selection{before}
	newConnections := [][]nativeForwardConnection{}
	for _, scope := range []string{lanScope, "access"} {
		previous := snapshot()
		var held *nativeScopeAPIGate
		if scope == lanScope {
			held = newNativeScopeAPIGate(t, ctx, config, evidence, scope, "hold-selector-put")
			waiting, cancelWait := context.WithCancel(ctx)
			late := make(chan error, 1)
			go func() {
				_, err := held.selector.ApplySelection(waiting, previous[scope], previous[scope])
				late <- err
			}()
			waitNativeScopeGate(t, ctx, held.entered, "the complete old LAN PUT")
			cancelWait()
			select {
			case err := <-late:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancelling the old PUT wait lost cancellation semantics", err)
				}
			case <-ctx.Done():
				t.Fatal("old PUT caller did not stop waiting")
			}
			checkConcurrent()
			if !reflect.DeepEqual(previous, snapshot()) {
				t.Fatal("the held old PUT reached the backend before release")
			}
		}
		if scope == lanScope {
			preference.LANPolicyIDs = map[string]string{"demo-lan": "demo-lan-b"}
		} else {
			preference.PolicyID = "demo-policy-b"
		}
		if err := store.SetPreference(preference); err != nil {
			t.Fatal(err)
		}
		reload <- syscall.SIGHUP
		wait("the changed Scope while both old flows transfer", func() bool {
			checkConcurrent()
			actual, err := selector.ReadSelection(ctx, scope)
			return err == nil && actual.Revision != previous[scope].Revision && actual.PolicyID == clientmodel.PolicyForSelector(preference, scope).PolicyID && actual.CandidateID != "reject"
		})
		after := snapshot()
		other := "access"
		if scope == "access" {
			other = lanScope
		}
		if !reflect.DeepEqual(previous[other], after[other]) {
			t.Fatal("one Scope changed the other's confirmed snapshot", scope)
		}
		// LAN releases its already accepted old request after caller cancellation
		// and a new full CAS. The gate records the actual backend response; it
		// never manufactures 409. Internet also checks its complete stale CAS.
		if held != nil {
			close(held.release)
			select {
			case status := <-held.forwarded:
				if status != http.StatusConflict {
					t.Fatal("the real native CAS accepted the cancelled caller's late old request", status)
				}
			case <-ctx.Done():
				t.Fatal("the held old PUT was not forwarded to the real CAS backend")
			}
			waitNativeScopeGate(t, ctx, held.finished, "the native late-PUT response")
		} else if _, err := selector.ApplySelection(ctx, previous[scope], previous[scope]); !errors.Is(err, clientadapter.ErrSelectionSuperseded) {
			t.Fatal("a stale Internet request was not rejected by the native CAS", err)
		}
		if !reflect.DeepEqual(after, snapshot()) {
			t.Fatal("a rejected late Scope request changed a confirmed snapshot")
		}
		current := connections()
		for _, original := range old {
			if !slices.ContainsFunc(current, func(value nativeForwardConnection) bool { return reflect.DeepEqual(original, value) }) {
				t.Fatal("Scope update replaced a legal old tracker or its pinned resource chain")
			}
		}
		// Exclude every tracker that existed before this round, including
		// earlier round connections whose close has not yet propagated.
		existingIDs := map[string]bool{}
		for _, value := range current {
			existingIDs[value.ID] = true
		}
		newInternet, newLAN := openInternet(), openLAN()
		if err := readHTTPS(newInternet); err != nil {
			t.Fatal("new Internet connection did not consume the current selection", err)
		}
		if err := readLAN(newLAN); err != nil {
			t.Fatal("new LAN connection did not consume the current selection", err)
		}
		fresh := slices.DeleteFunc(connections(), func(value nativeForwardConnection) bool {
			return existingIDs[value.ID] || value.Metadata.DestinationPort != httpsPort && value.Metadata.DestinationPort != lanPort
		})
		for _, portScope := range [][2]string{{httpsPort, "access"}, {lanPort, lanScope}} {
			choice := after[portScope[1]].Choices[after[portScope[1]].CandidateID]
			tag, err := control.ForwardSegmentTag(choice.FirstResourceID)
			if err != nil {
				t.Fatal("current Scope omitted its actual transport choice", err)
			}
			count := 0
			for _, value := range fresh {
				if value.Metadata.DestinationPort == portScope[0] {
					count++
					if !slices.Contains(value.Chains, tag) {
						t.Fatal("this round's new Scope connection did not use its confirmed resource chain", portScope[1])
					}
				}
			}
			if count != 1 {
				t.Fatal("this round did not create exactly one new connection for the Scope", portScope[1], count)
			}
		}
		newConnections = append(newConnections, fresh)
		newInternet.Close()
		newLAN.Close()
		checkConcurrent()
		matrices = append(matrices, after)
	}
	// Both choices are saved through their separate normal Policy operations
	// before one reload. The native runtime may apply their CAS writes in its
	// ordinary order; neither a shared revision nor a global transaction exists.
	beforeBoth := snapshot()
	for _, policy := range []string{"demo-policy", "demo-lan-a"} {
		next, err := clientmodel.ChoosePolicy(store.Preference(), lkg.View, policy)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SetPreference(next); err != nil {
			t.Fatal(err)
		}
	}
	preference = store.Preference()
	reload <- syscall.SIGHUP
	wait("both saved Scope changes after one reload", func() bool {
		checkConcurrent()
		for _, scope := range []string{"access", lanScope} {
			actual, err := selector.ReadSelection(ctx, scope)
			if err != nil || actual.Revision == beforeBoth[scope].Revision || actual.PolicyID != clientmodel.PolicyForSelector(preference, scope).PolicyID || actual.CandidateID == "reject" {
				return false
			}
		}
		return true
	})
	afterBoth := snapshot()
	for _, scope := range []string{"access", lanScope} {
		if afterBoth[scope].Revision == beforeBoth[scope].Revision || afterBoth[scope].PolicyID != clientmodel.PolicyForSelector(preference, scope).PolicyID {
			t.Fatal("both pending Scope changes did not retain independent confirmations", scope)
		}
	}
	checkConcurrent()
	currentConnections := connections()
	for _, original := range old {
		if !slices.ContainsFunc(currentConnections, func(value nativeForwardConnection) bool { return reflect.DeepEqual(original, value) }) {
			t.Fatal("applying both pending Scope choices replaced a legal old tracker or its resource chain")
		}
	}
	matrices = append(matrices, afterBoth)
	if !reflect.DeepEqual(store.LKG(), &lkg) {
		t.Fatal("Scope preference changes modified authenticated authorization")
	}
	if err := atomicJSON(filepath.Join(evidence, "scope-matrix.json"), matrices); err != nil {
		t.Fatal(err)
	}
	if err := atomicJSON(filepath.Join(evidence, "old-connections.json"), old); err != nil {
		t.Fatal(err)
	}
	if err := atomicJSON(filepath.Join(evidence, "new-connections.json"), newConnections); err != nil {
		t.Fatal(err)
	}
	if err := atomicJSON(filepath.Join(evidence, "final-connections.json"), connections()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evidence, "ordinary-https-body.txt"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

type nativeScopesConcurrentRound struct {
	seen    chan string
	release chan struct{}
	arrived atomic.Int32
}

func nativeScopesTLS(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"demo-forward.example"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(5 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	trust := x509.NewCertPool()
	trust.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: leaf}, trust
}
