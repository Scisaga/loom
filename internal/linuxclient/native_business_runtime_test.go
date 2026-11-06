package linuxclient

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
)

// Run/Store owns the actual selection. There are no Service probe URLs and no
// test-side selector writes. An ordinary failed request must teach the current
// nonfixed Policy to choose its other exit, retaining an unrelated old TCP.
func TestOfficialLinuxNativeBusinessFailureChangesOnlyNewTargetConnections(t *testing.T) {
	nativeBusinessRecoveryFixture(t, false, "hysteria2")
}

// Recovery must come from a real, budgeted native trial. The test never sends
// an A success into the reducer or changes the running selector to probe it.
func TestOfficialLinuxNativeBusinessBackgroundRecoveryKeepsExistingTCP(t *testing.T) {
	nativeBusinessRecoveryFixture(t, true, "hysteria2")
}

func TestOfficialLinuxNativeWGBackgroundRecoveryKeepsExistingTCP(t *testing.T) {
	nativeBusinessRecoveryFixture(t, true, "wireguard")
}

func nativeBusinessRecoveryFixture(t *testing.T, recovery bool, entryKind string) {
	executable := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the reviewed native executable in a dedicated namespace")
	}
	business, unavailable := isolatedPublicFixtureAddress(t), isolatedPublicFixtureAddress(t)
	limit := 35 * time.Second
	if recovery {
		limit = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	if err := exec.Command("ip", "address", "add", "192.0.2.53/32", "dev", "lo").Run(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("ip", "address", "add", "192.0.2.1/32", "dev", "lo").Run(); err != nil {
		t.Fatal(err)
	}
	// Keep the private management handshake pending. Its startup failure
	// notice must not trigger an extra full update that could masquerade as
	// the independent local feedback worker this test is meant to exercise.
	management, err := net.Listen("tcp", "192.0.2.1:443")
	if err != nil {
		t.Fatal("isolated management listener failed")
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
	resolver := func(address string, target netip.Addr) {
		t.Helper()
		socket, err := net.ListenPacket("udp", net.JoinHostPort(address, "53"))
		if err != nil {
			t.Fatal("isolated resolver could not listen")
		}
		t.Cleanup(func() { socket.Close() })
		go func() {
			var buffer [2048]byte
			for {
				n, peer, err := socket.ReadFrom(buffer[:])
				if err != nil {
					return
				}
				var query dnsmessage.Message
				if query.Unpack(buffer[:n]) != nil || len(query.Questions) != 1 {
					continue
				}
				question := query.Questions[0]
				query.Response, query.RecursionAvailable = true, true
				answer := target
				if question.Name.String() == "demo-keep.example." {
					answer = business
				} else if question.Name.String() != "demo-target.example." {
					query.RCode = dnsmessage.RCodeNameError
				}
				if query.RCode == dnsmessage.RCodeSuccess && question.Type == dnsmessage.TypeA {
					query.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: answer.As4()}}}
				}
				if body, err := query.Pack(); err == nil {
					_, _ = socket.WriteTo(body, peer)
				}
			}
		}()
	}
	resolver("127.0.0.1", business)
	resolver("192.0.2.53", unavailable)
	lifetime := time.Minute
	if recovery {
		lifetime = 5 * time.Minute
	}
	p, keys, input, at := nativeProjectionFixture(t, lifetime)
	p.DeviceAuthorizations[1].Responsibilities = []string{"forward", "internet_egress"}
	for i := range p.DeviceAuthorizations {
		p.DeviceAuthorizations[i].DNSServers = []string{"127.0.0.1"}
	}
	p.DeviceAuthorizations[1].DNSServers = []string{"192.0.2.53"}
	p.NetworkIntent.Resources = slices.DeleteFunc(p.NetworkIntent.Resources, func(resource control.TransportResource) bool {
		return resource.OwnerNodeID == "demo-entry" && resource.Kind != entryKind
	})
	if recovery {
		p.NetworkIntent.Policies[0].EntryScope = control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-entry", "demo-exit"}}
	}
	p.NetworkIntent.Policies[0].ExitScope = &control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-entry", "demo-exit"}}
	var inputs ResourceInputs
	if err := readStrict(input, 1<<20, &inputs); err != nil {
		t.Fatal(err)
	}
	used := map[int]bool{}
	for i := range p.NetworkIntent.Resources {
		resource := &p.NetworkIntent.Resources[i]
		for {
			socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal("isolated transport port allocation failed")
			}
			port := socket.LocalAddr().(*net.UDPAddr).Port
			socket.Close()
			if used[port] {
				continue
			}
			used[port] = true
			resource.DialHost, resource.DialPort = "127.0.0.1", port
			break
		}
		for j := range inputs.Listeners {
			if inputs.Listeners[j].ResourceID == resource.ID {
				if resource.Kind == "wireguard" {
					inputs.Listeners[j].ListenPort = resource.DialPort
				} else {
					inputs.Listeners[j].Listen = net.JoinHostPort(resource.DialHost, strconv.Itoa(resource.DialPort))
				}
			}
		}
	}
	if recovery {
		for i := range p.NetworkIntent.Resources {
			resource := &p.NetworkIntent.Resources[i]
			if resource.OwnerNodeID == "demo-exit" && resource.Kind == "wireguard" {
				resource.AccessEnabled = true
				// Public P and local Q remain independent; the owned namespace
				// proxy adds real delay instead of injecting an RTT observation.
				resource.DialPort = delayedNativeUDPFixture(t, ctx, resource.DialPort, 12*time.Millisecond)
			}
		}
	}
	if err := atomicJSON(input, inputs); err != nil {
		t.Fatal(err)
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registered := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	keyPath := filepath.Join(t.TempDir(), "sender.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(private.Bytes())), 0600); err != nil {
		t.Fatal(err)
	}
	store, identityPath, makeView := linuxAcceptanceProjectionFixture(t, func(projection *control.Projection) {
		source := projection.DeviceAuthorizations[0]
		source.WireGuardPublicKey = registered
		source.DNSServers = []string{"127.0.0.1"}
		projection.DeviceAuthorizations = append([]control.DeviceAuthorization{source}, p.DeviceAuthorizations[1:]...)
		projection.NetworkIntent = p.NetworkIntent
		p.Config, p.EndpointGenerations, p.DeviceAuthorizations = projection.Config, projection.EndpointGenerations, projection.DeviceAuthorizations
	})
	lkg := makeView(7, true)
	if err := store.SaveLKG(lkg); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPreference(clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"demo-exit", "demo-entry"} {
		startNativeTCPFixtureNode(t, ctx, p, id, input, executable, keys[id], at, false)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal("isolated HTTP target failed")
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "demo-ordinary-business") })}
	go server.Serve(listener)
	defer server.Close()
	echo, err := net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal("isolated persistent target failed")
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	root := t.TempDir()
	log, err := os.OpenFile(filepath.Join(root, "runtime.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	options := Options{DeviceState: identityPath, LocalState: filepath.Join(root, "observations.json"), Status: filepath.Join(root, "status.json"), Config: filepath.Join(root, "config.json"), SingBox: executable, WireGuardPrivateKey: keyPath, Capture: "mixed", RefreshPoll: time.Hour, Log: log, Generation: func() (string, error) { return "demo-underlay", nil }}
	if recovery {
		options.RefreshPoll = time.Second
	}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, options) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error("normal supervisor did not clean up")
		}
	}()
	wait := func(predicate func(Status) bool) Status {
		t.Helper()
		for {
			status, err := ReadStatus(options.Status)
			if err == nil && status.Runtime == "running" && predicate(status) {
				return status
			}
			select {
			case <-ctx.Done():
				t.Fatal("normal runtime did not reach the required business selection")
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	initial := wait(func(status Status) bool {
		return len(status.Selections) == 1 && status.Selections[0].FinalExit == "demo-entry"
	})
	// The initial full measurement update saves its ordinary probe cache only
	// after the final activation. Issue the fault after that observable point,
	// so another startup completion cannot stand in for the local-only worker.
	for {
		var cached observationCache
		if readStrict(options.LocalState, 1<<20, &cached) == nil && len(cached.ResourceObservations) > 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("initial probe results were not durably cached")
		case <-time.After(20 * time.Millisecond):
		}
	}
	configuration, err := os.ReadFile(options.Config)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := NewHTTPSelector(string(configuration))
	if err != nil {
		t.Fatal(err)
	}
	before, err := selector.ReadSelection(ctx, "access")
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	name := func(host string, address net.Addr) string {
		_, port, err := net.SplitHostPort(address.String())
		if err != nil {
			t.Fatal("invalid fixture listener")
		}
		return net.JoinHostPort(host, port)
	}
	keep, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", name("demo-keep.example", echo.Addr()))
	if err != nil {
		t.Fatal("initial unrelated connection failed")
	}
	defer keep.Close()
	reader := bufio.NewReader(keep)
	checkKeep := func() {
		t.Helper()
		_ = keep.SetDeadline(time.Now().Add(2 * time.Second))
		_, err := io.WriteString(keep, "demo-keep\n")
		if err != nil {
			t.Fatal("existing TCP was interrupted")
		}
		body, err := reader.ReadString('\n')
		if err != nil || body != "demo-keep\n" {
			t.Fatal("existing TCP lost its original path")
		}
	}
	checkKeep()
	transport := &http.Transport{DialContext: dialer.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	target := name("demo-target.example", listener.Addr())
	response, err := client.Get("http://" + target + "/ordinary-application")
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("the intentionally failing exit served a target it could not resolve correctly")
	}
	key := "tcp://" + target
	updated := wait(func(status Status) bool {
		for _, selection := range status.Selections {
			if selection.Targets[key] != "" && selection.Targets[key] != initial.Selections[0].CandidateID {
				return true
			}
		}
		return false
	})
	checkKeep()
	response, err = client.Get("http://" + target + "/ordinary-application")
	if err != nil {
		t.Fatal("ordinary request did not use the learned alternative")
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != "demo-ordinary-business" {
		t.Fatal("the alternative did not carry actual HTTP")
	}
	after, err := selector.ReadSelection(ctx, "access")
	if err != nil || after.CandidateID != before.CandidateID || after.Revision == before.Revision {
		t.Fatal("a target fault changed the default or failed to apply a new snapshot")
	}
	routes, _, err := clientadapter.AccessRoutingInputs(lkg.View, []string{"demo-policy"})
	if err != nil {
		t.Fatal(err)
	}
	selected := false
	for _, route := range routes {
		selected = selected || route.ID == after.Targets[key] && route.FinalExit == "demo-exit"
	}
	if !selected || updated.Preference.PolicyID != "demo-policy" {
		t.Fatal("business feedback escaped its current Policy or selected the same failing exit")
	}
	if recovery {
		oldTarget, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
		if err != nil {
			t.Fatal("learned target could not establish its persistent connection")
		}
		defer oldTarget.Close()
		oldReader := bufio.NewReader(oldTarget)
		checkOldTarget := func() {
			t.Helper()
			_ = oldTarget.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.WriteString(oldTarget, "GET /old-connection HTTP/1.1\r\nHost: demo-target.example\r\nConnection: keep-alive\r\n\r\n"); err != nil {
				t.Fatal("old target stream was closed")
			}
			response, err := http.ReadResponse(oldReader, &http.Request{Method: "GET"})
			if err != nil {
				t.Fatal("old target response was lost")
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != "demo-ordinary-business" {
				t.Fatal("old target did not retain its original exit")
			}
		}
		checkOldTarget()
		_, port, err := net.SplitHostPort(listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		recovered, err := net.Listen("tcp", net.JoinHostPort(unavailable.String(), port))
		if err != nil {
			t.Fatal("isolated recovery target failed")
		}
		var accepted, requests atomic.Int64
		recoveredServer := &http.Server{
			ConnState: func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					accepted.Add(1)
				}
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				_, _ = io.WriteString(w, "demo-recovered-business")
			}),
		}
		go recoveredServer.Serve(recovered)
		defer recoveredServer.Close()
		wait(func(status Status) bool {
			for _, selection := range status.Selections {
				if selection.CandidateID == before.CandidateID && selection.Targets[key] == "" {
					return true
				}
			}
			if ctx.Err() != nil {
				t.Fatal("no background recovery before the runtime deadline")
			}
			checkKeep()
			checkOldTarget()
			return false
		})
		restored, err := selector.ReadSelection(ctx, "access")
		if err != nil || restored.Revision == after.Revision || restored.PolicyID != before.PolicyID || restored.CandidateID != before.CandidateID || restored.Targets[key] != "" {
			t.Fatal("background recovery did not update only the target's new-flow selection")
		}
		if accepted.Load() == 0 || requests.Load() != 0 {
			t.Fatal("recovery was not a background TCP-only trial before production use")
		}
		checkKeep()
		checkOldTarget()
		response, err := client.Get("http://" + target + "/new-connection")
		if err != nil {
			t.Fatal("new request did not use the recovered path")
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || string(body) != "demo-recovered-business" {
			t.Fatal("the recovered exit did not carry the new request")
		}
		checkKeep()
		checkOldTarget()
	}
	var cache observationCache
	if err := readStrict(options.LocalState, 1<<20, &cache); err != nil {
		t.Fatal(err)
	}
	for _, value := range cache.Observations {
		if value.Action == "tcp_connect" || value.Action == "tcp_calibration" {
			t.Fatal("native ordinary results entered the Probe persistence cache")
		}
	}
}

// Every source gets its own upstream socket, so independently authenticated WG
// peers sharing the receiver cannot overwrite one another's return address.
func delayedNativeUDPFixture(t *testing.T, ctx context.Context, targetPort int, delay time.Duration) int {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal("isolated delayed transport could not listen")
	}
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: targetPort}
	var mu sync.Mutex
	peers := map[string]*net.UDPConn{}
	closed := false
	stop := make(chan struct{})
	var workers sync.WaitGroup
	pause := func() bool {
		select {
		case <-time.After(delay):
			return true
		case <-ctx.Done():
			return false
		case <-stop:
			return false
		}
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
			if closed {
				mu.Unlock()
				return
			}
			upstream := peers[peer.String()]
			if upstream == nil {
				upstream, err = net.DialUDP("udp4", nil, target)
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
						if err != nil {
							return
						}
						if !pause() {
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
		closed = true
		close(stop)
		_ = listener.Close()
		for _, connection := range peers {
			_ = connection.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return listener.LocalAddr().(*net.UDPAddr).Port
}
