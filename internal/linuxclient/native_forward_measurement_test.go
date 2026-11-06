package linuxclient

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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
)

// The normal composed access/forward entry starts at its own Link. Its one
// access candidate stays fixed while the forward selector compares two actual
// resources belonging to the same next hop. Only relay packet delay changes;
// neither the test nor its report receiver supplies samples or selector writes.
func TestOfficialLinuxNativeForwardMeasuredRTTReversalKeepsExistingTCP(t *testing.T) {
	executable := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the reviewed native executable in a dedicated namespace")
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
	limit := timing.IdlePeriod + 4*timing.ActivePeriod + 4*timing.RoundTimeout
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
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "sender.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(private.Bytes())), 0600); err != nil {
		t.Fatal(err)
	}
	var endpoint control.EndpointGeneration
	store, identityPath, makeView := linuxAcceptanceProjectionFixture(t, func(projection *control.Projection) {
		source := projection.DeviceAuthorizations[0]
		source.Responsibilities = []string{"access", "forward"}
		source.PolicyIDs, source.DNSServers = []string{"demo-policy"}, []string{"127.0.0.1"}
		source.WireGuardPublicKey = base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
		exit := p.DeviceAuthorizations[2]
		exit.DNSServers = []string{"127.0.0.1"}
		projection.DeviceAuthorizations = []control.DeviceAuthorization{source, exit}
		projection.NetworkIntent = p.NetworkIntent
		projection.EndpointGenerations = []control.EndpointGeneration{endpoint}
		p.Config, p.EndpointGenerations, p.DeviceAuthorizations = projection.Config, projection.EndpointGenerations, projection.DeviceAuthorizations
	})
	var lkg control.DeviceViewEnvelope
	var accepted atomic.Pointer[control.DeviceViewEnvelope]
	var reports *nativeForwardReports
	endpoint, reports = nativeForwardReportReceiver(t, ctx, evidence, store.PublicKey(), func() control.DeviceViewEnvelope { return *accepted.Load() })
	lkg = makeView(7, true)
	if err := store.SaveLKG(lkg); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPreference(clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}); err != nil {
		t.Fatal(err)
	}
	accepted.Store(&lkg)
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
	options := Options{DeviceState: identityPath, LocalState: filepath.Join(root, "observations.json"), Status: filepath.Join(root, "status.json"), Config: filepath.Join(root, "config.json"), SingBox: executable, WireGuardPrivateKey: keyPath, Capture: "mixed", RefreshPoll: time.Second, Log: log, Generation: func() (string, error) { return "demo-underlay", nil }}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, options) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error("normal forward supervisor did not clean up", err)
		}
	}()
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
		return err == nil && nativeForwardSamplePair(t, reports.samples(), links, specs, 0, "hysteria2", execution.Resources) && before.first() == tags["hysteria2"]
	})
	status, err := ReadStatus(options.Status)
	if err != nil || status.Runtime != "running" || len(status.Selections) != 1 || status.Selections[0].CandidateID != execution.Routes[0].ID {
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
	if err := atomicJSON(filepath.Join(evidence, "forward-before.json"), map[string]any{"forward": before, "samples": reports.samples(), "old_id": oldID, "access": accessBefore}); err != nil {
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
		return err == nil && after.Revision != before.Revision && after.first() == tags["wireguard"] && nativeForwardSamplePair(t, reports.samples(), links, specs, flipped, "wireguard", execution.Resources)
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
	if err := atomicJSON(filepath.Join(evidence, "forward-after.json"), map[string]any{"forward": after, "samples": reports.samples(), "flipped_at": flipped, "connections": finalConnections, "access": accessAfter}); err != nil {
		t.Fatal(err)
	}
}

func nativeForwardSamplePair(t *testing.T, samples []control.Observation, links map[string]control.NetworkLink, specs map[string]string, after int64, faster string, resources []control.TransportResource) bool {
	t.Helper()
	metrics := map[string]int64{}
	for _, sample := range samples {
		link, found := links[sample.LinkID]
		if !found || sample.ObservedAt <= after || sample.Result != "available" || sample.RoundTripMS == nil {
			continue
		}
		if sample.Level != "link" || sample.ResourceID != link.ResourceID || sample.SpecDigest != specs[link.ID] || sample.Action != link.ProbeTarget.Action || sample.Target != net.JoinHostPort(link.ProbeTarget.Host, strconv.Itoa(link.ProbeTarget.Port)) || sample.NetworkGeneration != "demo-underlay" || sample.Validate() != nil {
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

type nativeForwardReports struct {
	mu     sync.Mutex
	latest map[string]control.Observation
}

type nativeForwardChallenge struct {
	Schema int    `json:"schema"`
	Nonce  string `json:"nonce"`
}

func (reports *nativeForwardReports) samples() []control.Observation {
	reports.mu.Lock()
	defer reports.mu.Unlock()
	values := make([]control.Observation, 0, len(reports.latest))
	for _, value := range reports.latest {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].LinkID < values[j].LinkID })
	return values
}

// This disposable receiver authenticates the real client tunnel and verifies
// each original DeviceReport before preserving it and acknowledging its exact
// sequence. It is evidence consumption, not a measurement or control writer.
func nativeForwardReportReceiver(t *testing.T, ctx context.Context, root, devicePublic string, view func() control.DeviceViewEnvelope) (control.EndpointGeneration, *nativeForwardReports) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"demo.example"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	digest := func(body []byte) string { sum := sha256.Sum256(body); return "sha256:" + hex.EncodeToString(sum[:]) }
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"loom-tunnel/3"}, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := control.EndpointGeneration{ID: "demo-report-entry", Generation: 1, OwnerControlID: "demo-control", Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, ServerName: "demo.example", SPKISHA256: digest(parsed.RawSubjectPublicKeyInfo), CertificateDigest: digest(der), Modes: []string{"device"}, State: "serving"}
	reports := &nativeForwardReports{latest: map[string]control.Observation{}}
	var workers sync.WaitGroup
	var connections sync.Map
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Store(connection, true)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				defer connections.Delete(connection)
				_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
				reader := bufio.NewReader(connection)
				read := func(value any) error {
					var header [4]byte
					if _, err := io.ReadFull(reader, header[:]); err != nil {
						return err
					}
					size := binary.BigEndian.Uint32(header[:])
					if size == 0 || size > 8<<20 {
						return fmt.Errorf("invalid test tunnel frame")
					}
					body := make([]byte, size)
					if _, err := io.ReadFull(reader, body); err != nil {
						return err
					}
					return control.DecodeCanonical(body, value, control.ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20})
				}
				write := func(value any) error {
					body, err := control.CanonicalEncode(value)
					if err != nil {
						return err
					}
					var header [4]byte
					binary.BigEndian.PutUint32(header[:], uint32(len(body)))
					_, err = io.Copy(connection, bytes.NewReader(append(header[:], body...)))
					return err
				}
				var hello control.TunnelHello
				if read(&hello) != nil || hello.Validate() != nil || hello.Mode != "device" || hello.DeviceID != "demo-device" || hello.EndpointID != endpoint.ID || hello.Generation != endpoint.Generation {
					return
				}
				var nonce [32]byte
				if _, err := rand.Read(nonce[:]); err != nil {
					return
				}
				challenge := nativeForwardChallenge{3, base64.RawURLEncoding.EncodeToString(nonce[:])}
				if write(challenge) != nil {
					return
				}
				var proof control.TunnelProof
				if read(&proof) != nil || proof.Validate() != nil {
					return
				}
				message, err := control.CanonicalEncode(struct {
					Hello     control.TunnelHello    `json:"hello"`
					Challenge nativeForwardChallenge `json:"challenge"`
				}{hello, challenge})
				key, _ := base64.RawURLEncoding.DecodeString(devicePublic)
				signature, _ := base64.RawURLEncoding.DecodeString(proof.Signature)
				if err != nil || !ed25519.Verify(key, append([]byte("loom-device-tunnel-proof-v3\x00"), message...), signature) || write(struct {
					Schema int    `json:"schema"`
					Status string `json:"status"`
				}{3, "ready"}) != nil {
					return
				}
				request, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				defer request.Body.Close()
				response := httptest.NewRecorder()
				current := view()
				switch request.URL.Path {
				case "/device/report":
					var body io.Reader = request.Body
					if request.Header.Get("Content-Encoding") == "gzip" {
						compressed, err := gzip.NewReader(request.Body)
						if err != nil {
							return
						}
						defer compressed.Close()
						body = compressed
					}
					raw, err := io.ReadAll(io.LimitReader(body, 8<<20+1))
					var report control.DeviceReport
					if err != nil || control.DecodeCanonical(raw, &report, control.ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}) != nil || report.Verify(devicePublic) != nil || report.NetworkID != current.NetworkID || report.ViewDigest != current.ViewDigest || report.DeviceID != current.View.DeviceID {
						return
					}
					if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("signed-report-%d.json", report.ReportSequence)), raw, 0600); err != nil {
						return
					}
					reports.mu.Lock()
					for _, sample := range report.Observations {
						if sample.Level == "link" && sample.ObservedAt > reports.latest[sample.LinkID].ObservedAt {
							reports.latest[sample.LinkID] = sample
						}
					}
					reports.mu.Unlock()
					acknowledgement, _ := control.CanonicalEncode(control.DeviceReportResponse{Schema: 3, ReportSequence: report.ReportSequence, Status: "accepted"})
					_, _ = response.Write(acknowledgement)
				case "/device/config":
					// This case changes only packet latency. Keep the long poll
					// pending so management cannot manufacture another View.
					if request.Header.Get(control.DeviceConfigWaitHeader) != "" {
						<-ctx.Done()
						return
					}
					body, _ := control.CanonicalEncode(current)
					_, _ = response.Write(body)
				case "/device/link-observations":
					body, _ := control.CanonicalEncode(control.DeviceLinkObservations{Schema: 3, NetworkID: current.NetworkID, DeviceID: current.View.DeviceID, ViewDigest: current.ViewDigest, Cursor: "demo-empty", Reset: true, Removed: []string{}, Observations: []control.DeviceLinkObservation{}})
					_, _ = response.Write(body)
				default:
					response.WriteHeader(http.StatusNotFound)
				}
				result := response.Result()
				defer result.Body.Close()
				result.ContentLength, result.Close = int64(response.Body.Len()), true
				_ = result.Write(connection)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-acceptDone
		connections.Range(func(key, _ any) bool { _ = key.(net.Conn).Close(); return true })
		workers.Wait()
	})
	return endpoint, reports
}
