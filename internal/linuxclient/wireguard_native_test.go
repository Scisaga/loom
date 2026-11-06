package linuxclient

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"
)

func nativeProjectionFixture(t *testing.T, lifetime ...time.Duration) (control.Projection, map[string]string, string, time.Time) {
	t.Helper()
	validity := time.Minute
	if len(lifetime) > 0 {
		validity = lifetime[0]
	}
	hy2, input, at := resourceExecutionFixtureWithLifetime(t, time.Now(), validity)
	digest := "sha256:" + strings.Repeat("1", 64)
	p := control.Projection{NetworkID: "demo-network", NetworkIntent: control.EmptyNetworkIntent()}
	keys := map[string]string{}
	for _, id := range []string{"demo-access", "demo-entry", "demo-exit"} {
		seed := sha256.Sum256([]byte(id))
		public := base64.RawURLEncoding.EncodeToString(seed[:])
		roles := []string{"forward"}
		policies := []string{}
		if id == "demo-access" {
			roles = []string{"access"}
			policies = []string{"demo-policy"}
		}
		if id == "demo-exit" {
			roles = []string{"internet_egress"}
		}
		p.DeviceAuthorizations = append(p.DeviceAuthorizations, control.DeviceAuthorization{ID: id, Name: id, Platform: "linux", DevicePublicKey: public, Responsibilities: roles, PolicyIDs: policies, DistributionURLs: []string{}, RuntimeKey: public, TransactionID: "demo-join", InviteMaterialID: digest, BindingMaterialID: digest})
		if id == "demo-access" {
			registered, err := control.DerivedWireGuardPublicKey(p.NetworkID, p.DeviceAuthorizations[len(p.DeviceAuthorizations)-1])
			if err != nil {
				t.Fatal(err)
			}
			p.DeviceAuthorizations[len(p.DeviceAuthorizations)-1].WireGuardPublicKey = registered
			continue
		}
		seed[0] &= 248
		seed[31] &= 127
		seed[31] |= 64
		key, _ := ecdh.X25519().NewPrivateKey(seed[:])
		wgPublic := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
		p.DeviceAuthorizations[len(p.DeviceAuthorizations)-1].WireGuardPublicKey = wgPublic
		address, host, port := "192.0.2.51/32", "192.0.2.11", 51821
		if id == "demo-exit" {
			address, host, port = "192.0.2.52/32", "192.0.2.12", 51822
		}
		local := []string{address}
		p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, control.TransportResource{ID: id + "-wg", Kind: "wireguard", OwnerNodeID: id, ListenerID: id + "-wg", DialHost: host, DialPort: port, AccessEnabled: id == "demo-entry", Authentication: control.ResourceAuthentication{PublicKey: &wgPublic, LocalAddresses: &local}})
		path := filepath.Join(t.TempDir(), "node.key")
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(seed[:])), 0600); err != nil {
			t.Fatal(err)
		}
		keys[id] = path
	}
	resource := hy2.Resources[0]
	resource.OwnerNodeID = "demo-entry"
	p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, resource)
	sort.Slice(p.NetworkIntent.Resources, func(i, j int) bool { return p.NetworkIntent.Resources[i].ID < p.NetworkIntent.Resources[j].ID })
	p.NetworkIntent.Links = []control.NetworkLink{}
	p.NetworkIntent.Services = []control.Service{{ID: "demo-service", Name: "Demo service", Kind: "internet", RestrictToProbeTargets: new(false)}}
	p.NetworkIntent.DNSRecords = []control.DNSRecord{{ID: "demo-record", Name: "demo-service.loom", Addresses: []string{"192.0.2.80"}}}
	any := control.PolicyScope{Mode: "any", NodeIDs: []string{}}
	p.NetworkIntent.Policies = []control.NetworkPolicy{{ID: "demo-policy", Name: "Demo policy", ServiceID: "demo-service", Action: "allow", EntryScope: control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-entry"}}, RelayScope: any, ExitScope: new(control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-exit"}}), MaxHops: 2, LocalEgressDevices: new([]string{}), AllowDirect: new(false)}}
	addFixtureWGListeners(t, input, p.NetworkIntent.Resources)
	return p, keys, input, at
}

func TestNativeProjectionKeepsOneSessionAndSeparatesIsolatedCapture(t *testing.T) {
	p, _, input, at := nativeProjectionFixture(t)
	p.DeviceAuthorizations[1].Responsibilities = []string{"access", "forward"}
	p.DeviceAuthorizations[1].PolicyIDs = []string{"demo-policy"}
	// Local forward access starts at its Link; it has no public loopback login.
	view, err := control.ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	executions, err := prepareResourceExecutions(view, input, at)
	if err != nil {
		t.Fatal(err)
	}
	capture, server, err := generationConfigs(view, "demo-local", nil, "tun", executions)
	if err != nil {
		t.Fatal(err)
	}
	var a, b map[string]any
	json.Unmarshal([]byte(capture), &a)
	json.Unmarshal([]byte(server), &b)
	if a["endpoints"] != nil || b["endpoints"] == nil || !strings.Contains(capture, `"type":"socks"`) || strings.Contains(capture, `"type":"hysteria2"`) {
		t.Fatal("hybrid duplicated a WG session or lost its local capture bridge")
	}
	if !strings.Contains(capture, `"netns":"/proc/self/fd/3"`) || strings.Contains(server, `"type":"tun"`) || !strings.Contains(server, `"path":"native-dns.db"`) {
		t.Fatal("hybrid lost underlay isolation or separate disposable DNS cache")
	}
}

func TestRealNativeProjectedSegmentsWithoutImplicitHostAccess(t *testing.T) {
	testRealNativeProjectedSegments(t, false)
}
func TestRealNativeMixedFamilyProjectedBusinessAndOwnership(t *testing.T) {
	testRealNativeProjectedSegments(t, false, false, false, false, true)
}
func TestRealLocalNetworkProjectedSegmentsAndWithdrawal(t *testing.T) {
	testRealNativeProjectedSegments(t, true)
}
func TestRealLocalNetworkIdentityProjectedSegmentsAndWithdrawal(t *testing.T) {
	testRealNativeProjectedSegments(t, true, false, false, true)
}
func TestRealNativeSharedResourcePeers(t *testing.T) { testRealNativeProjectedSegments(t, false, true) }
func TestRealNativeCertifiedSenderDNS(t *testing.T) {
	testRealNativeProjectedSegments(t, false, false, true)
}
func testRealNativeProjectedSegments(t *testing.T, lan bool, shared ...bool) {
	namedPeer := len(shared) > 1 && shared[1]
	identityLAN := len(shared) > 2 && shared[2]
	mixedAddresses := len(shared) > 3 && shared[3]
	executable := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if executable == "" {
		t.Skip("set LOOM_LINUX_MIXED_EXECUTABLE in a fresh network namespace")
	}
	if err := requireDifferentNetworkNamespace("/proc/self/ns/net", "/proc/1/ns/net"); err != nil {
		t.Fatal(err)
	}
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) != 1 || ifaces[0].Name != "lo" {
		t.Fatal("requires a fresh loopback-only namespace")
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"address", "add", "192.0.2.10/32", "dev", "lo"}, {"address", "add", "192.0.2.11/32", "dev", "lo"}, {"address", "add", "192.0.2.12/32", "dev", "lo"}, {"address", "add", "192.0.2.80/32", "dev", "lo"}, {"address", "add", "192.0.2.81/32", "dev", "lo"}} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("namespace setup: %v %s", err, out)
		}
	}
	p, keys, input, at := nativeProjectionFixture(t)
	if mixedAddresses {
		for index := range p.NetworkIntent.Resources {
			if p.NetworkIntent.Resources[index].ID == "demo-exit-wg" {
				p.NetworkIntent.Resources[index].Authentication.LocalAddresses = new([]string{"2001:db8::52/128"})
			}
		}
	}
	if namedPeer {
		if out, err := exec.Command("ip", "address", "add", "192.0.2.53/32", "dev", "lo").CombinedOutput(); err != nil {
			t.Fatalf("isolated certified DNS input: %v %s", err, out)
		}
		serveNativePeerTestDNS(t)
		for i := range p.DeviceAuthorizations {
			p.DeviceAuthorizations[i].DNSServers = []string{"192.0.2.53"}
		}
		for i := range p.NetworkIntent.Resources {
			if p.NetworkIntent.Resources[i].ID == "demo-exit-wg" {
				p.NetworkIntent.Resources[i].DialHost = "demo-peer.example"
			}
		}
	}
	business := "192.0.2.80"
	if mixedAddresses {
		business = isolatedPublicFixtureAddress(t).String()
	}
	if lan {
		local := "192.0.2.0/24"
		if identityLAN {
			local = "10.64.8.0/24"
			if out, err := exec.Command("ip", "address", "add", "10.64.8.80/32", "dev", "lo").CombinedOutput(); err != nil {
				t.Fatalf("isolated LAN target: %v %s", err, out)
			}
		}
		virtual, err := control.AllocateLocalNetworkPrefix(p.NetworkID, "demo-service", 0, local, nil)
		if err != nil {
			t.Fatal(err)
		}
		host := virtual.Addr().As4()
		host[3] = 80
		business = netip.AddrFrom4(host).String()
		p.NetworkIntent.Services[0] = control.Service{ID: "demo-service", Name: "Demo LAN", Kind: "local_network", LocalNetwork: &control.LocalNetwork{GatewayNodeID: "demo-exit", LocalPrefix: local, VirtualPrefix: virtual.String(), Enabled: true}, RestrictToProbeTargets: new(false)}
		p.NetworkIntent.Policies[0].ExitScope = nil
		p.NetworkIntent.Policies[0].AllowDirect = nil
		p.NetworkIntent.Policies[0].LocalEgressDevices = nil
		p.DeviceAuthorizations[2].Responsibilities = []string{"forward"}
		p.NetworkIntent.DNSRecords[0].Addresses = []string{business}
		p.NetworkIntent.DNSRecords[0].ServiceID = "demo-service"
	}
	if len(shared) > 0 && shared[0] {
		for index, id := range []string{"demo-other-a", "demo-other-b"} {
			seed := sha256.Sum256([]byte(id))
			key, _ := ecdh.X25519().NewPrivateKey(seed[:])
			public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
			device := p.DeviceAuthorizations[1]
			device.ID = id
			device.Name = id
			device.DevicePublicKey = public
			device.RuntimeKey = public
			device.WireGuardPublicKey = public
			p.DeviceAuthorizations = append(p.DeviceAuthorizations, device)
			local := []string{fmt.Sprintf("192.0.2.%d/32", 53+index)}
			resource := control.TransportResource{ID: id + "-wg", Kind: "wireguard", OwnerNodeID: id, ListenerID: id + "-wg", DialHost: fmt.Sprintf("192.0.2.%d", 13+index), DialPort: 51823 + index, Authentication: control.ResourceAuthentication{PublicKey: &public, LocalAddresses: &local}}
			p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, resource)
			path := filepath.Join(t.TempDir(), "node.key")
			if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(seed[:])), 0600); err != nil {
				t.Fatal(err)
			}
			keys[id] = path
		}
		sort.Slice(p.DeviceAuthorizations, func(i, j int) bool { return p.DeviceAuthorizations[i].ID < p.DeviceAuthorizations[j].ID })
		sort.Slice(p.NetworkIntent.Resources, func(i, j int) bool { return p.NetworkIntent.Resources[i].ID < p.NetworkIntent.Resources[j].ID })
	}
	scope := p.NetworkIntent.Services[0].Scope()
	if p.NetworkIntent.Services[0].Kind == "internet" {
		scope = "access"
	}

	cacheRoot := t.TempDir()
	logs := map[string]string{}
	start := func(name, config string) (*exec.Cmd, chan error, func()) {
		t.Helper()
		dir := t.TempDir()
		config, err = withPersistentDNSCache(config, filepath.Join(cacheRoot, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "config.json")
		if err := writeConfig(path, config); err != nil {
			t.Fatal(err)
		}
		if err := preflightRuntimeConfig(executable, config); err != nil {
			t.Fatal(name, err)
		}
		log, err := os.OpenFile(filepath.Join(dir, "runtime.log"), os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		logs[name] = filepath.Join(dir, "runtime.log")
		command := exec.Command(executable, "run", "-c", path)
		command.Dir = dir
		command.Stdout, command.Stderr = log, log
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait(); close(done) }()
		stopped := false
		stop := func() {
			if !stopped {
				stopped = true
				_ = stopProcess(command, done)
				log.Close()
			}
		}
		t.Cleanup(stop)
		return command, done, stop
	}
	addFixtureWGListeners(t, input, p.NetworkIntent.Resources)
	render := func(id string) (control.DeviceView, string, *wireGuardTransaction) {
		t.Helper()
		view, err := control.ProjectDeviceView(p, id)
		if err != nil {
			t.Fatal(id, err)
		}
		executions, err := prepareResourceExecutions(view, input, at)
		if err != nil {
			t.Fatal(err)
		}
		config, err := nodeRuntimeConfig(view, "demo-local", nil, "mixed", executions)
		if err != nil {
			t.Fatal(id, err)
		}
		wg := fixtureWGReceiver(t, view, executions)
		var tx *wireGuardTransaction
		config, err = appendNativeWireGuard(config, view, wg, tx, keys[id])
		if err != nil {
			t.Fatal(id, err)
		}
		if id != "demo-access" {
			var value map[string]any
			json.Unmarshal([]byte(config), &value)
			delete(value["experimental"].(map[string]any), "clash_api")
			inbounds := []any{}
			for _, raw := range value["inbounds"].([]any) {
				if raw.(map[string]any)["tag"] != control.LinkProbeInbound {
					inbounds = append(inbounds, raw)
				}
			}
			value["inbounds"] = inbounds
			body, _ := json.Marshal(value)
			config = string(body)
		}
		return view, config, tx
	}
	exitView, exitConfig, tx := render("demo-exit")
	var receiverDocument struct {
		Endpoints []map[string]any `json:"endpoints"`
	}
	if json.Unmarshal([]byte(exitConfig), &receiverDocument) != nil || len(receiverDocument.Endpoints) != 1 || receiverDocument.Endpoints[0]["system"] == true || receiverDocument.Endpoints[0]["host_sources"] != nil {
		t.Fatal("independent native receiver created host management facilities")
	}
	exitProcess, exitDone, stopExit := start("exit", exitConfig)
	defer func() {
		stopExit()
		if err := tx.Cleanup(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	exitExecutions, err := prepareResourceExecutions(exitView, input, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := waitTransportResources(ctx, exitView, exitExecutions, exitProcess.Process.Pid, time.Now, exitDone); err != nil {
		t.Fatal("native listener readback", err)
	}
	readback, err := readTransportResources(ctx, exitView, exitExecutions, exitProcess.Process.Pid, time.Now())
	if err != nil || len(readback) != 1 || readback[0].Validate() != nil || readback[0].PublicKey == "" || readback[0].CertificateDigest != "" {
		t.Fatal("native resource identity readback", err)
	}
	if _, err := readTransportResources(ctx, exitView, exitExecutions, os.Getpid(), time.Now()); err == nil {
		t.Fatal("unrelated process was accepted as native receiver")
	}
	entryView, entryConfig, entryTransaction := render("demo-entry")
	entryProcess, entryDone, stopEntryProcess := start("entry", entryConfig)
	stopEntry := func() {
		stopEntryProcess()
		if entryTransaction != nil {
			if err := entryTransaction.Cleanup(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if namedPeer {
		entryExecutions, err := prepareResourceExecutions(entryView, input, at)
		if err != nil {
			t.Fatal(err)
		}
		if err := waitTransportResources(ctx, entryView, entryExecutions, entryProcess.Process.Pid, func() time.Time { return at }, entryDone); err != nil {
			t.Fatal(err)
		}

	}
	client, clientConfig, _ := render("demo-access")
	_, _, stopAccess := start("access", clientConfig)
	listener, err := net.Listen("tcp", "0.0.0.0:18080")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "demo-business") })}
	go server.Serve(listener)
	defer server.Close()
	selector, err := NewHTTPSelector(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := waitSelector(ctx, selector, []string{scope}); err != nil {
		t.Fatal(err)
	}
	selectCandidate := func(candidate control.RouteCandidate) error {
		previous, err := selector.ReadSelection(ctx, scope)
		if err != nil {
			return err
		}
		choice := protocol.RouteChoice{EntryNodeID: candidate.EntryNodeID, FirstResourceID: candidate.FirstResourceID, FinalExit: candidate.FinalExit}
		_, err = selector.ApplySelection(ctx, previous, clientmodel.Selection{Scope: scope, PolicyID: candidate.PolicyID, CandidateID: candidate.ID,
			Targets: map[string]string{}, Choices: map[string]protocol.RouteChoice{candidate.ID: choice}})
		return err
	}
	proxyURL, _ := url.Parse("http://127.0.0.1:1080")
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	lastRequestError := ""
	request := func(host string) bool {
		response, err := httpClient.Get("http://" + host + ":18080/demo")
		if err != nil {
			lastRequestError = err.Error()
			return false
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		lastRequestError = fmt.Sprintf("status=%d read=%v body=%q", response.StatusCode, err, body)
		return err == nil && string(body) == "demo-business"
	}
	if len(testDeviceExecution(client).Routes) != 2 {
		t.Fatal("WG and Hy2 first hops did not coexist")
	}
	for _, candidate := range testDeviceExecution(client).Routes {
		if err := selectCandidate(candidate); err != nil {
			t.Fatal(err)
		}
		hosts := []string{business}
		if !mixedAddresses {
			hosts = append(hosts, "demo-service.loom")
		}
		for _, host := range hosts {
			if !request(host) {
				t.Fatal("projected business path failed", candidate.FirstResourceID)
			}
		}
		if request("192.0.2.81") || request("192.0.2.52") {
			t.Fatal("unapproved business or host target was exposed")
		}
	}
	diagnostic, err := clientadapter.WithNativeDiagnostic(ctx, clientConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range client.Resources {
		if r.ID == "demo-entry-wg" {
			if roundTrip, err := clientadapter.ProbeWireGuard(diagnostic, client.NetworkID, r); err != nil || roundTrip == nil || *roundTrip <= 0 {
				t.Fatal("native first hop diagnostic", err)
			}
		}
	}
	stopEntry()
	if info, err := os.Stat(filepath.Join(cacheRoot, "entry.json."+clientadapter.TUNDNSCache)); err != nil || info.Size() == 0 {
		t.Fatal("native names were not persisted outside process configuration", err)
	}
	_, _, stopEntry = start("entry", entryConfig)
	stopAccess()
	_, _, stopAccess = start("access", clientConfig)
	if err := waitSelector(ctx, selector, []string{scope}); err != nil {
		t.Fatal(err)
	}
	if err := selectCandidate(testDeviceExecution(client).Routes[0]); err != nil {
		t.Fatal(err)
	}
	recovered := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		if request("demo-service.loom") {
			recovered = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !recovered {
		for _, name := range []string{"entry", "access", "exit"} {
			body, _ := os.ReadFile(logs[name])
			t.Log(name, string(body))
		}
		t.Fatal("native domain business did not recover with its persistent names", lastRequestError)
	}
	if lan {
		stopAccess()
		conflict := []string{p.NetworkIntent.Services[0].LocalNetwork.VirtualPrefix}
		bounded, err := clientadapter.WithLocalNetworkBoundary(clientConfig, &conflict)
		if err != nil {
			t.Fatal(err)
		}
		_, _, stopAccess = start("access", bounded)
		if err := waitSelector(ctx, selector, []string{scope}); err != nil {
			t.Fatal(err)
		}
		for _, candidate := range testDeviceExecution(client).Routes {
			if err := selectCandidate(candidate); err != nil {
				t.Fatal(err)
			}
			if request(business) || request("demo-service.loom") {
				t.Fatal("underlay conflict still allowed an IP or named LAN request")
			}
		}
		stopAccess()
		_, _, stopAccess = start("access", clientConfig)
		if err := waitSelector(ctx, selector, []string{scope}); err != nil {
			t.Fatal(err)
		}
		// A new data plane defaults to reject until the client selects an
		// authorized path. Exercise both independent first hops after recovery.
		for _, candidate := range testDeviceExecution(client).Routes {
			if err := selectCandidate(candidate); err != nil {
				t.Fatal(err)
			}
			for _, host := range []string{business, "demo-service.loom"} {
				if !request(host) {
					t.Fatal("removing the local conflict did not restore the unchanged authorized Service", candidate.FirstResourceID, host, lastRequestError)
				}
			}
		}
	}
	stopEntry()
	p.DeviceAuthorizations[0].PolicyIDs = []string{}
	_, revoked, _ := render("demo-entry")
	start("entry", revoked)
	for _, candidate := range testDeviceExecution(client).Routes {
		if err := selectCandidate(candidate); err != nil {
			t.Fatal(err)
		}
		if request(business) {
			t.Fatal("revoked permission survived receiver replacement")
		}
	}
	fmt.Fprintln(io.Discard, "native segmented transport verified")
}
