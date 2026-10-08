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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/control"
)

func nativeProjectionFixture(t *testing.T) (control.Projection, map[string]string, string, time.Time) {
	t.Helper()
	hy2, input, at := resourceExecutionFixture(t, time.Now())
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
			continue
		}
		seed[0] &= 248
		seed[31] &= 127
		seed[31] |= 64
		key, _ := ecdh.X25519().NewPrivateKey(seed[:])
		wgPublic := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
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
	var receiver control.TransportResource
	for _, r := range p.NetworkIntent.Resources {
		if r.ID == "demo-exit-wg" {
			receiver = r
		}
	}
	dns, err := control.WireGuardAccessAddress(receiver, "")
	if err != nil {
		t.Fatal(err)
	}
	p.NetworkIntent.Links = []control.NetworkLink{{ID: "demo-link", FromNodeID: "demo-entry", ToNodeID: "demo-exit", FromResourceID: "demo-entry-wg", ResourceID: receiver.ID, InitiatorNodeID: "demo-entry", Purpose: "relay", ProbeTarget: control.LinkProbeTarget{ResourceID: receiver.ID, Host: dns.String(), Port: 53, Action: "wireguard_dns"}}}
	p.NetworkIntent.Services = []control.Service{{ID: "demo-service", Name: "Demo service", Kind: "internet", Matchers: []control.ServiceMatcher{{Kind: "dns_exact", Value: "demo-service.loom"}, {Kind: "ip_prefix", Value: "192.0.2.80/32"}}}}
	p.NetworkIntent.DNSRecords = []control.DNSRecord{{ID: "demo-record", Name: "demo-service.loom", Addresses: []string{"192.0.2.80"}}}
	any := control.PolicyScope{Mode: "any", NodeIDs: []string{}}
	p.NetworkIntent.Policies = []control.NetworkPolicy{{ID: "demo-policy", Name: "Demo policy", ServiceID: "demo-service", Action: "allow", EntryScope: control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-entry"}}, RelayScope: any, ExitScope: control.PolicyScope{Mode: "only", NodeIDs: []string{"demo-exit"}}, MaxHops: 2, LocalEgressDevices: []string{}}}
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
	executions, err := prepareHY2Executions(view, input, at)
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

func TestRealNativeProjectedSegmentsAndManagementReturnPath(t *testing.T) {
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
	// Exercise the older-kernel rule even when this test host supports live
	// TUN renames. All actual interface operations remain in this test netns.
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	strictIP := filepath.Join(t.TempDir(), "ip")
	wrapper := fmt.Sprintf("#!/usr/bin/python3\nimport json,os,subprocess,sys\nip=%q\na=sys.argv[1:]\nif len(a)==6 and a[:3]==['link','set','dev'] and a[4]=='name':\n v=json.loads(subprocess.check_output([ip,'-json','link','show','dev',a[3]]))[0]\n if 'UP' in v['flags']:sys.exit(2)\nos.execv(ip,[ip]+a)\n", ip)
	if err := os.WriteFile(strictIP, []byte(wrapper), 0700); err != nil {
		t.Fatal(err)
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
	render := func(id string, system bool) (control.DeviceView, string, *wireGuardTransaction) {
		t.Helper()
		view, err := control.ProjectDeviceView(p, id)
		if err != nil {
			t.Fatal(id, err)
		}
		executions, err := prepareHY2Executions(view, input, at)
		if err != nil {
			t.Fatal(err)
		}
		config, err := nodeRuntimeConfig(view, "demo-local", nil, "mixed", executions)
		if err != nil {
			t.Fatal(id, err)
		}
		wg := wireGuardExecution{}
		var tx *wireGuardTransaction
		if system {
			wg, _, err = projectWireGuard(view)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Config: filepath.Join(t.TempDir(), "runtime.json"), IP: strictIP}
			options.defaults()
			tx, err = prepareNativeWireGuard(view, wg, options)
			if err != nil {
				t.Fatal(err)
			}
			if err = tx.saveOwnership(); err != nil {
				t.Fatal(err)
			}
		}
		config, err = appendNativeReceivers(config, view, wg, tx, keys[id])
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
	exitView, exitConfig, tx := render("demo-exit", true)
	exitProcess, exitDone, stopExit := start("exit", exitConfig)
	defer func() {
		stopExit()
		if err := tx.Cleanup(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	exitExecutions, err := prepareHY2Executions(exitView, input, at)
	if err != nil {
		t.Fatal(err)
	}
	// A TUN fd appears before the child has finished configuring its original
	// name. Its owned WG listener is the existing post-initialization readback.
	if err := waitTransportResources(ctx, exitView, exitExecutions, exitProcess.Process.Pid, func() time.Time { return at }, exitDone); err != nil {
		t.Fatal(err)
	}
	if err := tx.activateNative(ctx, exitProcess.Process.Pid, exitDone); err != nil {
		for _, owned := range tx.owned {
			addresses, _ := interfaceAddresses(tx.options.IP, owned.link.Interface)
			t.Logf("fixture addresses actual=%v wanted=%v", addresses, owned.localAddresses())
		}
		t.Fatal(err)
	}
	if err := waitTransportResources(ctx, exitView, nil, exitProcess.Process.Pid, time.Now, exitDone); err != nil {
		t.Fatal("native listener readback", err)
	}
	readback, err := readTransportResources(ctx, exitView, nil, exitProcess.Process.Pid, time.Now())
	if err != nil || len(readback) != 1 || readback[0].Validate() != nil || readback[0].PublicKey == "" || readback[0].CertificateDigest != "" {
		t.Fatal("native resource identity readback", err)
	}
	if _, err := readTransportResources(ctx, exitView, nil, os.Getpid(), time.Now()); err == nil {
		t.Fatal("unrelated process was accepted as native receiver")
	}
	_, entryConfig, _ := render("demo-entry", false)
	_, _, stopEntry := start("entry", entryConfig)
	client, clientConfig, _ := render("demo-access", false)
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
	if err := waitSelector(ctx, selector, []string{"service:demo-service"}); err != nil {
		t.Fatal(err)
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
	if len(client.Routes) != 2 {
		t.Fatal("WG and Hy2 first hops did not coexist")
	}
	for _, candidate := range client.Routes {
		if err := selector.Set(ctx, candidate.Scope, candidate.ID); err != nil {
			t.Fatal(err)
		}
		for _, host := range []string{"192.0.2.80", "demo-service.loom"} {
			if !request(host) {
				t.Fatal("projected business path failed", candidate.FirstResourceID, host)
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
			if err := clientadapter.ProbeWireGuard(diagnostic, r); err != nil {
				t.Fatal("native first hop diagnostic", err)
			}
		}
	}
	// Fixed node management identity has its exact pre-existing return route.
	private, _, _ := nativePrivateKey(keys["demo-entry"])
	var target control.TransportResource
	for _, r := range p.NetworkIntent.Resources {
		if r.ID == "demo-exit-wg" {
			target = r
		}
	}
	public, _ := base64.RawURLEncoding.DecodeString(*target.Authentication.PublicKey)
	management := map[string]any{"endpoints": []any{map[string]any{"type": "wireguard", "tag": "demo-management", "system": false, "address": []string{"192.0.2.51/32"}, "private_key": private, "peers": []any{map[string]any{"address": target.DialHost, "port": target.DialPort, "public_key": base64.StdEncoding.EncodeToString(public), "allowed_ips": []string{"0.0.0.0/0"}}}}}, "inbounds": []any{map[string]any{"type": "mixed", "listen": "127.0.0.1", "listen_port": 1081}}, "route": map[string]any{"final": "demo-management"}}
	body, _ := json.Marshal(management)
	start("management", string(body))
	mgmtURL, _ := url.Parse("http://127.0.0.1:1081")
	mgmtTransport := &http.Transport{Proxy: http.ProxyURL(mgmtURL), DisableKeepAlives: true}
	defer mgmtTransport.CloseIdleConnections()
	mgmtClient := http.Client{Transport: mgmtTransport, Timeout: 2 * time.Second}
	var managementErr error
	for i := 0; i < 10; i++ {
		response, err := mgmtClient.Get("http://192.0.2.52:18080/demo")
		managementErr = err
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if managementErr != nil {
		t.Fatal("original management identity lost its return path", managementErr)
	}
	if err := tx.readbackNative(); err != nil {
		t.Fatal(err)
	}
	stopEntry()
	if info, err := os.Stat(filepath.Join(cacheRoot, "entry.json."+clientadapter.TUNDNSCache)); err != nil || info.Size() == 0 {
		t.Fatal("native names were not persisted outside process configuration", err)
	}
	_, _, stopEntry = start("entry", entryConfig)
	stopAccess()
	start("access", clientConfig)
	if err := waitSelector(ctx, selector, []string{"service:demo-service"}); err != nil {
		t.Fatal(err)
	}
	if err := selector.Set(ctx, client.Routes[0].Scope, client.Routes[0].ID); err != nil {
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
	stopEntry()
	p.DeviceAuthorizations[0].PolicyIDs = []string{}
	_, revoked, _ := render("demo-entry", false)
	start("entry", revoked)
	for _, candidate := range client.Routes {
		if err := selector.Set(ctx, candidate.Scope, candidate.ID); err != nil {
			t.Fatal(err)
		}
		if request("192.0.2.80") {
			t.Fatal("revoked permission survived receiver replacement")
		}
	}
	fmt.Fprintln(io.Discard, "native segmented transport verified")
}
