package linuxclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/deviceclient"
)

func mixedSourceDocument() map[string]any {
	return map[string]any{
		"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true}},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "demo-path"},
			map[string]any{"type": "selector", "tag": "demo-service", "outbounds": []string{"demo-path"}},
			map[string]any{"type": "block", "tag": "demo-reject"},
		},
		"route": map[string]any{"rules": []any{map[string]any{"inbound": []string{"tun-in"},
			"domain": []string{"demo-service.example"}, "outbound": "demo-service"}}, "final": "demo-reject"},
		"experimental": map[string]any{"clash_api": map[string]any{
			"external_controller": "127.0.0.1:61800", "secret": "demo-secret"}},
	}
}

func TestMixedCapturePreservesCertifiedRouting(t *testing.T) {
	source := mixedSourceDocument()
	source["outbounds"] = append(source["outbounds"].([]any), map[string]any{"type": "dns", "tag": "demo-dns"})
	source["route"].(map[string]any)["rules"] = append([]any{map[string]any{"port": []int{53}, "outbound": "demo-dns"}},
		source["route"].(map[string]any)["rules"].([]any)...)
	body, _ := json.Marshal(source)
	derived, err := deriveLinuxMixedRuntime(string(body))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(derived), &got); err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(body, &want); err != nil {
		t.Fatal(err)
	}
	want["inbounds"] = []any{map[string]any{"type": "mixed", "tag": "tun-in", "listen": "127.0.0.1", "listen_port": float64(1080)}}
	wantRules := want["route"].(map[string]any)["rules"].([]any)
	var sniff any
	if err := json.Unmarshal([]byte(`{"type":"logical","mode":"and","rules":[{"inbound":["tun-in"]},{"domain_regex":[".+"],"invert":true},{"port":[53],"invert":true}],"action":"sniff"}`), &sniff); err != nil {
		t.Fatal(err)
	}
	want["route"].(map[string]any)["rules"] = []any{wantRules[0], sniff, wantRules[1]}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("Mixed capture changed certified routing, candidate identity or selector authentication")
	}
	repeated, err := deriveLinuxMixedRuntime(string(body))
	if err != nil || repeated != derived {
		t.Fatal("Mixed capture projection is not deterministic")
	}
}

func TestMixedCaptureRejectsAdditionalFacilitiesAndImplicitRouting(t *testing.T) {
	changes := map[string]func(map[string]any){
		"additional-inbound": func(source map[string]any) {
			source["inbounds"] = append(source["inbounds"].([]any), map[string]any{"type": "mixed", "listen": "0.0.0.0", "listen_port": 1081})
		},
		"capture-redirect":   func(source map[string]any) { source["inbounds"].([]any)[0].(map[string]any)["auto_redirect"] = true },
		"wireguard-outbound": func(source map[string]any) { source["outbounds"].([]any)[0].(map[string]any)["type"] = "wireguard" },
		"network-endpoint":   func(source map[string]any) { source["endpoints"] = []any{map[string]any{"type": "wireguard"}} },
		"missing-route":      func(source map[string]any) { delete(source, "route") },
		"implicit-final":     func(source map[string]any) { delete(source["route"].(map[string]any), "final") },
		"raw-direct-final":   func(source map[string]any) { source["route"].(map[string]any)["final"] = "demo-path" },
		"unbound-selector":   func(source map[string]any) { source["route"].(map[string]any)["rules"] = []any{} },
		"remote-rule-set": func(source map[string]any) {
			source["route"].(map[string]any)["rule_set"] = []any{map[string]any{"type": "remote", "url": "https://example.com/demo-rules"}}
		},
		"route-redirect": func(source map[string]any) { source["route"].(map[string]any)["auto_redirect"] = true },
		"nested-rule-set": func(source map[string]any) {
			source["route"].(map[string]any)["rules"] = []any{map[string]any{"type": "logical", "mode": "and", "outbound": "demo-service",
				"rules": []any{map[string]any{"rule_set": []string{"demo-remote"}}}}}
		},
		"second-api-listener": func(source map[string]any) {
			source["experimental"].(map[string]any)["v2ray_api"] = map[string]any{"listen": "0.0.0.0:1081"}
		},
		"external-ui-fetch": func(source map[string]any) {
			source["experimental"].(map[string]any)["clash_api"].(map[string]any)["external_ui_download_url"] = "https://example.com/demo-ui"
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			source := mixedSourceDocument()
			change(source)
			body, _ := json.Marshal(source)
			if _, err := deriveLinuxMixedRuntime(string(body)); err == nil {
				t.Fatal("unsupported Mixed network facility or implicit route was accepted")
			}
		})
	}
}

func TestWGAccessCaptureKeepsInnerHy2AndUnderlaySeparate(t *testing.T) {
	source := mixedSourceDocument()
	wg := map[string]any{"type": "wireguard", "tag": "wg-access.demo-resource", "system_interface": false, "local_address": []string{"fdab::2/128"}, "private_key": "demo-private-input", "peers": []any{map[string]any{"server": "192.0.2.10", "server_port": 51820, "public_key": "demo-public-input", "allowed_ips": []string{"fdab::1/128"}}}}
	hy2 := source["outbounds"].([]any)[0].(map[string]any)
	hy2["type"] = "hysteria2"
	hy2["detour"] = wg["tag"]
	source["outbounds"] = append(source["outbounds"].([]any), wg)
	body, _ := json.Marshal(source)
	mixed, err := deriveLinuxMixedRuntime(string(body))
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	_ = json.Unmarshal([]byte(mixed), &parsed)
	before, _ := json.Marshal(source["outbounds"])
	after, _ := json.Marshal(parsed["outbounds"])
	if !bytes.Equal(before, after) {
		t.Fatal("Mixed rewrote certified WG or inner Hy2")
	}
	tun, err := withTUNUnderlay(string(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal([]byte(tun), &parsed)
	values := parsed["outbounds"].([]any)
	if values[0].(map[string]any)["netns"] != nil || values[len(values)-1].(map[string]any)["netns"] != tunUnderlayReference {
		t.Fatal("inner Hy2 escaped WG or WG UDP lost underlay namespace")
	}
	wg["system_interface"] = true
	body, _ = json.Marshal(source)
	if _, err := deriveLinuxMixedRuntime(string(body)); err == nil {
		t.Fatal("Mixed permitted kernel WG")
	}
	if _, err := withTUNUnderlay(string(body)); err == nil {
		t.Fatal("TUN permitted unreviewed system WG")
	}
}

func TestCaptureModeRequiresExplicitKnownInput(t *testing.T) {
	for _, mode := range []string{"mixed", "tun"} {
		if err := validateCapture(mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, invalid := range []string{"", "auto", "Mixed"} {
		if err := validateCapture(invalid); err == nil {
			t.Fatal("unknown capture mode bypassed the boundary")
		}
	}
}

func mixedRuntimeFixture(t *testing.T, root string, targetPort int) (*deviceclient.Store, string) {
	t.Helper()
	store, path, makeView := linuxAcceptanceFixture(t)
	if err := store.SaveLKG(makeView(7, true)); err != nil {
		t.Fatal(err)
	}
	return store, path
}

// Run only in a separate user and network namespace. It changes no host
// networking, creates no TUN, and never reads installed identities or secrets.
func TestOfficialLinuxMixedRuntimeSelectorAndBusiness(t *testing.T) {
	executable := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if executable == "" {
		t.Skip("set LOOM_LINUX_MIXED_EXECUTABLE and run in a dedicated user/network namespace")
	}
	for _, kind := range []string{"user", "net"} {
		current, err := os.Stat("/proc/self/ns/" + kind)
		initial, initialErr := os.Stat("/proc/1/ns/" + kind)
		if err != nil || initialErr != nil || os.SameFile(current, initial) {
			t.Fatal("real Mixed test requires separate user and network namespaces")
		}
		currentID, _ := os.Readlink("/proc/self/ns/" + kind)
		t.Logf("isolated %s namespace=%s differs from /proc/1 by file identity", kind, currentID)
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("real Mixed test requires a namespace with only loopback")
	}
	if output, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("enable isolated loopback: %v %s", err, output)
	}
	for _, address := range []string{"127.0.0.1:1080", "127.0.0.1:61800"} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal("Mixed test ports are already occupied in the test namespace")
		}
		listener.Close()
	}
	version, err := exec.Command(executable, "version").Output()
	if err != nil || !strings.Contains(string(version), "sing-box version 1.11.4") {
		t.Fatal("real Mixed test requires the existing exact sing-box 1.11.4")
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	binaryDigest := sha256.Sum256(binary)
	t.Logf("sing-box 1.11.4 sha256=%x", binaryDigest)
	baseline, err := exec.Command("ip", "-json", "route", "show", "table", "all").Output()
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-service.example"},
		DNSNames: []string{"demo-service.example", "demo-denied.example"}, NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4102444800, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	parsedCertificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsedCertificate)
	var requests atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path != "/demo-business" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(writer, "demo-business-through-certified-selector")
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, MinVersion: tls.VersionTLS12}
	target.StartTLS()
	defer target.Close()
	requestTarget := func(name string, proxy *url.URL) (*http.Response, error) {
		transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12}}
		if proxy != nil {
			transport.Proxy = http.ProxyURL(proxy)
		}
		defer transport.CloseIdleConnections()
		request, err := http.NewRequest(http.MethodGet, target.URL+"/demo-business", nil)
		if err != nil {
			return nil, err
		}
		request.Host = name
		return (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Do(request)
	}
	response, err := requestTarget("demo-denied.example", nil)
	if err != nil {
		t.Fatal("denied target is not independently reachable inside the isolated namespace")
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "demo-business-through-certified-selector" || requests.Load() != 1 {
		t.Fatal("denied target did not answer its direct loopback reachability check")
	}
	root := t.TempDir()
	port := target.Listener.Addr().(*net.TCPAddr).Port
	store, path := mixedRuntimeFixture(t, root, port)
	reload := make(chan os.Signal, 1)
	var clockAdvance atomic.Int64
	options := Options{DeviceState: path, LocalState: filepath.Join(root, "runtime-state.json"), Status: filepath.Join(root, "status.json"),
		Config: filepath.Join(root, "config.json"), SingBox: executable, Capture: "mixed",
		WireGuardPrivateKey: filepath.Join(root, "no-wg-key"),
		RefreshPoll:         time.Hour, Reload: reload, Generation: func() (string, error) { return "demo-network", nil }, Now: func() time.Time { return time.Now().Add(time.Duration(clockAdvance.Load())) }}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	done := make(chan error, 1)
	var transaction *wireGuardTransaction
	t.Cleanup(func() {
		if err := transaction.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	go func() { done <- runGeneration(ctx, options, store, nil, &transaction) }()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			<-done
		}
	}()
	var status Status
	for {
		status, err = ReadStatus(options.Status)
		if err == nil {
			break
		}
		select {
		case err := <-done:
			stopped = true
			t.Fatalf("Mixed runtime exited before selector readback: %v", err)
		case <-ctx.Done():
			t.Fatal("Mixed runtime did not publish selector readback")
		case <-time.After(20 * time.Millisecond):
		}
	}
	if len(status.Selections) != 1 || status.Selections[0].Scope != "service:demo-service" || status.Selections[0].CandidateID != store.LKG().View.Routes[0].ID ||
		status.Selections[0].State != "unknown" || len(status.Observations) != 0 || status.Reported {
		t.Fatalf("selector readback invented business or report success: %+v", status)
	}
	proxy, _ := url.Parse("http://127.0.0.1:1080")
	response, err = requestTarget("demo-service.example", proxy)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "demo-business-through-certified-selector" {
		t.Fatal("actual Mixed request did not follow the certified selector rule")
	}
	if response, err := requestTarget("demo-denied.example", proxy); err == nil {
		response.Body.Close()
		if response.StatusCode < 400 {
			t.Fatal("unmatched Mixed traffic escaped the certified reject final route")
		}
	}
	if requests.Load() != 2 {
		t.Fatal("unmatched Mixed traffic reached the independently available denied target")
	}
	// Keep the selector API connection alive across reload. Reusing the same
	// connection proves the existing data plane survived the preference edit.
	var selectorConnections atomic.Int32
	selectorTransport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		selectorConnections.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	defer selectorTransport.CloseIdleConnections()
	selectorClient := &http.Client{Transport: selectorTransport, Timeout: 2 * time.Second}
	actualConfig, err := os.ReadFile(options.Config)
	if err != nil {
		t.Fatal(err)
	}
	actualSelector, err := NewHTTPSelector(string(actualConfig))
	if err != nil {
		t.Fatal(err)
	}
	readSelector := func() {
		request, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:61800/proxies/service:demo-service", nil)
		request.Header.Set("Authorization", "Bearer "+actualSelector.secret)
		response, err := selectorClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		var selection struct {
			Now string `json:"now"`
		}
		if err != nil || response.StatusCode != http.StatusOK || json.Unmarshal(body, &selection) != nil || selection.Now != store.LKG().View.Routes[0].ID {
			t.Fatal("actual selector readback changed or failed during preference reload")
		}
	}
	readSelector()
	if err := SetPreference(options.LocalState, "demo-network", clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeDirect}); err != nil {
		t.Fatal(err)
	}
	reload <- syscall.SIGHUP
	for {
		readback, err := ReadStatus(options.Status)
		if err == nil && readback.Preference.Mode == clientmodel.ModeDirect {
			if readback.ViewDigest != status.ViewDigest || len(readback.Selections) != 1 || readback.Selections[0].CandidateID != store.LKG().View.Routes[0].ID {
				t.Fatal("preference reload changed the certified authority or actual selector")
			}
			break
		}
		select {
		case err := <-done:
			stopped = true
			t.Fatalf("preference reload stopped the existing data plane: %v", err)
		case <-ctx.Done():
			t.Fatal("preference reload did not appear through runtime status")
		case <-time.After(20 * time.Millisecond):
		}
	}
	readSelector()
	if selectorConnections.Load() != 1 {
		t.Fatal("preference reload replaced the live selector API connection")
	}
	// A real selector blocks only this Service, keeps its process/API alive,
	// and can recover when a failed observation expires without a new View.
	routes, _, err := clientadapter.AccessProjection(store.LKG().View)
	if err != nil {
		t.Fatal(err)
	}
	local, err := LoadLocalState(options.LocalState, "demo-network")
	if err != nil {
		t.Fatal(err)
	}
	failed, err := Activate(ctx, actualSelector, routes, local, func(context.Context) ProbeResult { return ProbeResult{Action: "https_request"} }, options.Now)
	if !errors.Is(err, clientmodel.ErrNoUsableCandidate) || len(failed.Selections) != 0 {
		t.Fatal("failed Service remained selected", err)
	}
	if _, err := SaveObservations(options.LocalState, failed.State); err != nil {
		t.Fatal(err)
	}
	waitState := func(selected int, state string) {
		t.Helper()
		reload <- syscall.SIGHUP
		for {
			value, err := ReadStatus(options.Status)
			if err == nil && value.Runtime == "running" && len(value.Selections) == selected && len(value.Observations) == 1 && (selected == 0 || value.Selections[0].State == state) {
				return
			}
			select {
			case err := <-done:
				stopped = true
				t.Fatalf("business outcome stopped the data plane: %v", err)
			case <-ctx.Done():
				t.Fatal("business outcome did not reach runtime readback")
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	waitState(0, "")
	if response, err := requestTarget("demo-service.example", proxy); err == nil {
		response.Body.Close()
		if response.StatusCode < 400 {
			t.Fatal("failed Service was not actually blocked")
		}
	}
	clockAdvance.Store(int64(30 * time.Second))
	waitState(1, "unknown")
	response, err = requestTarget("demo-service.example", proxy)
	if err != nil {
		t.Fatal("expired observation did not recover actual HTTPS", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("recovered HTTPS request failed")
	}
	readSelector()
	if selectorConnections.Load() != 1 {
		t.Fatal("business failure or recovery replaced the data plane")
	}
	selectorTransport.CloseIdleConnections()
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		stopped = true
		t.Fatalf("Mixed shutdown failed: %v", err)
	}
	stopped = true
	if _, err := os.Stat(options.Status); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stopped Mixed runtime left a running status")
	}
	for _, address := range []string{"127.0.0.1:1080", "127.0.0.1:61800"} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal("stopped Mixed runtime retained its listener")
		}
		listener.Close()
	}
	after, err := exec.Command("ip", "-json", "route", "show", "table", "all").Output()
	if err != nil || !bytes.Equal(baseline, after) {
		t.Fatal("Mixed runtime changed the isolated route table")
	}
	t.Logf("isolated route table unchanged: %s", bytes.TrimSpace(after))
	interfaces, err = net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("Mixed runtime created a network interface")
	}
	t.Log("actual selector, IP CONNECT with authorized TLS name, rejected unmatched TLS name, preference reload without process restart and stop cleanup verified; report and service-wide health remain unverified")
}
