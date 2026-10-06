package linuxclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
)

// This exercises authentication and the actual receiver forwarding ACL, not
// WG transport. WG traversal and the signed report chain have separate checks.
func TestRealLinkProbeLoginHasNoForwardingPermission(t *testing.T) {
	executable := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if executable == "" {
		t.Skip("set LOOM_LINUX_MIXED_EXECUTABLE in a dedicated network namespace")
	}
	if err := requireDifferentNetworkNamespace("/proc/self/ns/net", "/proc/1/ns/net"); err != nil {
		t.Fatal(err)
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("requires a fresh loopback-only network namespace")
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"address", "add", "192.0.2.1/32", "dev", "lo"}, {"address", "add", "192.0.2.10/32", "dev", "lo"}} {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("isolated namespace setup: %v %s", err, output)
		}
	}
	view, inputPath, now := resourceExecutionFixture(t, time.Now())
	password := func(value string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(value, 32)))
	}
	probe := control.LinkProbeCredential{LinkID: "demo-link", Credential: password("p")}
	view.LinkProbeCredentials = []control.LinkProbeCredential{probe}
	keyA, keyB := password("a"), password("b")
	addressA, addressB := []string{"192.0.2.1/32"}, []string{"192.0.2.10/32"}
	source := control.TransportResource{ID: "demo-from-wg", Kind: "wireguard", OwnerNodeID: "demo-source", ListenerID: "lo", DialHost: "192.0.2.1", DialPort: 51820,
		Authentication: control.ResourceAuthentication{PublicKey: &keyA, LocalAddresses: &addressA}}
	destination := control.TransportResource{ID: "demo-to-wg", Kind: "wireguard", OwnerNodeID: "demo-exit", ListenerID: "wg-demo", DialHost: "192.0.2.10", DialPort: 51820,
		Authentication: control.ResourceAuthentication{PublicKey: &keyB, LocalAddresses: &addressB}}
	target := view.Resources[0]
	view.Resources = []control.TransportResource{source, target, destination}
	view.Links = []control.NetworkLink{{ID: probe.LinkID, FromNodeID: source.OwnerNodeID, ToNodeID: view.DeviceID, FromResourceID: source.ID, ResourceID: destination.ID,
		InitiatorNodeID: view.DeviceID, Purpose: "relay", ProbeTarget: control.LinkProbeTarget{ResourceID: target.ID, Host: "192.0.2.10", Port: 443, Action: "hysteria2_tls"}}}
	servicePassword := password("s")
	view.InboundCredentials = []control.InboundCredential{{DeviceID: "demo-access", ServiceID: "demo-service", PolicyID: "demo-policy", ResourceID: target.ID,
		ReceiverNodeID: view.DeviceID, Credential: servicePassword, AllowedTargets: []control.ServiceMatcher{{Kind: "ip_prefix", Value: "127.0.0.1/32"}}, ExcludedTargets: []control.ServiceMatcher{}}}
	dir := t.TempDir()
	start := func(name, config string) func() {
		t.Helper()
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := preflightRuntimeConfig(executable, config); err != nil {
			t.Fatal(err)
		}
		log, err := os.OpenFile(filepath.Join(dir, name+".log"), os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command(executable, "run", "-c", path)
		command.Stdout, command.Stderr = log, log
		if err := command.Start(); err != nil {
			log.Close()
			t.Fatal(err)
		}
		stopped := false
		stop := func() {
			if !stopped {
				stopped = true
				_ = command.Process.Kill()
				_ = command.Wait()
				_ = log.Close()
			}
		}
		t.Cleanup(stop)
		return stop
	}
	startReceiver := func(name string) func() {
		t.Helper()
		executions, err := prepareHY2Executions(view, inputPath, now)
		if err != nil {
			t.Fatal(err)
		}
		config, err := nodeRuntimeConfig(view, "demo-api", nil, "mixed", executions)
		if err != nil {
			t.Fatal(err)
		}
		return start(name, config)
	}
	stopReceiver := startReceiver("receiver")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		attempt, done := context.WithTimeout(ctx, 300*time.Millisecond)
		err := probeLink(attempt, source, target, "192.0.2.10:443", probe.Credential, now)
		done()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("actual Hy2 probe login did not succeed")
		}
	}
	for _, change := range []func(*control.TransportResource, *string){
		func(_ *control.TransportResource, value *string) { *value = password("x") },
		func(value *control.TransportResource, _ *string) {
			wrong := "wrong.example"
			value.Authentication.ServerName = &wrong
		},
	} {
		badTarget, credential := target, probe.Credential
		change(&badTarget, &credential)
		attempt, done := context.WithTimeout(context.Background(), time.Second)
		err := probeLink(attempt, source, badTarget, "192.0.2.10:443", credential, now)
		done()
		if err == nil {
			t.Fatal("wrong password or TLS name manufactured Link success")
		}
	}
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = io.WriteString(w, "demo-business") }))
	defer server.Close()
	trust, _ := control.HY2TrustPEM(target)
	requestThrough := func(name, credential string, allow bool) {
		t.Helper()
		document := map[string]any{"inbounds": []any{map[string]any{"type": "mixed", "listen": "127.0.0.1", "listen_port": 1080}},
			"outbounds": []any{map[string]any{"type": "hysteria2", "tag": "demo-out", "server": "192.0.2.10", "server_port": 443, "password": credential,
				"tls": map[string]any{"enabled": true, "server_name": *target.Authentication.ServerName, "certificate": trust}}}, "route": map[string]any{"final": "demo-out"}}
		body, _ := json.Marshal(document)
		stop := start(name, string(body))
		defer stop()
		proxy, _ := url.Parse("http://127.0.0.1:1080")
		transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
		defer transport.CloseIdleConnections()
		client := http.Client{Transport: transport, Timeout: time.Second}
		before := hits.Load()
		for deadline := time.Now().Add(3 * time.Second); ; {
			response, err := client.Get(server.URL)
			if err == nil {
				body, readErr := io.ReadAll(response.Body)
				response.Body.Close()
				if readErr == nil && response.StatusCode == 200 && string(body) == "demo-business" {
					if !allow {
						t.Fatal("probe-only user forwarded real business")
					}
					return
				}
			}
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		if allow || hits.Load() != before {
			t.Fatal("actual forwarding control or deny boundary failed")
		}
	}
	requestThrough("service-allowed", servicePassword, true)
	requestThrough("probe-denied", probe.Credential, false)
	stopReceiver()
	view.LinkProbeCredentials = nil
	stopReceiver = startReceiver("withdrawn")
	defer stopReceiver()
	requestThrough("service-after-withdrawal", servicePassword, true)
	attempt, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if probeLink(attempt, source, target, "192.0.2.10:443", probe.Credential, now) == nil {
		t.Fatal("withdrawn Link credential authenticated after receiver restart")
	}
}
