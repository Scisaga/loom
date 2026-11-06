package linuxclient

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

// The actual fixed key is consumed after the receiving resource is deleted.
// Both WG endpoints are userspace and all traffic stays on private loopback.
func TestRegisteredFixedWireGuardSenderWorksWithoutReceivingResource(t *testing.T) {
	executable := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the exact executable in separate user/network namespaces")
	}
	business := isolatedPublicFixtureAddress(t)
	listener, err := net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "demo-fixed-wg-business") }))
	target.Listener.Close()
	target.Listener = listener
	target.Start()
	defer target.Close()
	p, keys, _, _ := nativeProjectionFixture(t)
	before, err := control.ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	p.DeviceAuthorizations[1].Responsibilities = []string{"access", "forward"}
	p.DeviceAuthorizations[1].PolicyIDs = []string{"demo-policy"}
	p.NetworkIntent.Resources = slices.DeleteFunc(p.NetworkIntent.Resources, func(value control.TransportResource) bool { return value.ID != "demo-exit-wg" })
	p.NetworkIntent.Resources[0].DialHost = "127.0.0.1"
	source, err := control.ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	if source.WireGuardPublicKey != before.WireGuardPublicKey || source.WireGuardPrivateKey != "" {
		t.Fatal("resource deletion changed the registered fixed sender")
	}
	exit, err := control.ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	sourceConfig, err := nodeRuntimeConfig(source, "demo-local", nil, "mixed", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appendNativeWireGuard(sourceConfig, source, wireGuardExecution{}, nil, keys["demo-exit"]); err == nil {
		t.Fatal("wrong local key acquired the registered identity")
	}
	sourceConfig, err = appendNativeWireGuard(sourceConfig, source, wireGuardExecution{}, nil, keys["demo-entry"])
	if err != nil {
		t.Fatal(err)
	}
	var sourceDocument struct {
		Endpoints []map[string]json.RawMessage `json:"endpoints"`
	}
	if json.Unmarshal([]byte(sourceConfig), &sourceDocument) != nil || len(sourceDocument.Endpoints) != 1 || sourceDocument.Endpoints[0]["listen_port"] != nil || sourceDocument.Endpoints[0]["execution"] != nil {
		t.Fatal("outgoing-only WG retained receiving authority")
	}
	execution, err := control.ProjectDeviceExecution(exit, nil)
	if err != nil {
		t.Fatal(err)
	}
	exitConfig, err := appendNativeWireGuard(execution.RuntimeProfile.Config, exit, fixtureWGReceiver(t, exit, fixtureWGExecutions(exit)), nil, keys["demo-exit"])
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := func(name, config string) {
		t.Helper()
		if err := preflightRuntimeConfig(executable, config); err != nil {
			t.Fatal(name, err)
		}
		root := t.TempDir()
		path := filepath.Join(root, "config.json")
		if err := writeConfig(path, config); err != nil {
			t.Fatal(err)
		}
		log, err := os.OpenFile(filepath.Join(root, "runtime.log"), os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, executable, "run", "-c", path)
		command.Dir, command.Stdout, command.Stderr = root, log, log
		if err := command.Start(); err != nil {
			log.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = command.Process.Signal(os.Interrupt); _ = command.Wait(); _ = log.Close() })
	}
	start("exit", exitConfig)
	start("source", sourceConfig)
	selector, err := clientadapter.NewHTTPSelector(sourceConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientadapter.WaitSelector(ctx, selector, []string{control.AccessSelectorScope}); err != nil {
		t.Fatal(err)
	}
	routes, err := clientadapter.AccessCandidates(source, []string{"demo-policy"})
	if err != nil || len(routes) != 1 {
		t.Fatal("expected only the fixed-exit forward choice", err)
	}
	activation, err := clientadapter.Activate(ctx, selector, routes, clientadapter.State{Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-network-generation"}, nil, time.Now, control.AccessSelectorScope)
	if err != nil || len(activation.Selections) != 1 {
		t.Fatal("normal selection failed", err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1080"}), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for {
		response, requestErr := client.Get(target.URL + "/ordinary-application")
		if requestErr == nil {
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK && string(body) == "demo-fixed-wg-business" {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("ordinary request through the registered fixed WG sender failed")
		case <-time.After(25 * time.Millisecond):
		}
	}
}
