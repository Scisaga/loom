package linuxclient

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
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

// Normal Run consumes a persisted signed View, performs actual WG admission,
// applies the completion and serves ordinary business while another entry is
// silent. All interfaces, processes and workloads stay in a fresh namespace.
func TestOfficialLinuxMixedProgressiveFirstHopBusiness(t *testing.T) {
	executable := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the reviewed native executable in an isolated namespace")
	}
	business := isolatedPublicFixtureAddress(t)
	quiet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer quiet.Close()
	quietStarted := make(chan time.Time, 1)
	go func() {
		var packet [2048]byte
		if _, _, err := quiet.ReadFrom(packet[:]); err == nil {
			quietStarted <- time.Now()
		}
	}()
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "demo-progressive-ordinary-business")
	}))
	target.Listener.Close()
	target.Listener, err = net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	target.Start()
	defer target.Close()
	p, keys, _, _ := nativeProjectionFixture(t)
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registered := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	keyPath := filepath.Join(t.TempDir(), "sender.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(private.Bytes())), 0600); err != nil {
		t.Fatal(err)
	}
	p.NetworkIntent.Resources = slices.DeleteFunc(p.NetworkIntent.Resources, func(r control.TransportResource) bool { return r.Kind != "wireguard" })
	for i := range p.NetworkIntent.Resources {
		r := &p.NetworkIntent.Resources[i]
		r.DialHost = "127.0.0.1"
		if r.OwnerNodeID == "demo-exit" {
			r.AccessEnabled = true
		} else {
			r.DialPort = quiet.LocalAddr().(*net.UDPAddr).Port
		}
	}
	p.NetworkIntent.Policies[0].EntryScope = control.PolicyScope{Mode: "any", NodeIDs: []string{}}
	store, identityPath, makeView := linuxAcceptanceProjectionFixture(t, func(projection *control.Projection) {
		source := projection.DeviceAuthorizations[0]
		source.WireGuardPublicKey = registered
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
	exit, err := control.ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	exitExecution, err := control.ProjectDeviceExecution(exit, nil)
	if err != nil {
		t.Fatal(err)
	}
	exitConfig, err := appendNativeWireGuard(exitExecution.RuntimeProfile.Config, exit, fixtureWGReceiver(t, exit, fixtureWGExecutions(exit)), nil, keys["demo-exit"])
	if err != nil {
		t.Fatal(err)
	}
	if err := preflightRuntimeConfig(executable, exitConfig); err != nil {
		t.Fatal(err)
	}
	exitRoot := t.TempDir()
	exitPath := filepath.Join(exitRoot, "exit.json")
	if err := writeConfig(exitPath, exitConfig); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(exitRoot, "exit.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	budget, err := clientadapter.NewMeasurementBudget(clientadapter.MeasurementLimits{Window: time.Minute, Requests: 8, Concurrent: 2, Bytes: 64 << 10, Timeout: clientadapter.DefaultMeasurementTiming.RoundTimeout}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ctx = clientadapter.WithMeasurementBudget(ctx, budget)
	receiver := exec.CommandContext(ctx, executable, "run", "-c", exitPath)
	receiver.Dir, receiver.Stdout, receiver.Stderr = exitRoot, log, log
	if err := receiver.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = receiver.Process.Signal(os.Interrupt); _ = receiver.Wait() }()
	root := t.TempDir()
	options := Options{DeviceState: identityPath, LocalState: filepath.Join(root, "observations.json"), Status: filepath.Join(root, "status.json"),
		Config: filepath.Join(root, "config.json"), SingBox: executable, WireGuardPrivateKey: keyPath, Capture: "mixed", RefreshPoll: time.Hour,
		Generation: func() (string, error) { return "demo-underlay", nil }}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, options) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error("normal supervisor cleanup failed", err)
		}
	}()
	var quietAt time.Time
	select {
	case quietAt = <-quietStarted:
	case <-ctx.Done():
		t.Fatal("concurrent silent entry was never explored")
	}
	for {
		status, err := ReadStatus(options.Status)
		ready := false
		if err == nil {
			for _, sample := range status.ResourceObservations {
				if sample.ResourceID == "demo-entry-wg" {
					t.Fatal("first usable result waited for the silent entry")
				}
				ready = ready || sample.ResourceID == "demo-exit-wg" && sample.Result == "available"
			}
		}
		if ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual WG admission did not reach normal runtime readback")
		case <-time.After(10 * time.Millisecond):
		}
	}
	proxyURL := &url.URL{Scheme: "http", Host: "127.0.0.1:1080"}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(target.URL + "/ordinary-application")
	if err != nil {
		t.Fatal("first usable entry did not carry ordinary business", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "demo-progressive-ordinary-business" {
		t.Fatal("ordinary business returned a different result")
	}
	if time.Since(quietAt) >= clientadapter.DefaultMeasurementTiming.RoundTimeout {
		t.Fatal("business only succeeded after the independent measurement timeout")
	}
	t.Log("ordinary business completed before the concurrent silent entry deadline")
}
