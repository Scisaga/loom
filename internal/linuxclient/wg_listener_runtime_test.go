package linuxclient

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

// The formal supervisor consumes the sole accepted View and local listener
// input. A failed local bind must not revive removed policies or replace the
// unchanged native process, Hy2 listener and an already established TCP stream.
func TestOfficialLinuxWGListenerFailureKeepsHy2AndTCPThenRecovers(t *testing.T) {
	testOfficialLinuxWGListenerRuntime(t, false)
}

func TestOfficialLinuxEntryScopeExpansionKeepsNativeAndExistingTCP(t *testing.T) {
	testOfficialLinuxWGListenerRuntime(t, true)
}

func testOfficialLinuxWGListenerRuntime(t *testing.T, entryScopeExpansion bool) {
	executable := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the native data plane in a dedicated loopback-only namespace")
	}
	business := isolatedPublicFixtureAddress(t)
	freshPort := func() int {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal("fixture UDP socket could not be created")
		}
		port := socket.LocalAddr().(*net.UDPAddr).Port
		if err := socket.Close(); err != nil {
			t.Fatal("fixture UDP socket did not close")
		}
		return port
	}
	wgPort, hy2Port := freshPort(), freshPort()
	for wgPort == 40000 || wgPort == 40001 {
		wgPort = freshPort()
	}
	for hy2Port == wgPort {
		hy2Port = freshPort()
	}
	blocked, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("fixture conflict socket could not be created")
	}
	defer blocked.Close()
	blockedPort := blocked.LocalAddr().(*net.UDPAddr).Port
	for blockedPort == wgPort || blockedPort == hy2Port {
		_ = blocked.Close()
		blocked, err = net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal("fixture conflict socket could not be created")
		}
		blockedPort = blocked.LocalAddr().(*net.UDPAddr).Port
	}
	hy2, input, at := resourceExecutionFixture(t, time.Now())
	var inputs ResourceInputs
	if err := readStrict(input, 1<<20, &inputs); err != nil {
		t.Fatal(err)
	}
	inputs.Listeners[0].Listen = net.JoinHostPort("127.0.0.1", strconv.Itoa(hy2Port))
	inputs.Listeners = append(inputs.Listeners, ResourceListenerInput{ResourceID: "demo-wg", ListenPort: wgPort})
	if err := atomicJSON(input, inputs); err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("demo-local-wg-listener"))
	seed[0] &= 248
	seed[31] = (seed[31] & 127) | 64
	wgKey, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	wgPublic := base64.RawURLEncoding.EncodeToString(wgKey.PublicKey().Bytes())
	keyPath := filepath.Join(t.TempDir(), "node.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(seed[:])), 0600); err != nil {
		t.Fatal(err)
	}
	store, path, makeView := linuxAcceptanceProjectionFixture(t, func(p *control.Projection) { p.DeviceAuthorizations[0].WireGuardPublicKey = wgPublic }, func(sequence uint64, view *control.DeviceView) {
		view.Responsibilities = []string{"access", "forward", "internet_egress"}
		resource := hy2.Resources[0]
		resource.OwnerNodeID = view.DeviceID
		local := []string{"192.0.2.51/32"}
		publicPort := 40000
		if sequence >= 8 && !entryScopeExpansion {
			publicPort++
		}
		view.Resources = []control.TransportResource{resource, {ID: "demo-wg", Kind: "wireguard", OwnerNodeID: view.DeviceID, ListenerID: "demo-wg-listener", DialHost: "192.0.2.10", DialPort: publicPort, Authentication: control.ResourceAuthentication{PublicKey: &wgPublic, LocalAddresses: &local}}}
		spare := view.Services[0]
		spare.ID, spare.Name = "demo-spare", "Demo spare"
		policy := view.Policies[0]
		policy.ID, policy.Name, policy.ServiceID = "demo-spare-policy", "Demo spare policy", spare.ID
		if entryScopeExpansion && sequence < 8 {
			policy.EntryScope = control.PolicyScope{Mode: "only", NodeIDs: []string{view.DeviceID}}
		}
		view.Services = append(view.Services, spare)
		view.Policies = append(view.Policies, policy)
		if sequence < 8 || entryScopeExpansion {
			// Withdraw only this access node's unused grant. The shared
			// forward/egress facilities remain useful to other origins.
			view.PolicyIDs = append(view.PolicyIDs, policy.ID)
		}
	})
	first, next := makeView(7, true), makeView(8, true)
	if err := store.SaveLKG(first); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPreference(clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	log, err := os.OpenFile(filepath.Join(root, "runtime.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	reload := make(chan os.Signal, 1)
	options := Options{DeviceState: path, LocalState: filepath.Join(root, "local.json"), Status: filepath.Join(root, "status.json"), Config: filepath.Join(root, "config.json"), SingBox: executable, Capture: "mixed", ResourceInputs: input, WireGuardPrivateKey: keyPath, RefreshPoll: 20 * time.Millisecond, Reload: reload, Log: log, Generation: func() (string, error) { return "demo-network", nil }}
	if err := PreflightResources(path, executable, "mixed", input, keyPath); err != nil {
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			t.Log("fixture preflight:", cause)
		}
		t.Fatal("formal fixture preflight failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		err := Run(ctx, options)
		// The fixture owns this private log. Retain the causal error before
		// TempDir cleanup so a status timeout cannot hide an earlier failure.
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			fmt.Fprintln(log, "fixture runtime result:", cause)
		}
		done <- err
	}()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			<-done
		}
	}()
	wait := func(predicate func(Status) bool) Status {
		t.Helper()
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for {
			status, err := ReadStatus(options.Status)
			if err == nil && predicate(status) {
				return status
			}
			select {
			case <-done:
				stopped = true
				t.Fatal("formal runtime exited before the required local readback")
			case <-deadline.C:
				t.Fatal("formal runtime did not reach the expected listener confirmation")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	listen := func(status Status, port int) bool {
		for _, value := range status.Resources {
			if value.ResourceID == "demo-wg" {
				host, text, err := net.SplitHostPort(value.Listen)
				return err == nil && (host == "0.0.0.0" || host == "::") && text == strconv.Itoa(port)
			}
		}
		return false
	}
	wait(func(status Status) bool {
		return status.Runtime == "running" && status.ViewDigest == first.ViewDigest && listen(status, wgPort)
	})
	pid := officialNativeChildPID(t, executable)
	configuration, err := os.ReadFile(options.Config)
	if err != nil {
		t.Fatal(err)
	}
	assertOfficialAccessPolicies(t, configuration, []string{"demo-policy", "demo-spare-policy"})
	diagnostic, err := clientadapter.WithNativeDiagnostic(ctx, string(configuration), nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := clientadapter.ObserveWireGuardCounters(diagnostic, first.View, time.Now)
	if err != nil || before == nil {
		t.Fatal("initial WG epoch was not readable")
	}
	echo, err := net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal("isolated business socket could not be created")
	}
	defer echo.Close()
	go func() {
		for {
			stream, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer stream.Close(); _, _ = io.Copy(stream, stream) }()
		}
	}()
	stream, err := net.DialTimeout("tcp", "127.0.0.1:1080", time.Second)
	if err != nil {
		t.Fatal("formal Mixed entry was not reachable")
	}
	defer stream.Close()
	_, _ = fmt.Fprintf(stream, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.Addr().String(), echo.Addr().String())
	reader := bufio.NewReader(stream)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatal("ordinary policy business connection failed")
	}
	checkStream := func(text string) {
		t.Helper()
		_ = stream.SetDeadline(time.Now().Add(time.Second))
		if _, err := io.WriteString(stream, text); err != nil {
			t.Fatal("existing business connection was closed")
		}
		body := make([]byte, len(text))
		if _, err := io.ReadFull(reader, body); err != nil || string(body) != text {
			t.Fatal("same TCP stream stopped carrying business")
		}
	}
	checkStream("demo-before-update")
	other, err := deviceclient.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.SaveLKG(next); err != nil {
		t.Fatal(err)
	}
	reload <- syscall.SIGHUP
	wait(func(status Status) bool {
		return status.Runtime == "running" && status.ViewDigest == next.ViewDigest && listen(status, wgPort)
	})
	configuration, err = os.ReadFile(options.Config)
	if err != nil {
		t.Fatal(err)
	}
	if entryScopeExpansion {
		assertOfficialAccessPolicies(t, configuration, []string{"demo-policy", "demo-spare-policy"})
		checkStream("demo-after-entry-expansion")
		if officialNativeChildPID(t, executable) != pid {
			t.Fatal("entry permission expansion replaced unchanged native facilities")
		}
		cancel()
		err := <-done
		stopped = true
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal("entry expansion runtime did not stop normally", err)
		}
		return
	}
	assertOfficialAccessPolicies(t, configuration, []string{"demo-policy"})
	for i := range inputs.Listeners {
		if inputs.Listeners[i].ResourceID == "demo-wg" {
			inputs.Listeners[i].ListenPort = blockedPort
		}
	}
	if err := atomicJSON(input, inputs); err != nil {
		t.Fatal(err)
	}
	reload <- syscall.SIGHUP
	unknown := wait(func(status Status) bool { return status.Runtime == "unknown" && status.ViewDigest == next.ViewDigest })
	if len(unknown.Resources) != 0 || len(unknown.Selections) != 0 || unknown.Reported {
		t.Fatal("unconfirmed WG update retained current resource/selection proof")
	}
	checkStream("demo-during-bind-failure")
	if officialNativeChildPID(t, executable) != pid {
		t.Fatal("local WG port failure replaced the shared native process")
	}
	currentExecutions, err := prepareResourceExecutions(next.View, input, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, execution := range currentExecutions {
		if execution.resource.Kind == "hysteria2" {
			if _, err := execution.readback(ctx, pid, time.Now()); err != nil {
				t.Fatal("WG bind failure stopped the unchanged Hy2 listener")
			}
		}
	}
	if err := blocked.Close(); err != nil {
		t.Fatal(err)
	}
	reload <- syscall.SIGHUP
	wait(func(status Status) bool {
		return status.Runtime == "running" && status.ViewDigest == next.ViewDigest && listen(status, blockedPort)
	})
	checkStream("demo-after-recovery")
	after, err := clientadapter.ObserveWireGuardCounters(diagnostic, next.View, time.Now)
	if err != nil || after == nil || after.Epoch != before.Epoch {
		t.Fatal("recovery replaced the WG device or counter epoch")
	}
	if officialNativeChildPID(t, executable) != pid {
		t.Fatal("same-View listener recovery replaced the native process")
	}
	configuration, err = os.ReadFile(options.Config)
	if err != nil {
		t.Fatal(err)
	}
	assertOfficialAccessPolicies(t, configuration, []string{"demo-policy"})
}

func assertOfficialAccessPolicies(t *testing.T, configuration []byte, want []string) {
	t.Helper()
	var document struct {
		Outbounds []struct {
			Tag    string `json:"tag"`
			Access *struct {
				Policies []struct {
					Policy struct {
						ID string `json:"policy_id"`
					} `json:"policy"`
				} `json:"policies"`
			} `json:"access"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(configuration, &document); err != nil {
		t.Fatal(err)
	}
	forward := false
	var policies []string
	for _, outbound := range document.Outbounds {
		if outbound.Tag == control.ForwardSelectorTag("demo-spare-policy") {
			forward = true
		}
		if outbound.Tag == control.AccessSelectorScope && outbound.Access != nil {
			for _, policy := range outbound.Access.Policies {
				policies = append(policies, policy.Policy.ID)
			}
		}
	}
	if !slices.Equal(policies, want) || !forward {
		t.Fatal("local access grants or shared forwarding facilities differ from the current View")
	}
}

func officialNativeChildPID(t *testing.T, executable string) int {
	t.Helper()
	want, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := filepath.Glob("/proc/self/task/*/children")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, task := range tasks {
		body, err := os.ReadFile(task)
		if err != nil {
			continue
		}
		for _, text := range strings.Fields(string(body)) {
			pid, err := strconv.Atoi(text)
			if err != nil {
				continue
			}
			actual, err := os.Stat(filepath.Join("/proc", text, "exe"))
			if err == nil && os.SameFile(want, actual) {
				seen[pid] = true
			}
		}
	}
	if len(seen) != 1 {
		t.Fatal("the exact supervised native process was not singular")
	}
	for pid := range seen {
		return pid
	}
	return 0
}
