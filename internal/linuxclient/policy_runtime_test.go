package linuxclient

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"

	"golang.org/x/net/proxy"
)

// All sockets, processes and workloads stay in the dedicated test namespace.
func TestOfficialLinuxMixedPerServicePolicyChoice(t *testing.T) {
	binary := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if binary == "" {
		t.Skip("requires the reviewed data plane in a dedicated user/network namespace")
	}
	for _, kind := range []string{"user", "net"} {
		current, err := os.Stat("/proc/self/ns/" + kind)
		initial, initialErr := os.Stat("/proc/1/ns/" + kind)
		if err != nil || initialErr != nil || os.SameFile(current, initial) {
			t.Fatal("isolated namespace required")
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("fresh loopback-only namespace required")
	}
	if err := exec.Command("ip", "link", "set", "lo", "up").Run(); err != nil {
		t.Fatal(err)
	}
	echo := func(address string) net.Listener {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				go func() { defer connection.Close(); io.Copy(connection, connection) }()
			}
		}()
		return listener
	}
	api, domestic := echo("127.0.0.2:0"), echo("127.0.0.3:0")
	store, identityPath, makeView := linuxAcceptanceFixture(t, func(sequence uint64, view *control.DeviceView) {
		view.Services[0].Matchers = []control.ServiceMatcher{{Kind: "ip_prefix", Value: "127.0.0.2/32"}}
		service := view.Services[0]
		service.ID, service.Name, service.Matchers = "demo-service-b", "Demo domestic", []control.ServiceMatcher{{Kind: "ip_prefix", Value: "127.0.0.3/32"}}
		view.Services = append(view.Services, service)
		alternative, other := view.Policies[0], view.Policies[0]
		alternative.ID, alternative.Name = "demo-policy-alt", "Demo alternate"
		other.ID, other.Name, other.ServiceID = "demo-policy-domestic", "Demo domestic", service.ID
		if sequence == 7 {
			view.Policies = append(view.Policies, alternative)
			view.PolicyIDs = append(view.PolicyIDs, alternative.ID)
		}
		view.Policies = append(view.Policies, other)
		view.PolicyIDs = append(view.PolicyIDs, other.ID)
	})
	view := makeView(7, true)
	if err := store.SaveLKG(view); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	reload := make(chan os.Signal, 1)
	options := Options{DeviceState: identityPath, LocalState: filepath.Join(root, "runtime.json"), Status: filepath.Join(root, "status.json"),
		Config: filepath.Join(root, "config.json"), SingBox: binary, Capture: "mixed", RefreshPoll: time.Hour, Reload: reload,
		Generation: func() (string, error) { return "demo-network", nil }, Log: io.Discard}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, options) }()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			<-done
		}
	}()
	wait := func(digest, policy string, count int) Status {
		t.Helper()
		for {
			status, err := ReadStatus(options.Status)
			if err == nil && status.Runtime == "running" && status.ViewDigest == digest && status.Preference.PolicyID == policy && len(status.Selections) == count {
				return status
			}
			select {
			case err := <-done:
				stopped = true
				t.Fatal("runtime exited before policy readback", err)
			case <-ctx.Done():
				last, readErr := ReadStatus(options.Status)
				t.Fatalf("policy selection did not reach runtime: wanted %s, status=%+v, read=%v", policy, last, readErr)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	initial := wait(view.ViewDigest, "", 1)
	if initial.Preference.PolicyID != "demo-policy-domestic" {
		t.Fatal("singleton Service was not initialized")
	}
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	connect := func(listener net.Listener) net.Conn {
		t.Helper()
		connection, err := dialer.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { connection.Close() })
		return connection
	}
	check := func(connection net.Conn) {
		t.Helper()
		connection.SetDeadline(time.Now().Add(time.Second))
		if _, err := connection.Write([]byte("demo")); err != nil {
			t.Fatal(err)
		}
		body := make([]byte, 4)
		if _, err := io.ReadFull(connection, body); err != nil || string(body) != "demo" {
			t.Fatal("unrelated Service connection was interrupted", err)
		}
	}
	if pending, err := dialer.Dial("tcp", api.Addr().String()); err == nil {
		pending.SetDeadline(time.Now().Add(time.Second))
		pending.Write([]byte("demo"))
		_, err = pending.Read(make([]byte, 4))
		pending.Close()
		if err == nil {
			t.Fatal("pending Service bypassed its rejecting selector")
		}
	}
	domesticConnection := connect(domestic)
	check(domesticConnection)
	var previousAPI net.Conn
	for _, policy := range []string{"demo-policy", "demo-policy-alt"} {
		if err := store.SetPreference(clientmodel.Preference{Schema: 3, PolicyID: policy}); err != nil {
			t.Fatal(err)
		}
		reload <- syscall.SIGHUP
		status := wait(view.ViewDigest, policy, 2)
		if status.Preference.PolicyID != "demo-policy-domestic" {
			t.Fatal("policy choice changed another Service")
		}
		for _, selected := range status.Selections {
			if selected.Scope == "service:demo-service" && selected.PolicyID != policy {
				t.Fatal("saved choice was shown as applied without selector confirmation")
			}
		}
		check(domesticConnection)
		if previousAPI != nil {
			previousAPI.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := previousAPI.Read(make([]byte, 1)); err == nil {
				t.Fatal("changed Service connection stayed open")
			} else if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
				t.Fatal("changed Service connection was not closed")
			}
		}
		previousAPI = connect(api)
		check(previousAPI)
	}
	// Revoking the chosen policy leaves a pending record even with one remaining.
	revoked := makeView(8, true)
	if err := store.SaveLKG(revoked); err != nil {
		t.Fatal(err)
	}
	reload <- syscall.SIGHUP
	wait(revoked.ViewDigest, "", 1)
	cancel()
	if err := <-done; err != nil {
		stopped = true
		t.Fatal(err)
	}
	stopped = true
	local, err := loadLocalState(options.LocalState, "demo-network", revoked.ViewDigest)
	if err != nil || local.Preference.PolicyID != "" {
		t.Fatal("revoked policy was restored", err)
	}
	local, err = loadLocalState(options.LocalState, "demo-network", revoked.ViewDigest)
	if err != nil || local.Preference.PolicyID != "" {
		t.Fatal("restart automatically selected the remaining policy", err)
	}
}
