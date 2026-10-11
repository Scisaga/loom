package linuxclient

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

// Both real private TLS requests remain unanswered. The public supervisor
// must still start, serve HTTPS, process local input, accept a durable
// revocation, cancel those requests and stop with the same protected identity.
func TestOfficialLinuxMixedSlowPrivateRequests(t *testing.T) {
	executable := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if executable == "" {
		t.Skip("set LOOM_LINUX_MIXED_EXECUTABLE in a dedicated user/network namespace")
	}
	for _, kind := range []string{"user", "net"} {
		current, err := os.Stat("/proc/self/ns/" + kind)
		initial, initialErr := os.Stat("/proc/1/ns/" + kind)
		if err != nil || initialErr != nil || os.SameFile(current, initial) {
			t.Fatal("real Mixed test requires separate user and network namespaces")
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("real Mixed test requires only isolated loopback")
	}
	if err := exec.Command("ip", "link", "set", "lo", "up").Run(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.WaitGroup
	var active atomic.Int32
	var accepted atomic.Int32
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			active.Add(1)
			accepted.Add(1)
			go func() {
				defer connections.Done()
				defer active.Add(-1)
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
				_, _ = io.Copy(io.Discard, connection)
			}()
		}
	}()
	defer func() {
		listener.Close()
		<-acceptDone
		connections.Wait()
	}()
	target := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "demo-authorized-business")
	}))
	defer target.Close()
	store, path, makeView := linuxAcceptanceFixture(t, func(_ uint64, view *control.DeviceView) {
		view.Endpoints[0].Host = "127.0.0.1"
		view.Endpoints[0].Port = listener.Addr().(*net.TCPAddr).Port
		if len(view.Services) != 0 {
			view.Services[0].Matchers = []control.ServiceMatcher{{Kind: "ip_prefix", Value: "127.0.0.1/32"}}
		}
	})
	first, revoked := makeView(7, true), makeView(8, false)
	if err := store.SaveLKG(first); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	reload := make(chan os.Signal, 1)
	var generation atomic.Value
	generation.Store("demo-before")
	options := Options{DeviceState: path, LocalState: filepath.Join(root, "local.json"), Status: filepath.Join(root, "status.json"),
		Config: filepath.Join(root, "config.json"), SingBox: executable, Capture: "mixed", RefreshPoll: time.Hour,
		Reload: reload, Generation: func() (string, error) { return generation.Load().(string), nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	done := make(chan error, 1)
	go func() { done <- Run(ctx, options) }()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			<-done
		}
	}()
	wait := func(predicate func(Status) bool) Status {
		t.Helper()
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		for {
			status, err := ReadStatus(options.Status)
			if err == nil && predicate(status) {
				return status
			}
			select {
			case err := <-done:
				stopped = true
				t.Fatal("supervisor stopped before local readback", err)
			case <-deadline.C:
				t.Fatal("slow private request blocked local runtime progress")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	wait(func(status Status) bool { return status.Runtime == "running" && active.Load() == 2 })
	proxy, _ := url.Parse("http://127.0.0.1:1080")
	client := target.Client()
	client.Timeout = time.Second
	client.Transport.(*http.Transport).Proxy = http.ProxyURL(proxy)
	client.Transport.(*http.Transport).DisableKeepAlives = true
	defer client.CloseIdleConnections()
	request := func() bool {
		t.Helper()
		response, err := client.Get(target.URL)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return err == nil && response.StatusCode == http.StatusOK && string(body) == "demo-authorized-business"
	}
	if !request() {
		t.Fatal("authorized HTTPS failed while management requests were waiting")
	}
	generation.Store("demo-after")
	if err := SetPreference(options.LocalState, "demo-after", clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeDirect}); err != nil {
		t.Fatal(err)
	}
	reload <- syscall.SIGHUP
	status := wait(func(status Status) bool {
		return status.Runtime == "running" && status.NetworkGeneration == "demo-after" && status.Preference.Mode == clientmodel.ModeDirect
	})
	if status.Reported || accepted.Load() != 2 || !request() {
		t.Fatal("local change waited for management, overlapped requests or invented report acknowledgement")
	}
	if err := store.SaveLKG(revoked); err != nil {
		t.Fatal(err)
	}
	reload <- syscall.SIGHUP
	wait(func(status Status) bool {
		return status.Runtime == "running" && status.ViewDigest == revoked.ViewDigest && len(status.Selections) == 0
	})
	if request() {
		t.Fatal("accepted revocation retained old business authorization")
	}
	cancel()
	err = <-done
	stopped = true
	status, readErr := ReadStatus(options.Status)
	restarted, loadErr := deviceclient.Load(path)
	if err != nil || readErr != nil || loadErr != nil || status.Runtime != "stopped" || status.ViewDigest != revoked.ViewDigest ||
		restarted.PublicKey() != store.PublicKey() || !reflect.DeepEqual(restarted.LKG(), &revoked) {
		t.Fatal("stop did not preserve accepted revocation and identity", err, readErr, loadErr)
	}
	for _, address := range []string{"127.0.0.1:1080", "127.0.0.1:61800"} {
		probe, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal("stop left a data-plane listener")
		}
		probe.Close()
	}
	t.Log("unanswered private configuration/report TLS, actual HTTPS, local generation/preference, durable revocation and cancellation cleanup verified")
}
