package linuxclient

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"loom/internal/control"
)

// This exercises the public supervisor, accepted persistent Views, the real
// data plane and its default HTTPS probe. The self-signed target deliberately
// produces an actual TLS failure whose original expiry must survive a rename.
func TestOfficialLinuxMixedAcceptedViewTransition(t *testing.T) {
	executable := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if executable == "" {
		t.Skip("set LOOM_LINUX_MIXED_EXECUTABLE in a dedicated user/network namespace")
	}
	for _, kind := range []string{"user", "net"} {
		current, err := os.Stat("/proc/self/ns/" + kind)
		initial, initialErr := os.Stat("/proc/1/ns/" + kind)
		if err != nil || initialErr != nil || os.SameFile(current, initial) {
			t.Fatal("real Mixed transition requires separate user and network namespaces")
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("real Mixed transition requires only isolated loopback")
	}
	if err := exec.Command("ip", "link", "set", "lo", "up").Run(); err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("untrusted TLS target received an authenticated HTTP request")
	}))
	target.Config.ErrorLog = log.New(io.Discard, "", 0)
	target.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			attempts.Add(1)
		}
	}
	target.StartTLS()
	defer target.Close()
	store, path, makeView := linuxAcceptanceFixture(t, func(sequence uint64, view *control.DeviceView) {
		if sequence > 7 {
			view.Name = "Demo renamed device"
		}
		if len(view.Services) != 0 {
			view.Services[0].Matchers = []control.ServiceMatcher{{Kind: "ip_prefix", Value: "127.0.0.1/32"}}
			view.BusinessProbeTargets = []control.ServiceProbeTargets{{ServiceID: "demo-service", Targets: []string{target.URL + "/"}}}
		}
	})
	first, renamed, revoked := makeView(7, true), makeView(8, true), makeView(9, false)
	if err := store.SaveLKG(first); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	reload := make(chan os.Signal, 1)
	at := time.Now()
	options := Options{DeviceState: path, LocalState: filepath.Join(root, "runtime-state.json"), Status: filepath.Join(root, "status.json"),
		Config: filepath.Join(root, "config.json"), SingBox: executable, Capture: "mixed", RefreshPoll: time.Hour, Reload: reload,
		Generation: func() (string, error) { return "demo-network", nil }, Now: func() time.Time { return at }}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	done := make(chan error, 1)
	go func() { done <- Run(ctx, options) }()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			<-done
		}
	}()
	wait := func(digest string, observations int) Status {
		t.Helper()
		for {
			status, err := ReadStatus(options.Status)
			if err == nil && status.ViewDigest == digest && status.Runtime == "running" && len(status.Observations) == observations {
				return status
			}
			select {
			case err := <-done:
				stopped = true
				t.Fatal("supervisor exited before accepted View readback", err)
			case <-ctx.Done():
				t.Fatal("accepted View never reached runtime readback")
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	original := wait(first.ViewDigest, 1)
	if attempts.Load() != 1 || len(original.Selections) != 0 || original.Observations[0].Result != "unavailable" {
		t.Fatal("fixture did not record a real failed HTTPS request")
	}
	if err := store.SaveLKG(renamed); err != nil {
		t.Fatal(err)
	}
	reload <- syscall.SIGHUP
	actual := wait(renamed.ViewDigest, 1)
	if attempts.Load() != 1 || len(actual.Selections) != 0 || !reflect.DeepEqual(original.Observations, actual.Observations) {
		t.Fatal("unrelated accepted View retried or renewed valid failure evidence")
	}
	if err := store.SaveLKG(revoked); err != nil {
		t.Fatal(err)
	}
	reload <- syscall.SIGHUP
	actual = wait(revoked.ViewDigest, 0)
	if len(actual.Selections) != 0 || attempts.Load() != 1 {
		t.Fatal("revocation retained or executed the old candidate")
	}
	cancel()
	err = <-done
	stopped = true
	status, readErr := ReadStatus(options.Status)
	if err != nil || readErr != nil || status.Runtime != "stopped" || status.ViewDigest != revoked.ViewDigest {
		t.Fatal("supervisor did not stop with the accepted revocation", err, readErr)
	}
	for _, address := range []string{"127.0.0.1:1080", "127.0.0.1:61800"} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal("supervisor stop retained a data-plane listener")
		}
		listener.Close()
	}
}
