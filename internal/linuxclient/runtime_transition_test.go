package linuxclient

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

// The normal supervisor consumes signed, persisted Views and current preference.
// Only isolated loopback is configured; no host network object is accessible.
func TestOfficialLinuxMixedAcceptedViewTransition(t *testing.T) {
	executable := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if executable == "" {
		t.Skip("set LOOM_LINUX_MIXED_EXECUTABLE in a dedicated user/network namespace")
	}
	business := isolatedPublicFixtureAddress(t)
	if err := exec.Command("ip", "address", "add", "192.0.2.53/32", "dev", "lo").Run(); err != nil {
		t.Fatal(err)
	}
	dns, err := net.ListenPacket("udp", "192.0.2.53:53")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	var resolved sync.Map
	go func() {
		var buffer [2048]byte
		for {
			n, peer, err := dns.ReadFrom(buffer[:])
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil || len(query.Questions) != 1 {
				continue
			}
			question := query.Questions[0]
			name := strings.TrimSuffix(question.Name.String(), ".")
			query.Response, query.RecursionAvailable = true, true
			if name == "demo-site.example" || name == "demo-dependency.example" {
				resolved.Store(name, true)
				if question.Type == dnsmessage.TypeA {
					query.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: business.As4()}}}
				}
			} else {
				query.RCode = dnsmessage.RCodeNameError
			}
			if response, err := query.Pack(); err == nil {
				_, _ = dns.WriteTo(response, peer)
			}
		}
	}()
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "demo-ordinary-business")
	}))
	target.Listener.Close()
	target.Listener, err = net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	target.Start()
	defer target.Close()
	echo, err := net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	store, path, makeView := linuxAcceptanceFixture(t, func(sequence uint64, view *control.DeviceView) {
		view.DNSServers = []string{"192.0.2.53"}
		if sequence >= 8 {
			view.Name = "Demo renamed device"
		}
		if sequence >= 9 {
			view.Policies[0].MaxHops = 1
		}
	})
	first, renamed, permission := makeView(7, true), makeView(8, true), makeView(9, true)
	if err := store.SaveLKG(first); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPreference(clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	options := Options{DeviceState: path, LocalState: filepath.Join(root, "runtime-state.json"), Status: filepath.Join(root, "status.json"),
		Config: filepath.Join(root, "config.json"), SingBox: executable, Capture: "mixed", RefreshPoll: 20 * time.Millisecond,
		Generation: func() (string, error) { return "demo-network", nil }}
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
	wait := func(digest string) {
		t.Helper()
		for {
			status, err := ReadStatus(options.Status)
			if err == nil && status.ViewDigest == digest && status.Runtime == "running" && len(status.Selections) == 1 {
				return
			}
			select {
			case err := <-done:
				stopped = true
				t.Fatal("supervisor exited before accepted View readback", err)
			case <-ctx.Done():
				t.Fatal("accepted View never reached runtime readback")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	wait(first.ViewDigest)
	// No probe URLs are configured. The website and persistent TCP stream must
	// still work through the selected Policy's normal Mixed entry.
	proxyURL, _ := url.Parse("http://127.0.0.1:1080")
	proxy := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer proxy.CloseIdleConnections()
	client := &http.Client{Transport: proxy, Timeout: time.Second}
	request := func() {
		t.Helper()
		for _, host := range []string{business.String(), "demo-site.example", "demo-dependency.example"} {
			address := "http://" + net.JoinHostPort(host, fmt.Sprint(target.Listener.Addr().(*net.TCPAddr).Port))
			response, err := client.Get(address + "/application-dependency")
			if err != nil {
				t.Fatal("ordinary unlisted business failed", err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != "demo-ordinary-business" {
				t.Fatalf("ordinary business returned another result: status=%d body=%q error=%v", response.StatusCode, body, err)
			}
		}
	}
	request()
	stream, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(time.Second))
	_, _ = fmt.Fprintf(stream, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.Addr(), echo.Addr())
	reader := bufio.NewReader(stream)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatal("ordinary TCP connection was not established", err)
	}
	exchange := func() {
		t.Helper()
		_ = stream.SetDeadline(time.Now().Add(time.Second))
		if _, err := stream.Write([]byte("demo")); err != nil {
			t.Fatal(err)
		}
		var reply [4]byte
		if _, err := io.ReadFull(reader, reply[:]); err != nil || string(reply[:]) != "demo" {
			t.Fatal("accepted configuration interrupted the persistent business connection", err)
		}
	}
	exchange()
	for _, next := range []control.DeviceViewEnvelope{renamed, permission} {
		if err := store.SaveLKG(next); err != nil {
			t.Fatal(err)
		}
		wait(next.ViewDigest)
		exchange()
		request()
	}
	for _, name := range []string{"demo-site.example", "demo-dependency.example"} {
		if _, ok := resolved.Load(name); !ok {
			t.Fatal("business domain bypassed the authenticated resolver")
		}
	}
	cancel()
	err = <-done
	stopped = true
	status, readErr := ReadStatus(options.Status)
	restarted, stateErr := deviceclient.Load(path)
	if err != nil || readErr != nil || stateErr != nil || status.Runtime != "stopped" || status.ViewDigest != permission.ViewDigest || restarted.LKG().ViewDigest != permission.ViewDigest || restarted.PublicKey() != store.PublicKey() {
		t.Fatal("normal stop lost runtime readback or accepted identity", err, readErr, stateErr)
	}
	for _, address := range []string{"127.0.0.1:1080", "127.0.0.1:61800"} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal("supervisor stop retained a data-plane listener")
		}
		listener.Close()
	}
}
