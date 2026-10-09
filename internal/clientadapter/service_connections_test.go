package clientadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestServiceConnectionsRequireActualScopeAndExactIdentity(t *testing.T) {
	body := []byte(`{"connections":[{"id":"00000000-0000-0000-0000-000000000001","chains":["demo-shared-exit","service:demo-a"]},{"id":"00000000-0000-0000-0000-000000000002","chains":["demo-shared-exit","service:demo-b"]},{"id":"00000000-0000-0000-0000-000000000003","chains":["demo-shared-exit"]}]}`)
	ids, err := ServiceConnectionIDs(body, []string{"service:demo-b"})
	if err != nil || !reflect.DeepEqual(ids, []string{"00000000-0000-0000-0000-000000000002"}) {
		t.Fatal("shared exit was mistaken for Service ownership", ids, err)
	}
	for _, bad := range []string{`{}`, `{"connections":{}}`, `{"connections":[{"id":"../","chains":["service:demo-b"]}]}`} {
		if _, err := ServiceConnectionIDs([]byte(bad), []string{"service:demo-b"}); err == nil {
			t.Fatal("invalid connection evidence was accepted")
		}
	}
}

// Loopback Mixed only. No host TUN, routing, DNS or firewall objects are created.
func TestRealServiceSwitchPreservesOtherServiceConnection(t *testing.T) {
	executable := os.Getenv("LOOM_TUN_ROUTING_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the reviewed data-plane executable")
	}
	listen := func() net.Listener {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		return listener
	}
	echo := func() net.Listener {
		listener := listen()
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
	a, b := echo(), echo()
	controller, mixed := listen(), listen()
	controllerAddress, mixedAddress := controller.Addr().String(), mixed.Addr().String()
	controller.Close()
	mixed.Close()
	config := map[string]any{
		"inbounds": []any{map[string]any{"type": "mixed", "tag": "demo-mixed", "listen": "127.0.0.1", "listen_port": mixed.Addr().(*net.TCPAddr).Port}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "demo-direct"}, map[string]any{"type": "block", "tag": "reject"},
			map[string]any{"type": "selector", "tag": "service:demo-a", "outbounds": []string{"demo-direct", "reject"}, "default": "demo-direct"},
			map[string]any{"type": "selector", "tag": "service:demo-b", "outbounds": []string{"demo-direct", "reject"}, "default": "demo-direct"}},
		"route":        map[string]any{"final": "reject", "rules": []any{map[string]any{"port": []int{a.Addr().(*net.TCPAddr).Port}, "outbound": "service:demo-a"}, map[string]any{"port": []int{b.Addr().(*net.TCPAddr).Port}, "outbound": "service:demo-b"}}},
		"experimental": map[string]any{"clash_api": map[string]any{"external_controller": controllerAddress, "secret": "demo-local-secret"}},
	}
	body, _ := json.Marshal(config)
	file := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(file, body, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "run", "-c", file)
	var log bytes.Buffer
	command.Stdout, command.Stderr = &log, &log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = command.Wait() })
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", controllerAddress)
	}}
	defer transport.CloseIdleConnections()
	selector := &HTTPSelector{secret: "demo-local-secret", client: &http.Client{Transport: transport, Timeout: time.Second}}
	if err := WaitSelector(ctx, selector, []string{"service:demo-a", "service:demo-b"}); err != nil {
		t.Fatal(err)
	}
	dial, err := proxy.SOCKS5("tcp", mixedAddress, nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	connect := func(address string) net.Conn {
		t.Helper()
		connection, err := dial.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { connection.Close() })
		return connection
	}
	first, second := connect(a.Addr().String()), connect(b.Addr().String())
	check := func(connection net.Conn) {
		t.Helper()
		connection.SetDeadline(time.Now().Add(time.Second))
		if _, err := connection.Write([]byte("demo")); err != nil {
			t.Fatal("working connection was interrupted", err)
		}
		value := make([]byte, 4)
		if _, err := io.ReadFull(connection, value); err != nil || string(value) != "demo" {
			t.Fatal("working connection was interrupted", err)
		}
	}
	check(first)
	check(second)
	if _, err := ApplySelections(ctx, selector, map[string]string{"service:demo-b": BlockedSelection}); err != nil {
		t.Fatal(err)
	}
	check(first)
	second.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("old changed-Service connection survived rejection")
	} else if failure, ok := err.(net.Error); ok && failure.Timeout() {
		t.Fatal("changed-Service connection was not closed")
	}
	if _, err := ApplySelections(ctx, selector, map[string]string{"service:demo-b": "demo-direct"}); err != nil {
		t.Fatal(err)
	}
	check(first)
	check(connect(b.Addr().String()))
}
