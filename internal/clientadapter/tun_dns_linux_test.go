//go:build linux

package clientadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The DNS listener is loopback-only and has no TUN or route privileges. This
// exercises the real cache across abrupt exits, not a replica of its allocator.
func TestTUNDomainDNSCrashRecovery(t *testing.T) {
	executable := os.Getenv("LOOM_TUN_ROUTING_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the exact data-plane executable")
	}
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	address := listener.LocalAddr().String()
	_ = listener.Close()
	apiListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	api := apiListener.Addr().String()
	_ = apiListener.Close()
	root := t.TempDir()
	config := map[string]any{
		"inbounds": []any{map[string]any{"type": "direct", "tag": "tun-in", "listen": "127.0.0.1", "listen_port": port}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "demo-underlay"}, map[string]any{"type": "block", "tag": "reject"},
			map[string]any{"type": "direct", "tag": "demo-first"}, map[string]any{"type": "direct", "tag": "demo-next"},
			map[string]any{"type": "selector", "tag": "demo-selector", "outbounds": []string{"demo-first", "demo-next"}, "default": "demo-first"}},
		"route": map[string]any{"final": "reject", "rules": []any{
			map[string]any{"inbound": []string{"tun-in"}, "action": "hijack-dns"},
			map[string]any{"domain_suffix": []string{"demo.example"}, "outbound": "reject"},
		}},
		"dns":          map[string]any{"servers": []any{map[string]any{"tag": "demo-resolver", "address": "192.0.2.53", "detour": "demo-underlay"}}},
		"experimental": map[string]any{"clash_api": map[string]any{"external_controller": api, "secret": "demo-local"}},
	}
	body, _ := json.Marshal(config)
	derived, err := WithTUNDomainDNS(string(body))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config.json")
	if err := os.WriteFile(path, []byte(derived), 0o600); err != nil {
		t.Fatal(err)
	}
	query := func(name string) string {
		t.Helper()
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addresses, err := resolver.LookupIP(ctx, "ip4", name+".demo.example")
		if err != nil || len(addresses) != 1 {
			t.Fatalf("query %s: %v %v", name, addresses, err)
		}
		return addresses[0].String()
	}
	values := map[string]string{}
	selection := func(method string) string {
		t.Helper()
		request, err := http.NewRequest(method, "http://"+api+"/proxies/demo-selector", bytes.NewBufferString(`{"name":"demo-next"}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer demo-local")
		request.Header.Set("Content-Type", "application/json")
		response, err := (&http.Client{Timeout: time.Second}).Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
			t.Fatal("selector API rejected fixture request", response.StatusCode)
		}
		if method != http.MethodGet {
			return ""
		}
		var value struct {
			Now string `json:"now"`
		}
		if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
			t.Fatal(err)
		}
		return value.Now
	}
	for _, names := range [][]string{{"demo-a", "demo-b"}, {"demo-b", "demo-c"}, {"demo-c", "demo-a"}} {
		command := exec.Command(executable, "run", "-c", path)
		command.Dir = root
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
			deadline := time.Now().Add(5 * time.Second)
			for {
				connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
				if err == nil {
					_ = connection.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("DNS data plane did not become ready", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			for _, name := range names {
				got := query(name)
				if previous := values[name]; previous != "" && previous != got {
					t.Fatalf("crash reassigned %s: %s -> %s", name, previous, got)
				}
				for other, used := range values {
					if other != name && used == got {
						t.Fatalf("crash reused %s for %s instead of %s", got, name, other)
					}
				}
				values[name] = got
			}
			if selection(http.MethodGet) != "demo-first" {
				t.Fatal("DNS cache restored an old selector instead of the current runtime default")
			}
			selection(http.MethodPut)
			info, err := os.Stat(filepath.Join(root, TUNDNSCache))
			if err != nil || info.Mode().Perm()&0o077 != 0 {
				t.Fatal("DNS cache was not persisted with owner-only permissions", err)
			}
		}()
	}
	corrupt := []byte("demo damaged cache must not be silently reset")
	cache := filepath.Join(root, TUNDNSCache)
	if err := os.WriteFile(cache, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "run", "-c", path)
	command.Dir = root
	err = command.Run()
	after, readErr := os.ReadFile(cache)
	if err == nil || ctx.Err() != nil || readErr != nil || !bytes.Equal(after, corrupt) {
		t.Fatal("damaged DNS cache did not fail closed with its original bytes preserved", err, readErr)
	}
}
