//go:build windows

package clientruntime

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This opt-in native test starts only the mixed listener. The derived config
// contains no TUN inbound, so it does not create an adapter or alter routes.
func TestOfficialPortableMixedNativeRun(t *testing.T) {
	executable := os.Getenv("LOOM_SING_BOX_EXECUTABLE")
	if executable == "" {
		t.Skip("set LOOM_SING_BOX_EXECUTABLE for the native Portable Mixed check")
	}
	for _, address := range []string{"127.0.0.1:1080", "127.0.0.1:61800"} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Skip("managed loopback listener already used")
		}
		_ = listener.Close()
	}
	root := t.TempDir()
	source := strings.NewReplacer(
		"${secret:vault:cred/win01}", "fixture-password",
		"${secret:api/win01}", "fixture-api",
	).Replace(validWindowsConfig("warn"))
	config, err := DeriveWindowsRuntimeConfig([]byte(source), WindowsPortableMixedProfile, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(config)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	runtimeDir := filepath.Join(root, "runtime")
	go func() {
		done <- RunWindowsDataPlaneProfile(ctx, executable, config, runtimeDir, WindowsPortableMixedProfile)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		connection, dialErr := net.DialTimeout("tcp", "127.0.0.1:1080", 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		select {
		case runErr := <-done:
			t.Fatalf("Portable Mixed exited before opening its listener: %v", runErr)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("Portable Mixed did not open 127.0.0.1:1080")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatal(runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Portable Mixed did not stop")
	}
	entries, err := os.ReadDir(runtimeDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Portable Mixed leaked plaintext runtime files: %v", entries)
	}
}

// The same loopback TLS peer is reachable only when its name matches the
// authenticated Service. The deny-only replacement closes that authorization.
func TestOfficialPortableMixedServiceRevocation(t *testing.T) {
	executable := os.Getenv("LOOM_SING_BOX_EXECUTABLE")
	if executable == "" {
		t.Skip("set LOOM_SING_BOX_EXECUTABLE for native Service enforcement")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "demo-service-response") }))
	defer server.Close()
	target := strings.TrimPrefix(server.URL, "https://")
	source := []byte(validWindowsConfig(""))
	for _, revoked := range []bool{false, true} {
		current := source
		if revoked {
			c, err := decodeWindowsConfig(source)
			if err != nil {
				t.Fatal(err)
			}
			c.Outbounds = []singBoxOutbound{{Type: "block", Tag: "reject"}}
			c.Route.Rules = []singBoxRule{}
			current, err = json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
		}
		config, err := DeriveWindowsRuntimeConfig(current, WindowsPortableMixedProfile, nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- RunWindowsDataPlaneProfile(ctx, executable, config, filepath.Join(t.TempDir(), "runtime"), WindowsPortableMixedProfile)
		}()
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
		func() {
			defer stop()
			deadline := time.Now().Add(10 * time.Second)
			for {
				connection, err := net.DialTimeout("tcp", "127.0.0.1:1080", time.Millisecond*100)
				if err == nil {
					_ = connection.Close()
					break
				}
				select {
				case err := <-done:
					stopped = true
					t.Fatalf("data plane exited: %v", err)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("managed proxy did not start")
				}
				time.Sleep(30 * time.Millisecond)
			}
			for _, name := range []string{"demo-service.example", "demo-denied.example"} {
				value, err := nativeMixedTLS(target, name)
				want := !revoked && name == "demo-service.example"
				if want && (err != nil || value != "demo-service-response") {
					t.Fatalf("authorized Service failed: %v", err)
				}
				if !want && err == nil {
					t.Fatal("denied TLS name or revoked Service reached target")
				}
			}
		}()
	}
}

func nativeMixedTLS(target, name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:1080")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if _, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		return "", err
	}
	reply, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return "", err
	}
	if reply.StatusCode != 200 {
		return "", errors.New("proxy rejected target")
	}
	// This loopback fixture tests routing, not public PKI. TLS still supplies the
	// original name to the real sing-box sniff path; production probes verify PKI.
	encrypted := tls.Client(conn, &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err = encrypted.HandshakeContext(ctx); err != nil {
		return "", err
	}
	if _, err = fmt.Fprintf(encrypted, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", name); err != nil {
		return "", err
	}
	response, err := http.ReadResponse(bufio.NewReader(encrypted), &http.Request{Method: http.MethodGet})
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 128))
	return string(body), err
}
