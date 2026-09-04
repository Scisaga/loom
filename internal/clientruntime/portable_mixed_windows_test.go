//go:build windows

package clientruntime

import (
	"context"
	"errors"
	"net"
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
	caSource := os.Getenv("LOOM_TEST_CA_CERTIFICATE")
	if executable == "" || caSource == "" {
		t.Skip("set LOOM_SING_BOX_EXECUTABLE and LOOM_TEST_CA_CERTIFICATE for the native Portable Mixed smoke test")
	}
	for _, address := range []string{"127.0.0.1:1080", "127.0.0.1:61800"} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Skipf("required managed loopback address %s is already in use: %v", address, err)
		}
		_ = listener.Close()
	}
	caBody, err := os.ReadFile(caSource)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	caPath := filepath.Join(root, "tls", "ca.crt")
	if err := os.MkdirAll(filepath.Dir(caPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, caBody, 0o600); err != nil {
		t.Fatal(err)
	}
	source := strings.NewReplacer(
		"${secret:vault:cred/win01}", "fixture-password",
		"${secret:api/win01}", "fixture-api",
	).Replace(validWindowsConfig("warn"))
	config, err := DeriveWindowsRuntimeConfig([]byte(source), WindowsPortableMixedProfile, caPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(config)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	runtimeDir := filepath.Join(root, "runtime")
	go func() {
		done <- RunWindowsDataPlaneProfile(ctx, executable, config, runtimeDir, WindowsPortableMixedProfile, caPath)
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
