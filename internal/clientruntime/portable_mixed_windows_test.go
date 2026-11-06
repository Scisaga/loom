//go:build windows

package clientruntime

import (
	"context"
	"errors"
	"loom/internal/clientadapter"
	"net"
	"os"
	"path/filepath"
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
	config, err := DeriveWindowsRuntimeConfig(windowsViewFixture(t), WindowsPortableMixedProfile, "demo-api", clientadapter.WebsiteAccess{}, new([]string{}))
	if err != nil {
		t.Fatal(err)
	}
	defer config.Clear()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	runtimeDir := filepath.Join(root, "runtime")
	go func() {
		done <- RunWindowsDataPlane(ctx, executable, config, runtimeDir, runtimeDir, nil)
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
