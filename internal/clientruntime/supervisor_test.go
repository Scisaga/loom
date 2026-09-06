//go:build !windows

package clientruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunWindowsDataPlanePreflightsAndStopsChild(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "sing-box")
	script := "#!/bin/sh\ncase \"$1\" in\ncheck) exit 0;;\nrun) while :; do sleep 1; done;;\n*) exit 90;;\nesac\n"
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(root, "runtime")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	source := strings.NewReplacer(
		"${secret:vault:cred/win01}", "fixture-password",
		"${secret:api/win01}", "fixture-api",
	).Replace(validWindowsConfig("warn"))
	config, err := DeriveWindowsRuntimeConfig([]byte(source), WindowsInstalledProfile, WindowsInstalledCAPath)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		done <- RunWindowsDataPlane(ctx, executable, []byte(config), runtimeDir)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("supervisor exited before cancellation: %v", err)
		default:
		}
		entries, err := os.ReadDir(runtimeDir)
		if err == nil && len(entries) == 1 && strings.HasPrefix(entries[0].Name(), ".sing-box-active-") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("supervisor did not start with exactly one active config")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor did not stop the child")
	}
	entries, err := os.ReadDir(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("supervisor leaked plaintext runtime config: %v", entries)
	}
}

func TestRunWindowsDataPlaneRemovesStalePlaintextConfigBeforeStart(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "sing-box")
	script := "#!/bin/sh\ncase \"$1\" in\ncheck) exit 0;;\nrun) while :; do sleep 1; done;;\n*) exit 90;;\nesac\n"
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(root, "runtime")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(runtimeDir, ".sing-box-active-stale.json")
	if err := os.WriteFile(stale, []byte("old secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := strings.NewReplacer(
		"${secret:vault:cred/win01}", "fixture-password",
		"${secret:api/win01}", "fixture-api",
	).Replace(validWindowsConfig("warn"))
	config, err := DeriveWindowsRuntimeConfig([]byte(source), WindowsInstalledProfile, WindowsInstalledCAPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunWindowsDataPlane(ctx, executable, []byte(config), runtimeDir) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries, _ := os.ReadDir(runtimeDir)
		if len(entries) == 1 && entries[0].Name() != filepath.Base(stale) {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("stale runtime config was not replaced: %v", entries)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunPortableMixedDataPlaneNeverReceivesTUN(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "sing-box")
	script := `#!/bin/sh
case "$1" in
check|run) ;;
*) exit 90;;
esac
[ "$2" = -c ] || exit 91
[ -f "$3" ] || exit 92
grep -q '"type": "tun"' "$3" && exit 93
grep -q '"tag": "in-1080"' "$3" || exit 94
if [ "$1" = check ]; then exit 0; fi
while :; do sleep 1; done
`
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	source := strings.NewReplacer(
		"${secret:vault:cred/win01}", "fixture-password",
		"${secret:api/win01}", "fixture-api",
	).Replace(validWindowsConfig("warn"))
	caPath := `C:\Users\fixture\AppData\Local\LoomPortable\tls\ca.crt`
	config, err := DeriveWindowsRuntimeConfig([]byte(source), WindowsPortableMixedProfile, caPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(config)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	runtimeDir := filepath.Join(root, "runtime-mixed")
	go func() {
		done <- RunWindowsDataPlaneProfile(ctx, executable, config, runtimeDir, WindowsPortableMixedProfile, caPath)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("Portable Mixed supervisor exited before cancellation: %v", err)
		default:
		}
		entries, err := os.ReadDir(runtimeDir)
		if err == nil && len(entries) == 1 && strings.HasPrefix(entries[0].Name(), ".sing-box-active-") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Portable Mixed supervisor did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Portable Mixed supervisor did not stop")
	}
}
